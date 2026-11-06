package org.heptabao.preview;

import android.app.Application;
import android.app.PendingIntent;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** One foreground, one-use authorization. No unlocked state is persisted. */
public final class VaultApplication extends Application {
    static final long REQUEST_TTL_MS = 120000;
    static final long UNLOCK_TTL_MS = 20000;
    final ExecutorService cryptoWorker = Executors.newSingleThreadExecutor();
    final ExecutorService importWorker = Executors.newSingleThreadExecutor();
    final ExecutorService cancellationWorker = Executors.newSingleThreadExecutor();
    final ScheduledThreadPoolExecutor timers = new ScheduledThreadPoolExecutor(1);
    final Handler handler = new Handler(Looper.getMainLooper());
    private Pending pending;
    private VaultCrypto.Login login;
    private Handoff handoff;
    private long unlockDeadline;
    private long generation;
    private ScheduledFuture<?> loginTimeout;
    private boolean importing;
    private String lastDecision = "locked";

    static final class Pending {
        final String token = UUID.randomUUID().toString();
        final TargetPolicy.Target target;
        final long deadline = SystemClock.elapsedRealtime() + REQUEST_TTL_MS;
        PendingIntent launch;
        ScheduledFuture<?> timeout;
        Pending(TargetPolicy.Target target) { this.target = target; }
    }
    static final class Handoff {
        final Pending request;
        final VaultCrypto.Login login;
        final long notAfter;
        final long epoch;
        Handoff(Pending request, VaultCrypto.Login login, long notAfter, long epoch) {
            this.request = request; this.login = login; this.notAfter = notAfter; this.epoch = epoch;
        }
    }
    synchronized Pending begin(TargetPolicy.Target target) {
        lockAll("authentication_required");
        pending = new Pending(target);
        final Pending created = pending;
        created.timeout = timers.schedule(() -> { synchronized (VaultApplication.this) { if (pending == created) lockAll("request_expired"); } }, REQUEST_TTL_MS, TimeUnit.MILLISECONDS);
        return pending;
    }
    synchronized void attachLaunch(String token, PendingIntent launch) {
        if (request(token) == null) cancellationWorker.execute(launch::cancel); else pending.launch = launch;
    }
    synchronized Pending request(String token) {
        if (pending == null || !pending.token.equals(token)) return null;
        if (SystemClock.elapsedRealtime() >= pending.deadline) { lockAll("request_expired"); return null; }
        return pending;
    }
    synchronized long ticket(String token) {
        return request(token) == null ? -1 : generation;
    }
    synchronized boolean install(String token, long ticket, VaultCrypto.Login value) {
        if (request(token) == null || generation != ticket) { value.close(); return false; }
        clearLogin();
        login = value;
        unlockDeadline = Math.min(SystemClock.elapsedRealtime() + UNLOCK_TTL_MS, pending.deadline);
        lastDecision = "unlocked_pending_confirmation";
        loginTimeout = timers.schedule(() -> expire(token, value), Math.max(0, unlockDeadline - SystemClock.elapsedRealtime()), TimeUnit.MILLISECONDS);
        return true;
    }
    private synchronized void expire(String token, VaultCrypto.Login value) {
        if (pending != null && pending.token.equals(token) && login == value) {
            clearLogin(); generation++; lastDecision = "expired";
        }
        if (handoff != null && handoff.request.token.equals(token) && handoff.login == value) lockAll("expired");
    }
    synchronized boolean isUnlocked(String token) {
        if (request(token) == null) return false;
        if (login != null && SystemClock.elapsedRealtime() >= unlockDeadline) {
            clearLogin(); generation++; lastDecision = "expired";
        }
        return login != null;
    }
    synchronized Handoff consume(String token) {
        if (!isUnlocked(token)) return null;
        handoff = new Handoff(pending, login, unlockDeadline, generation + 1);
        login = null; clearPending(); unlockDeadline = 0; generation++;
        lastDecision = "handoff_pending";
        return handoff;
    }
    synchronized boolean handoffValid(Handoff value) {
        if (handoff != value || generation != value.epoch) return false;
        if (SystemClock.elapsedRealtime() >= Math.min(value.notAfter, value.request.deadline)) {
            lockAll("expired"); return false;
        }
        return true;
    }
    synchronized void endHandoff(Handoff value, boolean delivered) {
        if (handoff == value) {
            clearLogin(); generation++; lastDecision = delivered ? "filled_once" : "handoff_rejected";
        } else value.login.close();
    }
    synchronized void lockLogin(String token) {
        if (request(token) != null) { clearLogin(); generation++; lastDecision = "locked"; }
    }
    synchronized void cancel(String token) {
        if ((pending != null && pending.token.equals(token)) || (handoff != null && handoff.request.token.equals(token))) lockAll("background_locked");
    }
    synchronized void lockAll(String reason) {
        clearLogin(); clearPending(); generation++; lastDecision = reason;
    }
    synchronized void decision(String reason) { lastDecision = reason; }
    synchronized String decision() { return lastDecision; }
    synchronized boolean startImport() {
        if (importing) return false;
        importing = true; lockAll("importing"); return true;
    }
    synchronized void endImport(String reason) { importing = false; lockAll(reason); }
    synchronized boolean isImporting() { return importing; }
    private void clearLogin() {
        if (loginTimeout != null) loginTimeout.cancel(false);
        loginTimeout = null;
        if (login != null) login.close();
        if (handoff != null) handoff.login.close();
        handoff = null;
        login = null; unlockDeadline = 0;
    }
    private void clearPending() {
        if (pending != null) {
            if (pending.launch != null) { final PendingIntent launch = pending.launch; cancellationWorker.execute(launch::cancel); }
            if (pending.timeout != null) pending.timeout.cancel(false);
        }
        pending = null;
    }
    @Override public void onCreate() { super.onCreate(); timers.setRemoveOnCancelPolicy(true); }
    @Override public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        final String event;
        synchronized (this) {
            // The single pending challenge has no decrypted credentials. Its
            // original deadline and launch are retained; it grants only entry
            // to fresh local authentication. Cancellation/expiry/onPause still
            // clear it through lockAll. Always advance generation, even when
            // login is null, so a KDF already running cannot install its result.
            String before = stateBits();
            clearLogin(); generation++; lastDecision = "memory_locked";
            event = "trim_" + trimLevel(level) + "_before_" + before
                + "_after_" + stateBits() + "_epoch_advanced";
        }
        android.util.Log.i("HeptaBaoPreview", event);
    }
    private String stateBits() {
        return "p" + (pending != null ? "1" : "0") + "l" + (login != null ? "1" : "0")
            + "h" + (handoff != null ? "1" : "0");
    }
    private static String trimLevel(int level) {
        if (level == TRIM_MEMORY_RUNNING_MODERATE) return "running_moderate";
        if (level == TRIM_MEMORY_RUNNING_LOW) return "running_low";
        if (level == TRIM_MEMORY_RUNNING_CRITICAL) return "running_critical";
        if (level == TRIM_MEMORY_UI_HIDDEN) return "ui_hidden";
        if (level == TRIM_MEMORY_BACKGROUND) return "background";
        if (level == TRIM_MEMORY_MODERATE) return "moderate";
        if (level == TRIM_MEMORY_COMPLETE) return "complete";
        return "other";
    }
}
