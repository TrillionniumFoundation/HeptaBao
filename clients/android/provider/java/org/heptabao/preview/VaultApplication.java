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

    enum CancelSource {
        OTHER("other"), AUTH_PAUSE("auth_pause"), SERVICE_LISTENER("service_listener"), SERVICE_CALLBACK("service_callback");
        final String code;
        CancelSource(String code) { this.code = code; }
    }
    enum RejectionStage {
        UNLOCK_PRECHECK("unlock_precheck"), UNLOCK_POST_KDF("unlock_post_kdf"), SERVICE_REQUEST("service_request");
        final String code;
        RejectionStage(String code) { this.code = code; }
    }
    enum ServiceTarget {
        EXPECTED("expected"), SELF("self"), OTHER("other");
        final String code;
        ServiceTarget(String code) { this.code = code; }
    }

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
        String before = stateBits();
        lockAll("authentication_required");
        pending = new Pending(target);
        final Pending created = pending;
        try {
            created.timeout = timers.schedule(() -> { synchronized (VaultApplication.this) { if (pending == created) {
                lockAll("request_expired"); diagnostic("request_expiry_timer");
            } } }, REQUEST_TTL_MS, TimeUnit.MILLISECONDS);
        } catch (RuntimeException error) {
            // The service cannot own this challenge until begin returns. Do not
            // leave a partially created challenge without its expiry timer.
            if (pending == created) lockAll("invalid_request");
            throw error;
        }
        diagnostic("request_created_before_" + before + "_after_" + stateBits());
        return pending;
    }
    synchronized void attachLaunch(String token, PendingIntent launch) {
        if (request(token) == null) cancellationWorker.execute(launch::cancel); else pending.launch = launch;
    }
    synchronized Pending request(String token) {
        if (pending == null || !pending.token.equals(token)) return null;
        if (SystemClock.elapsedRealtime() >= pending.deadline) { lockAll("request_expired"); diagnostic("request_expiry_access"); return null; }
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
            diagnostic("unlock_expiry_timer_login");
        }
        if (handoff != null && handoff.request.token.equals(token) && handoff.login == value) {
            lockAll("expired"); diagnostic("unlock_expiry_timer_handoff");
        }
    }
    synchronized boolean isUnlocked(String token) {
        if (request(token) == null) return false;
        if (login != null && SystemClock.elapsedRealtime() >= unlockDeadline) {
            clearLogin(); generation++; lastDecision = "expired";
            diagnostic("unlock_expiry_access");
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
            lockAll("expired"); diagnostic("handoff_expiry_access"); return false;
        }
        return true;
    }
    synchronized void endHandoff(Handoff value, boolean delivered) {
        if (handoff == value) {
            clearLogin(); generation++; lastDecision = delivered ? "filled_once" : "handoff_rejected";
        } else value.login.close();
    }
    synchronized void lockLogin(String token) {
        if (request(token) != null) {
            String before = stateBits();
            clearLogin(); generation++; lastDecision = "locked";
            diagnostic("explicit_login_lock_before_" + before + "_after_" + stateBits());
        }
    }
    synchronized void cancel(String token) {
        cancel(token, CancelSource.OTHER);
    }
    synchronized void cancel(String token, CancelSource source) {
        String before = stateBits();
        boolean matched = (pending != null && pending.token.equals(token)) || (handoff != null && handoff.request.token.equals(token));
        if (matched) lockAll("background_locked");
        diagnostic("cancel_" + source.code + "_matched_" + (matched ? "1" : "0") + "_before_" + before + "_after_" + stateBits());
    }
    synchronized void lockAll(String reason) {
        String before = stateBits();
        clearLogin(); clearPending(); generation++; lastDecision = reason;
        diagnostic("lock_all_" + closedCode(reason) + "_before_" + before + "_after_" + stateBits());
    }
    synchronized void rejectServiceRequest(Pending owned, String reason) {
        // A rejected incoming request does not own a different challenge. A
        // delayed error from a replaced request also cannot revoke its successor.
        if (owned != null && (pending == owned || (handoff != null && handoff.request == owned))) {
            lockAll(reason);
        } else lastDecision = reason; // Diagnostic state only, never authorization.
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
    void observeRejection(RejectionStage stage, String code) {
        diagnostic("reject_" + stage.code + "_" + closedCode(code));
    }
    void observeServiceTarget(ServiceTarget target) {
        diagnostic("service_target_" + target.code);
    }
    void observeStaleUnlock() { diagnostic("unlock_callback_stale"); }
    private void diagnostic(String closedEvent) {
        // Capture only a prebuilt closed code. Never log under the authorization
        // monitor or enqueue a token, credential, Activity, structure, or exception.
        // Delivery is best effort and may lag direct lifecycle diagnostics.
        try { handler.post(() -> {
            try { android.util.Log.i("HeptaBaoPreview", closedEvent); }
            catch (RuntimeException ignored) { /* Diagnostics cannot grant or revoke authorization. */ }
        }); } catch (RuntimeException ignored) { /* A stopped looper is not an authorization event. */ }
    }
    static String closedCode(String code) {
        if (code == null) return "other";
        switch (code) {
            case "request_expired": case "wrong_result_recipient": case "request_changed":
            case "wrong_package": case "wrong_certificate": case "missing_structure":
            case "wrong_activity": case "unsupported_windows": case "structure_too_large":
            case "webview_unsupported": case "wrong_fields": case "browser_unsupported":
            case "import_in_progress": case "vault_not_imported": case "invalid_request":
            case "authentication_required": case "background_locked": case "expired":
            case "locked": case "importing": case "imported_locked": case "import_failed":
            case "memory_locked": case "unlock_failed": case "authentication_failed":
            case "unlocked_pending_confirmation": case "handoff_pending": case "filled_once": case "handoff_rejected":
                return code;
            default: return "other";
        }
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
