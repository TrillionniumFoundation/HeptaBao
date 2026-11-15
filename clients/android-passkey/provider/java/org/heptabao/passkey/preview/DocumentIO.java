package org.heptabao.passkey.preview;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.ProviderInfo;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.heptabao.passkey.core.Failure;

/** Bounded local-document operation. Logical cancellation never calls Binder. */
final class DocumentIO implements AutoCloseable {
    private static final long LIMIT_MILLIS = 15000;
    private static final ScheduledExecutorService TIMER = Executors.newSingleThreadScheduledExecutor(action -> {
        Thread thread = new Thread(action, "heptabao-document-deadline"); thread.setDaemon(true); return thread;
    });
    private final long deadline = SystemClock.elapsedRealtime() + LIMIT_MILLIS;
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final AtomicReference<ParcelFileDescriptor> descriptor = new AtomicReference<>();
    private final CancellationSignal signal = new CancellationSignal();
    private final ScheduledFuture<?> timer;
    private volatile boolean timedOut;
    DocumentIO(Runnable onTimeout) {
        timer = TIMER.schedule(() -> { timedOut = true; cancel(); onTimeout.run(); }, LIMIT_MILLIS, TimeUnit.MILLISECONDS);
    }
    void check() throws Failure {
        if (SystemClock.elapsedRealtime() >= deadline) { timedOut = true; cancel(); }
        Failure.require(!cancelled.get(), timedOut ? "document_timeout" : "document_cancelled");
    }
    void cancel() {
        if (!cancelled.compareAndSet(false, true)) return;
        // CancellationSignal.cancel and descriptor close may enter Binder/kernel
        // code. A stuck provider cannot stall the global deadline thread or the
        // session's immediate logical revocation.
        Thread cleanup = new Thread(() -> {
            ParcelFileDescriptor fd = descriptor.getAndSet(null);
            if (fd != null) try { fd.close(); } catch (Exception ignored) { }
            try { signal.cancel(); } catch (Exception ignored) { }
        }, "heptabao-document-cancel");
        cleanup.setDaemon(true); cleanup.start();
    }
    ParcelFileDescriptor open(Context context, Uri uri, String mode) throws Exception {
        check(); Failure.require(uri != null && "content".equals(uri.getScheme()), "invalid_document");
        String authority = uri.getAuthority();
        Failure.require("com.android.externalstorage.documents".equals(authority)
            || "com.android.providers.downloads.documents".equals(authority), "unsupported_document_provider");
        ProviderInfo provider = context.getPackageManager().resolveContentProvider(authority, 0);
        check(); Failure.require(provider != null && provider.applicationInfo != null
            && (provider.applicationInfo.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0,
            "unsupported_document_provider");
        ParcelFileDescriptor opened = context.getContentResolver().openFileDescriptor(uri, mode, signal);
        try {
            check(); Failure.require(opened != null && descriptor.compareAndSet(null, opened), "document_descriptor_busy");
            check(); return opened;
        } catch (Exception error) { if (opened != null) opened.close(); throw error; }
    }
    void released(ParcelFileDescriptor fd) { descriptor.compareAndSet(fd, null); }
    @Override public void close() {
        timer.cancel(false);
        if (descriptor.get() != null) cancel(); else cancelled.set(true);
    }
}
