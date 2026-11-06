package org.heptabao.preview;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class MainActivity extends Activity {
    static final String IMPORT_ACTION = "org.heptabao.personal.preview.IMPORT_CIPHERTEXT";
    private TextView status;
    private VaultApplication app;
    @Override public void onCreate(Bundle saved) {
        super.onCreate(null); getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        app = (VaultApplication)getApplication();
        String last = app.decision(); app.lockAll(last);
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); layout.setPadding(32,32,32,32);
        layout.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        TextView title = new TextView(this); title.setText("HeptaBao Android Preview"); title.setTextSize(22); layout.addView(title);
        TextView scope = new TextView(this); scope.setText("Read-only encrypted .hbv import\nOnly the pinned synthetic native fixture is supported.\nWebView, browser, passkeys, sync, and saving are unsupported.\nThe vault starts locked after every restart."); layout.addView(scope);
        Button choose = new Button(this); choose.setText("Import encrypted .hbv"); choose.setOnClickListener(view -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream");
            startActivityForResult(intent, 11);
        }); layout.addView(choose);
        Button enable = new Button(this); enable.setText("Choose Autofill service"); enable.setOnClickListener(view -> startActivity(new Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:" + getPackageName())))); layout.addView(enable);
        Button lock = new Button(this); lock.setText("Lock now"); lock.setOnClickListener(view -> { app.lockAll("locked"); status.setText("Locked\nDecision: locked"); }); layout.addView(lock);
        status = new TextView(this); status.setText((VaultFiles.exists(this) ? "Encrypted vault imported; locked" : "No encrypted vault imported") + "\nDecision: " + last); status.setContentDescription("Provider status"); layout.addView(status);
        setContentView(layout);
        if (IMPORT_ACTION.equals(getIntent().getAction())) confirmImport(getIntent().getData());
    }
    private void confirmImport(Uri uri) {
        if (uri == null || !"content".equals(uri.getScheme())) { status.setText("Import rejected"); return; }
        new AlertDialog.Builder(this).setTitle("Import encrypted vault?")
            .setMessage("This replaces this preview's encrypted copy and locks every pending authorization. No password is imported in plaintext.")
            .setNegativeButton("Cancel", null).setPositiveButton("Import", (dialog, which) -> {
                if (!app.startImport()) { status.setText("Import already in progress"); return; }
                status.setText("Importing ciphertext…");
                CancellationSignal cancel = new CancellationSignal();
                AtomicReference<InputStream> active = new AtomicReference<>();
                long deadline = SystemClock.elapsedRealtime() + 10000;
                ScheduledFuture<?> timeout = app.timers.schedule(() -> {
                    // A content-provider binder or close can block: never run either on the expiry thread.
                    app.cancellationWorker.execute(() -> {
                        cancel.cancel(); InputStream input = active.getAndSet(null);
                        if (input != null) try { input.close(); } catch (IOException ignored) { }
                    });
                    app.handler.post(() -> { if (!isFinishing()) status.setText("Import timed out; vault remains locked"); });
                }, 10000, TimeUnit.MILLISECONDS);
                app.importWorker.execute(() -> {
                    boolean success = false;
                    try { VaultFiles.importCiphertext(this, uri, cancel, deadline, active); success = true; }
                    catch (IOException | VaultCrypto.Failure | RuntimeException ignored) { }
                    finally { timeout.cancel(false); }
                    final boolean imported = success;
                    app.endImport(imported ? "imported_locked" : "import_failed");
                    app.handler.post(() -> { if (!isFinishing()) status.setText(imported ? "Encrypted vault imported; locked\nDecision: imported_locked" : "Import failed"); });
                });
            }).show();
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 11 && result == RESULT_OK && data != null) confirmImport(data.getData());
    }
}
