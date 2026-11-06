package org.heptabao.preview;

import android.app.Activity;
import android.app.assist.AssistStructure;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.view.autofill.AutofillManager;
import android.view.autofill.AutofillValue;
import android.service.autofill.Dataset;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RemoteViews;
import android.widget.TextView;
import java.io.IOException;
import java.util.Arrays;

/** Sensitive UI is local. There is no exported unlock API and no plaintext saved state. */
public final class AuthActivity extends Activity {
    private VaultApplication app;
    private String token;
    private EditText master;
    private TextView status;
    private Button unlock;
    private boolean foreground;
    private final Runnable ticker = new Runnable() {
        @Override public void run() {
            if (!foreground || token == null) return;
            if (!app.isUnlocked(token) && "Unlocked; confirm within 20 seconds".contentEquals(status.getText())) status.setText("Locked or expired");
            app.handler.postDelayed(this, 250);
        }
    };
    @Override public void onCreate(Bundle saved) {
        super.onCreate(null);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        app = (VaultApplication)getApplication();
        setResult(RESULT_CANCELED, new Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, (android.os.Parcelable)null));
        if (getIntent().getData() != null && "heptabao-auth".equals(getIntent().getData().getScheme())
            && "local".equals(getIntent().getData().getHost())) token = getIntent().getData().getLastPathSegment();
        try { boundRequest(); }
        catch (TargetPolicy.Rejected rejection) {
            // Rejected.code is a closed set of static policy strings, never input or an exception message.
            android.util.Log.i("HeptaBaoPreview", "auth_rejected_" + rejection.code);
            app.decision(rejection.code); finish(); return;
        }
        android.util.Log.i("HeptaBaoPreview", "auth_context_bound");
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); layout.setPadding(32,32,32,32);
        layout.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        TextView title = new TextView(this); title.setText("HeptaBao · local authorization"); title.setTextSize(22); layout.addView(title);
        TextView target = new TextView(this); target.setText("Synthetic native fixture\nPackage and signing certificate verified\nFill once after local confirmation"); layout.addView(target);
        master = new EditText(this); master.setHint("Master password"); master.setContentDescription("Master password");
        master.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        master.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        master.setSaveEnabled(false); master.setLongClickable(false); master.setAutofillHints((String[])null);
        layout.addView(master);
        unlock = new Button(this); unlock.setText("Unlock locally"); unlock.setOnClickListener(view -> unlock()); layout.addView(unlock);
        Button fill = new Button(this); fill.setText("Fill once"); fill.setOnClickListener(view -> fill()); layout.addView(fill);
        Button lock = new Button(this); lock.setText("Lock"); lock.setOnClickListener(view -> { app.lockLogin(token); master.setText(""); status.setText("Locked or expired"); }); layout.addView(lock);
        Button cancel = new Button(this); cancel.setText("Cancel"); cancel.setOnClickListener(view -> finish()); layout.addView(cancel);
        status = new TextView(this); status.setText("Locked"); status.setContentDescription("Authorization status"); layout.addView(status);
        setContentView(layout);
    }
    private VaultApplication.Pending boundRequest() throws TargetPolicy.Rejected {
        VaultApplication.Pending request = token == null ? null : app.request(token);
        if (request == null) throw new TargetPolicy.Rejected("request_expired");
        if (getCallingActivity() == null || !request.target.component.equals(getCallingActivity())) throw new TargetPolicy.Rejected("wrong_result_recipient");
        AssistStructure structure = getIntent().getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure.class);
        TargetPolicy.Target actual = TargetPolicy.inspect(this, structure);
        if (!request.target.same(actual)) throw new TargetPolicy.Rejected("request_changed");
        return request;
    }
    private void unlock() {
        try { boundRequest(); }
        catch (TargetPolicy.Rejected rejection) { app.lockAll(rejection.code); status.setText("Authorization rejected"); return; }
        Editable editable = master.getText(); char[] chars = new char[editable.length()]; editable.getChars(0, editable.length(), chars, 0);
        master.setText(""); byte[] password;
        try { password = VaultCrypto.passwordBytes(chars); }
        catch (VaultCrypto.Failure failure) { status.setText("Master password must be 12 to 1024 UTF-8 bytes"); return; }
        finally { Arrays.fill(chars, '\0'); }
        final long ticket = app.ticket(token); unlock.setEnabled(false); status.setText("Unlocking locally…");
        app.cryptoWorker.execute(() -> {
            VaultCrypto.Login result = null; String error = null;
            try { result = VaultCrypto.unlock(VaultFiles.read(this), password, BuildConfig.ENTRY_ID, BuildConfig.ENTRY_ORIGIN); }
            catch (VaultCrypto.Failure failure) { error = failure.code; }
            catch (IOException | RuntimeException failure) { error = "unlock_failed"; }
            finally { Arrays.fill(password, (byte)0); }
            final VaultCrypto.Login value = result; final String code = error;
            app.handler.post(() -> {
                if (!foreground || isFinishing() || app.ticket(token) != ticket) { if (value != null) value.close(); return; }
                unlock.setEnabled(true);
                try { boundRequest(); }
                catch (TargetPolicy.Rejected rejection) { if (value != null) value.close(); app.lockAll(rejection.code); status.setText("Authorization rejected"); return; }
                if (value != null && app.install(token, ticket, value)) status.setText("Unlocked; confirm within 20 seconds");
                else { app.decision(code == null ? "unlock_failed" : code); status.setText("Unlock failed"); }
            });
        });
    }
    @SuppressWarnings("deprecation") private void fill() {
        VaultApplication.Pending request;
        try { request = boundRequest(); }
        catch (TargetPolicy.Rejected rejection) { app.lockAll(rejection.code); status.setText("Authorization rejected"); return; }
        VaultApplication.Handoff handoff = app.consume(token);
        if (handoff == null) { status.setText("Locked or expired"); return; }
        boolean delivered = false;
        try {
            // Perform potentially blocking system identity checks before making framework String copies.
            try { TargetPolicy.certificate(this, request.target.component.getPackageName()); }
            catch (TargetPolicy.Rejected rejection) { app.lockAll(rejection.code); status.setText("Authorization rejected"); return; }
            if (!request.target.component.equals(getCallingActivity()) || !app.handoffValid(handoff)) { status.setText("Locked or expired"); return; }
            RemoteViews menu = new RemoteViews(getPackageName(), R.layout.presentation);
            menu.setTextViewText(R.id.presentation_text, "Fill synthetic login once");
            Dataset dataset = new Dataset.Builder(menu)
                .setValue(request.target.username, AutofillValue.forText(new String(handoff.login.username)))
                .setValue(request.target.password, AutofillValue.forText(new String(handoff.login.password))).build();
            if (!app.handoffValid(handoff)) { status.setText("Locked or expired"); return; }
            setResult(RESULT_OK, new Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset)
                .putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT_EPHEMERAL_DATASET, true));
            if (!app.handoffValid(handoff)) {
                setResult(RESULT_CANCELED, new Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, (android.os.Parcelable)null));
                status.setText("Locked or expired"); return;
            }
            finish();
            delivered = true;
        } finally { app.endHandoff(handoff, delivered); }
    }
    @Override protected void onResume() { super.onResume(); foreground = true; if (app != null) app.handler.post(ticker); }
    @Override protected void onPause() {
        foreground = false;
        if (master != null) master.setText("");
        if (app != null) { app.handler.removeCallbacks(ticker); app.cancel(token); }
        super.onPause();
    }
    @Override protected void onSaveInstanceState(Bundle state) { /* Passwords and authorization are never saved. */ }
}
