package org.heptabao.passkey.preview;

import android.app.Activity;
import android.content.Intent;
import android.credentials.Credential;
import android.credentials.CredentialOption;
import android.credentials.CreateCredentialException;
import android.credentials.CreateCredentialResponse;
import android.credentials.GetCredentialException;
import android.credentials.GetCredentialResponse;
import android.os.Bundle;
import android.service.credentials.CallingAppInfo;
import android.service.credentials.CredentialProviderService;
import android.text.InputType;
import android.text.InputFilter;
import android.view.inputmethod.EditorInfo;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.ScrollView;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.heptabao.passkey.core.Failure;
import org.heptabao.passkey.core.Hbv;
import org.heptabao.passkey.core.Passkey;
import org.heptabao.passkey.core.Protocol;

/** Explicit one-use selection activity. A fresh password + Approve supplies UV + UP. */
public final class OperationActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private Tickets.Ticket ticket;
    private Passkey.Request request;
    private CallingAppInfo caller;
    private volatile boolean foreground;
    private boolean submitted;
    private volatile boolean completed;
    private EditText password;
    private TextView status;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state); setResult(RESULT_CANCELED);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        try {
            Failure.require(state == null, "operation_interrupted");
            ticket = Tickets.consume(getIntent().getData());
            String raw;
            if (ticket.create) {
                android.service.credentials.CreateCredentialRequest finalRequest = getIntent().getParcelableExtra(
                    CredentialProviderService.EXTRA_CREATE_CREDENTIAL_REQUEST, android.service.credentials.CreateCredentialRequest.class);
                Failure.require(finalRequest != null && Protocol.TYPE.equals(finalRequest.getType()), "invalid_final_request");
                caller = finalRequest.getCallingAppInfo(); raw = Policy.request(finalRequest.getData());
            } else {
                android.service.credentials.GetCredentialRequest finalRequest = getIntent().getParcelableExtra(
                    CredentialProviderService.EXTRA_GET_CREDENTIAL_REQUEST, android.service.credentials.GetCredentialRequest.class);
                Failure.require(finalRequest != null, "invalid_final_request"); caller = finalRequest.getCallingAppInfo();
                List<CredentialOption> options = finalRequest.getCredentialOptions();
                Failure.require(options.size() == 1 && Protocol.TYPE.equals(options.get(0).getType()), "unsupported_options");
                raw = Policy.request(options.get(0).getCredentialRetrievalData());
            }
            request = Passkey.request(raw, ticket.create);
            Failure.require(MessageDigest.isEqual(request.requestDigest, ticket.requestDigest)
                && Policy.caller(this, caller).equals(ticket.origin), "request_changed");
            Session.authorized(ticket.epoch, ticket.store, () -> { Failure.require(ticket.valid(), "selection_expired"); return null; });
            render();
        } catch (Exception error) { reject(ProviderService.safe(error)); }
    }
    private void render() {
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); layout.setPadding(32, 40, 32, 32);
        TextView title = new TextView(this); title.setText((ticket.create ? "Create" : "Use") + " synthetic passkey"); title.setTextSize(24); layout.addView(title);
        TextView target = new TextView(this); target.setText(Protocol.RP_ID + "\n" + Protocol.FIXTURE_PACKAGE + "\nVerify the target, enter your vault password, then approve."); layout.addView(target);
        password = new EditText(this); password.setSingleLine(true); password.setHint("Vault password");
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setFilters(new InputFilter[]{new InputFilter.LengthFilter(1024)});
        password.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        password.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        password.setSaveEnabled(false); password.setId(0x4a110001); layout.addView(password);
        Button approve = new Button(this); approve.setText("Approve passkey operation"); approve.setId(0x4a110002);
        approve.setOnClickListener(view -> approve()); layout.addView(approve);
        Button cancel = new Button(this); cancel.setText("Cancel"); cancel.setOnClickListener(view -> reject("cancelled")); layout.addView(cancel);
        status = new TextView(this); status.setText("Waiting for password and approval"); layout.addView(status);
        ScrollView scrolling = new ScrollView(this); scrolling.addView(layout); setContentView(scrolling);
    }
    private void approve() {
        if (submitted || completed || !foreground) return;
        byte[] bytes;
        char[] chars = new char[password.length()]; password.getText().getChars(0, chars.length, chars, 0);
        password.getText().clear();
        try { bytes = Hbv.passwordBytes(chars); }
        catch (Failure error) { status.setText(error.code); return; }
        finally { Arrays.fill(chars, '\0'); }
        submitted = true; status.setText("Verifying vault password");
        worker.execute(() -> {
            boolean committed = false;
            try {
                String response; List<Session.Entry> labels;
                checkpoint();
                try (VaultFiles.Transaction tx = VaultFiles.begin(this, ticket.store)) {
                    checkpoint();
                    Hbv.Unlocked unlocked;
                    try { unlocked = Hbv.unlock(tx.ciphertext, bytes); }
                    finally { Arrays.fill(bytes, (byte)0); }
                    try (Hbv.Unlocked vault = unlocked) {
                        checkpoint();
                        Failure.require(Policy.caller(this, caller).equals(ticket.origin), "calling_application_changed");
                        checkpoint();
                        if (ticket.create) {
                            Passkey.Record record = Passkey.create(vault, request, BuildConfig.FIXTURE_CERT_SHA256);
                            checkpoint(); response = Passkey.attestation(record, request, ticket.origin); checkpoint();
                            tx.commit(vault); committed = true; checkpoint();
                        } else {
                            Passkey.Assertion assertion = Passkey.advance(vault, request, ticket.selectedId, BuildConfig.FIXTURE_CERT_SHA256, ticket.origin);
                            checkpoint(); tx.commit(vault); committed = true; checkpoint();
                            response = assertion.sign(); checkpoint();
                        }
                        labels = Session.labels(vault); checkpoint();
                    }
                }
                final String readyResponse = response; final List<Session.Entry> readyLabels = labels;
                runOnUiThread(() -> deliver(readyResponse, readyLabels));
            } catch (Exception error) {
                Session.lock(); final String code = committed ? "operation_outcome_unknown" : ProviderService.safe(error);
                runOnUiThread(() -> reject(code));
            } finally { Arrays.fill(bytes, (byte)0); }
        });
    }
    private void checkpoint() throws Failure {
        Failure.require(foreground && !completed && ticket.valid(), "operation_interrupted");
        Session.check(ticket.epoch, ticket.store);
    }
    private void deliver(String response, List<Session.Entry> labels) {
        try {
            synchronized (Session.class) {
                checkpoint();
                long finalEpoch = Session.refreshAfterCommit(ticket.epoch, ticket.store, labels);
                Bundle data = new Bundle(); Intent result = new Intent();
                if (ticket.create) {
                    data.putString(Protocol.REGISTRATION_JSON, response);
                    result.putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE, new CreateCredentialResponse(data));
                } else {
                    data.putString(Protocol.AUTHENTICATION_JSON, response);
                    result.putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE, new GetCredentialResponse(new Credential(Protocol.TYPE, data)));
                }
                Failure.require(foreground && !completed && ticket.valid(), "operation_interrupted");
                Session.check(finalEpoch, ticket.store);
                setResult(RESULT_OK, result);
                // setResult only stages the response. The next finish call is
                // the final platform handoff, after one last logical revoke check.
                Failure.require(foreground && ticket.valid(), "operation_interrupted");
                Session.check(finalEpoch, ticket.store);
                completed = true; finish();
            }
        } catch (Exception error) {
            Session.lock(); reject("operation_outcome_unknown");
        }
    }
    private void reject(String code) {
        synchronized (Session.class) {
            if (completed) return; completed = true;
            if (ticket != null) ticket.cancelled = true;
            Intent result = new Intent();
            if (ticket != null && ticket.create) result.putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_EXCEPTION,
                new CreateCredentialException(CreateCredentialException.TYPE_USER_CANCELED, code));
            else result.putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_EXCEPTION,
                new GetCredentialException(GetCredentialException.TYPE_USER_CANCELED, code));
            setResult(RESULT_OK, result); finish();
        }
    }
    @Override protected void onResume() { super.onResume(); foreground = true; }
    @Override protected void onPause() {
        foreground = false; if (!completed && ticket != null) ticket.cancelled = true;
        if (password != null) password.getText().clear(); super.onPause();
    }
    @Override protected void onDestroy() {
        foreground = false; if (!completed && ticket != null) ticket.cancelled = true;
        worker.shutdown(); super.onDestroy();
    }
}
