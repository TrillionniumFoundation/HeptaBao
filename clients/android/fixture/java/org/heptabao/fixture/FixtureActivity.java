package org.heptabao.fixture;

import android.app.Activity;
import android.content.ClipData;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.autofill.AutofillManager;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Only hash commitments are packaged. The actual fixture credentials come from Autofill. */
public final class FixtureActivity extends Activity {
    private EditText user;
    private EditText password;
    private TextView result;
    private int verificationCount;
    @Override public void onCreate(Bundle state) {
        super.onCreate(null);
        setContentView(R.layout.fixture);
        user = findViewById(R.id.login_username); password = findViewById(R.id.login_password); result = findViewById(R.id.result);
        user.setSaveEnabled(false); password.setSaveEnabled(false);
        user.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        password.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        findViewById(R.id.request_fill).setOnClickListener(view -> {
            user.requestFocus(); getSystemService(AutofillManager.class).requestAutofill(user);
        });
        findViewById(R.id.clear_fields).setOnClickListener(view -> {
            // Deliberately keep the system session: QA must catch reusable cached plaintext datasets.
            user.setText(""); password.setText(""); result.setText("Verification " + verificationCount + ": Fields cleared");
        });
        findViewById(R.id.check_login).setOnClickListener(view -> {
            verificationCount++;
            String outcome = user.length() == 0 && password.length() == 0 ? "Empty fields" :
                digest(user.getText().toString()).equals(BuildConfig.USER_SHA256)
                && digest(password.getText().toString()).equals(BuildConfig.PASSWORD_SHA256) ? "Synthetic login accepted" : "Synthetic login rejected";
            result.setText("Verification " + verificationCount + ": " + outcome);
        });
        findViewById(R.id.import_ciphertext).setOnClickListener(view -> {
            Uri uri = Uri.parse("content://" + getPackageName() + ".ciphertext/vault.hbv");
            Intent intent = new Intent("org.heptabao.personal.preview.IMPORT_CIPHERTEXT")
                .setComponent(new ComponentName("org.heptabao.personal.preview", "org.heptabao.preview.MainActivity"))
                .setDataAndType(uri, "application/octet-stream")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            intent.setClipData(ClipData.newRawUri("Encrypted synthetic vault", uri));
            startActivity(intent);
        });
        findViewById(R.id.webview_mode).setOnClickListener(view -> webview());
    }
    private void webview() {
        getSystemService(AutofillManager.class).cancel(); user.setText(""); password.setText("");
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL);
        TextView text = new TextView(this); text.setText("WebView is unsupported; no credentials may be filled"); layout.addView(text);
        WebView web = new WebView(this); web.getSettings().setJavaScriptEnabled(false);
        web.getSettings().setAllowFileAccess(false); web.getSettings().setAllowContentAccess(false);
        web.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_YES);
        layout.addView(web, new LinearLayout.LayoutParams(-1, 500));
        web.loadDataWithBaseURL("https://native-fixture.heptabao.invalid", "<!doctype html><form><label>Web username <input name='username' autocomplete='username'></label><br><label>Web password <input type='password' name='password' autocomplete='current-password'></label></form>", "text/html", "UTF-8", null);
        Button request = new Button(this); request.setText("Request WebView Autofill"); request.setOnClickListener(view -> getSystemService(AutofillManager.class).requestAutofill(web)); layout.addView(request);
        setContentView(layout);
    }
    private static String digest(String text) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder(); for (byte value : bytes) out.append(String.format(java.util.Locale.ROOT, "%02x", value & 255)); return out.toString();
        } catch (NoSuchAlgorithmException error) { throw new IllegalStateException("digest_unavailable"); }
    }
    @Override protected void onSaveInstanceState(Bundle state) { /* Never persist test credentials. */ }
}
