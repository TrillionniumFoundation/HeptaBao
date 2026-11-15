package org.heptabao.passkey.fixture;

import android.app.Activity;
import android.content.ComponentName;
import android.credentials.CredentialManager;
import android.credentials.CredentialOption;
import android.credentials.CreateCredentialException;
import android.credentials.CreateCredentialRequest;
import android.credentials.CreateCredentialResponse;
import android.credentials.GetCredentialException;
import android.credentials.GetCredentialRequest;
import android.credentials.GetCredentialResponse;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.OutcomeReceiver;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.heptabao.passkey.core.Codec;
import org.heptabao.passkey.core.Failure;
import org.heptabao.passkey.core.Json;
import org.heptabao.passkey.core.Protocol;

/** Native CredentialManager fixture. It never generates keys or signatures. */
public final class FixtureActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private CredentialManager manager;
    private TextView status;
    private boolean busy;
    private boolean destroyed;
    private CancellationSignal cancellation;
    private long operation;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state); manager = getSystemService(CredentialManager.class);
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); layout.setPadding(32, 40, 32, 32);
        TextView title = new TextView(this); title.setText("Synthetic native Passkey RP"); title.setTextSize(24); layout.addView(title);
        TextView note = new TextView(this); note.setText(Protocol.RP_ID + "\nFramework CredentialManager create/get; local RP verifies every returned signature."); layout.addView(note);
        button(layout, "Create passkey", 0x4a130001, () -> begin(true, false));
        button(layout, "Authenticate with passkey", 0x4a130002, () -> begin(false, false));
        button(layout, "Reject a wrong RP target", 0x4a130003, () -> begin(false, true));
        button(layout, "Cancel pending request", 0x4a130004, () -> { if (cancellation != null) cancellation.cancel(); });
        status = new TextView(this); status.setId(0x4a130005); status.setText("Ready; synthetic data only"); layout.addView(status); setContentView(layout);
    }
    private void button(LinearLayout layout, String label, int id, Runnable action) {
        Button button = new Button(this); button.setText(label); button.setId(id); button.setOnClickListener(view -> action.run()); layout.addView(button);
    }
    private void begin(boolean create, boolean wrongRp) {
        if (busy || destroyed) return; busy = true; long token = ++operation;
        status.setText("Fetching one-use RP challenge");
        worker.execute(() -> {
            try {
                Map<String,Object> options = post(create ? "/registration/options" : "/authentication/options", Json.map());
                Json.keys(options, "ceremony_id", "publicKey"); String ceremony = Json.string(options.get("ceremony_id"));
                Map<String,Object> publicKey = Json.object(options.get("publicKey"));
                if (wrongRp) publicKey.put("rpId", "wrong-target.heptabao.test");
                String request = Json.write(publicKey);
                runOnUiThread(() -> invoke(token, create, wrongRp, ceremony, request));
            } catch (Exception error) { runOnUiThread(() -> failed(token, create, wrongRp, "rp_options_failed", null)); }
        });
    }
    private void invoke(long token, boolean create, boolean wrongRp, String ceremony, String request) {
        if (destroyed || token != operation) return;
        cancellation = new CancellationSignal(); Bundle data = new Bundle();
        data.putString(Protocol.REQUEST_JSON, request);
        data.putString(Protocol.SUBTYPE, create ? "androidx.credentials.BUNDLE_VALUE_SUBTYPE_CREATE_PUBLIC_KEY_CREDENTIAL_REQUEST"
            : "androidx.credentials.BUNDLE_VALUE_SUBTYPE_GET_PUBLIC_KEY_CREDENTIAL_OPTION");
        data.putBoolean("androidx.credentials.BUNDLE_KEY_IS_AUTO_SELECT_ALLOWED", false);
        try {
            if (create) {
                Bundle display = new Bundle(); display.putCharSequence("androidx.credentials.BUNDLE_KEY_USER_ID", "synthetic-user");
                display.putCharSequence("androidx.credentials.BUNDLE_KEY_USER_DISPLAY_NAME", "Synthetic passkey");
                data.putBundle("androidx.credentials.BUNDLE_KEY_REQUEST_DISPLAY_INFO", display);
                CreateCredentialRequest platformRequest = new CreateCredentialRequest.Builder(Protocol.TYPE, data, new Bundle(data))
                    .setAlwaysSendAppInfoToProvider(true).setIsSystemProviderRequired(false).build();
                status.setText("Android CredentialManager create request started");
                manager.createCredential(this, platformRequest, cancellation, getMainExecutor(),
                    new OutcomeReceiver<CreateCredentialResponse, CreateCredentialException>() {
                        @Override public void onResult(CreateCredentialResponse response) {
                            received(token, true, wrongRp, ceremony, response.getData().getString(Protocol.REGISTRATION_JSON));
                        }
                        @Override public void onError(CreateCredentialException error) { failed(token, true, wrongRp, "platform_rejected", error.getType()); }
                    });
            } else {
                CredentialOption option = new CredentialOption.Builder(Protocol.TYPE, data, new Bundle(data))
                    .addAllowedProvider(new ComponentName(Protocol.PROVIDER_PACKAGE, Protocol.PROVIDER_SERVICE)).build();
                GetCredentialRequest platformRequest = new GetCredentialRequest.Builder(new Bundle())
                    .addCredentialOption(option).setAlwaysSendAppInfoToProvider(true).build();
                status.setText("Android CredentialManager get request started");
                manager.getCredential(this, platformRequest, cancellation, getMainExecutor(),
                    new OutcomeReceiver<GetCredentialResponse, GetCredentialException>() {
                        @Override public void onResult(GetCredentialResponse response) {
                            if (!Protocol.TYPE.equals(response.getCredential().getType())) { failed(token, false, wrongRp, "unexpected_type", null); return; }
                            received(token, false, wrongRp, ceremony, response.getCredential().getData().getString(Protocol.AUTHENTICATION_JSON));
                        }
                        @Override public void onError(GetCredentialException error) { failed(token, false, wrongRp, "platform_rejected", error.getType()); }
                    });
            }
        } catch (Exception error) { failed(token, create, wrongRp, "platform_invocation_failed", null); }
    }
    private void received(long token, boolean create, boolean wrongRp, String ceremony, String credentialJson) {
        if (destroyed || token != operation) return;
        if (wrongRp) { failed(token, create, true, "unexpected_credential_for_wrong_target", null); return; }
        status.setText("Platform response received; verifying at RP");
        worker.execute(() -> {
            try {
                Map<String,Object> credential = Json.parseObject(credentialJson, Protocol.MAX_REQUEST);
                Map<String,Object> result = post(create ? "/registration/verify" : "/authentication/verify", Json.map("ceremony_id", ceremony, "credential", credential));
                Failure.require(Boolean.TRUE.equals(result.get("ok")), "rp_rejected");
                Map<String,Object> receipt = Json.map("schema", 1L, "operation", create ? "create" : "get", "wrong_rp", false,
                    "platform_callback", "result", "rp_verified", true, "credential_json_sha256", Codec.hex(Codec.sha(Json.bytes(credential))), "rp_result", result);
                writeReceipt(receipt); runOnUiThread(() -> { if (!destroyed && token == operation) { busy = false; status.setText("PASS: RP verified " + (create ? "registration" : "authentication")); } });
            } catch (Exception error) { runOnUiThread(() -> failed(token, create, wrongRp, "rp_verification_failed", null)); }
        });
    }
    private void failed(long token, boolean create, boolean wrongRp, String code, String platformType) {
        if (destroyed || token != operation) return; busy = false; status.setText(code + (platformType == null ? "" : "\n" + platformType));
        try { writeReceipt(Json.map("schema", 1L, "operation", create ? "create" : "get", "wrong_rp", wrongRp,
            "platform_callback", code.equals("platform_rejected") ? "error" : "unconfirmed", "rp_verified", false, "error", code, "platform_error_type", platformType)); }
        catch (Exception ignored) { status.setText("receipt_write_failed"); }
    }
    private void writeReceipt(Map<String,Object> value) throws Exception {
        // Public result metadata only: no password, private key, request body or pending challenge.
        try (FileOutputStream output = openFileOutput("result.public.json", MODE_PRIVATE)) { output.write(Json.bytes(value)); output.flush(); output.getFD().sync(); }
    }
    private Map<String,Object> post(String path, Map<String,Object> value) throws Exception {
        HttpURLConnection connection = (HttpURLConnection)new URL(Protocol.RP_BASE + path).openConnection();
        try {
            connection.setInstanceFollowRedirects(false); connection.setConnectTimeout(5000); connection.setReadTimeout(10000);
            connection.setRequestMethod("POST"); connection.setRequestProperty("Content-Type", "application/json");
            byte[] body = Json.bytes(value); connection.setFixedLengthStreamingMode(body.length); connection.setDoOutput(true);
            try (java.io.OutputStream out = connection.getOutputStream()) { out.write(body); }
            Failure.require(connection.getResponseCode() == 200, "rp_http_rejected");
            String contentType = connection.getContentType(); Failure.require(contentType != null && contentType.startsWith("application/json"), "rp_content_type");
            try (InputStream input = connection.getInputStream()) {
                ByteArrayOutputStream output = new ByteArrayOutputStream(); byte[] block = new byte[4096]; int count;
                while ((count = input.read(block)) != -1) { Failure.require(output.size() + count <= Protocol.MAX_REQUEST, "rp_input_limit"); output.write(block, 0, count); }
                return Json.object(Json.parse(output.toByteArray()));
            }
        } finally { connection.disconnect(); }
    }
    @Override protected void onDestroy() { destroyed = true; operation++; if (cancellation != null) cancellation.cancel(); worker.shutdown(); super.onDestroy(); }
}
