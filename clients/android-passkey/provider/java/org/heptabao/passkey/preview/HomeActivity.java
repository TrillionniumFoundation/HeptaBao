package org.heptabao.passkey.preview;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.credentials.CredentialManager;
import android.os.Bundle;
import android.net.Uri;
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
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.heptabao.passkey.core.Failure;
import org.heptabao.passkey.core.Hbv;

/** Restricted preview administration. Import/backup contain ciphertext only. */
public final class HomeActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private EditText password;
    private TextView status;
    private volatile boolean foreground;
    private boolean busy;
    private volatile long generation;
    private static final int PICK_IMPORT = 901;
    private static final int PICK_EXPORT = 902;
    private int pendingPicker;
    private Uri exportDestination;
    private String stagedCiphertextSha256;
    private volatile DocumentIO documentJob;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state); getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); layout.setPadding(32, 40, 32, 32);
        TextView title = new TextView(this); title.setText("HeptaBao Passkey Preview"); title.setTextSize(24); layout.addView(title);
        TextView note = new TextView(this);
        note.setText("Synthetic fixture only. Unlock lasts five minutes; every passkey operation asks for your password again. Choose an encrypted vault, then import it with its password. Recovery creates a fresh private store. Backups contain ciphertext only."); layout.addView(note);
        button(layout, "Choose encrypted vault file", 0x4a120008, () -> pick(false));
        password = new EditText(this); password.setSingleLine(true); password.setHint("Vault password");
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setFilters(new InputFilter[]{new InputFilter.LengthFilter(1024)});
        password.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        password.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        password.setSaveEnabled(false); password.setId(0x4a120001); layout.addView(password);
        button(layout, "Import encrypted vault into a fresh store", 0x4a120002, () -> start("import"));
        button(layout, "Unlock public credential list", 0x4a120003, () -> start("unlock"));
        button(layout, "Choose encrypted backup destination", 0x4a120009, () -> pick(true));
        button(layout, "Write encrypted backup to chosen file", 0x4a120004, () -> start("backup"));
        button(layout, "Lock now", 0x4a120005, () -> { generation++; Session.lock(); cancelDocument(); password.getText().clear(); status.setText("Locked"); });
        button(layout, "Cancel active document operation", 0x4a120010, () -> { generation++; cancelDocument(); status.setText("Document operation cancelled"); });
        button(layout, "Open provider settings", 0x4a120006, () -> {
            try {
                CredentialManager manager = getSystemService(CredentialManager.class);
                if (manager != null && manager.isEnabledCredentialProviderService(new ComponentName(this, ProviderService.class))) {
                    status.setText("Provider is already enabled in Android credential settings"); return;
                }
                startActivity(new Intent("android.settings.CREDENTIAL_PROVIDER")
                    .setData(Uri.fromParts("package", getPackageName(), null)));
            }
            catch (Exception error) { status.setText("Open Android Settings > Passwords, passkeys and accounts manually"); }
        });
        status = new TextView(this); status.setText("Locked until you import or unlock"); status.setId(0x4a120007); layout.addView(status);
        ScrollView scrolling = new ScrollView(this); scrolling.addView(layout); setContentView(scrolling);
    }
    private void button(LinearLayout layout, String text, int id, Runnable action) {
        Button button = new Button(this); button.setText(text); button.setId(id); button.setOnClickListener(view -> action.run()); layout.addView(button);
    }
    private void start(String action) {
        if (!foreground || busy) return;
        final long operationGeneration; final long expectedEpoch; final String expectedStore; final Uri destination; final String incomingHash;
        byte[] parsedBytes = null; char[] chars = new char[password.length()]; password.getText().getChars(0, chars.length, chars, 0); password.getText().clear();
        try {
            parsedBytes = Hbv.passwordBytes(chars);
            synchronized (Session.class) {
                if (action.equals("backup")) {
                    Failure.require(exportDestination != null, "choose_backup_destination_first");
                    expectedEpoch = Session.epoch(); expectedStore = Session.store(expectedEpoch); destination = exportDestination; exportDestination = null;
                } else { expectedEpoch = Session.lockEpoch(); expectedStore = null; destination = null; }
                if (action.equals("import")) Failure.require(stagedCiphertextSha256 != null, "choose_encrypted_vault_first");
                incomingHash = action.equals("import") ? stagedCiphertextSha256 : null;
                operationGeneration = ++generation; busy = true;
            }
        } catch (Exception error) { if (parsedBytes != null) Arrays.fill(parsedBytes, (byte)0); status.setText(ProviderService.safe(error)); return; }
        finally { Arrays.fill(chars, '\0'); }
        final byte[] bytes = parsedBytes;
        final DocumentIO documents = action.equals("backup") ? newDocument(operationGeneration) : null;
        if (documents != null) documentJob = documents;
        status.setText("Verifying vault password");
        worker.execute(() -> {
            boolean published = false;
            try {
                VaultFiles.Loaded loaded; String backupName;
                checkpoint(action, operationGeneration, expectedEpoch, expectedStore);
                VaultFiles.Prepared readyPrepared;
                try { readyPrepared = VaultFiles.prepare(this, action, expectedStore, incomingHash, bytes); }
                finally { Arrays.fill(bytes, (byte)0); }
                try (VaultFiles.Prepared prepared = readyPrepared) {
                    checkpoint(action, operationGeneration, expectedEpoch, expectedStore);
                    loaded = prepared.publish(); published = !action.equals("unlock"); backupName = prepared.backupName;
                    checkpoint(action, operationGeneration, expectedEpoch, expectedStore);
                }
                if (action.equals("backup")) {
                    checkpoint(action, operationGeneration, expectedEpoch, expectedStore);
                    VaultFiles.exportContent(this, backupName, destination, documents);
                    checkpoint(action, operationGeneration, expectedEpoch, expectedStore);
                }
                final VaultFiles.Loaded ready = loaded; final String exported = backupName;
                runOnUiThread(() -> complete(action, ready, exported, operationGeneration, expectedEpoch, expectedStore));
            } catch (Exception error) {
                String code = published ? "operation_outcome_unknown" : ProviderService.safe(error);
                runOnUiThread(() -> { busy = false; if (foreground && generation == operationGeneration) status.setText(code); });
            } finally {
                Arrays.fill(bytes, (byte)0);
                if (documents != null) { documents.close(); if (documentJob == documents) documentJob = null; }
            }
        });
    }
    private void checkpoint(String action, long operationGeneration, long expectedEpoch, String expectedStore) throws Failure {
        Failure.require(foreground && generation == operationGeneration, "operation_interrupted");
        if (action.equals("backup")) Session.check(expectedEpoch, expectedStore); else Session.checkLocked(expectedEpoch);
    }
    private void complete(String action, VaultFiles.Loaded loaded, String backupName, long operationGeneration, long expectedEpoch, String expectedStore) {
        try {
            synchronized (Session.class) {
                checkpoint(action, operationGeneration, expectedEpoch, expectedStore);
                if (action.equals("backup")) {
                    status.setText("Encrypted backup written and read-back verified");
                } else {
                    Session.unlock(expectedEpoch, loaded.store, loaded.labels);
                    if (action.equals("import")) stagedCiphertextSha256 = null;
                    status.setText("Unlocked public list: " + loaded.labels.size() + " passkeys; five minute limit");
                }
            }
        } catch (Exception error) { if (foreground && generation == operationGeneration) status.setText(ProviderService.safe(error)); }
        finally { busy = false; }
    }
    private void pick(boolean export) {
        if (busy || pendingPicker != 0) return;
        // Starting a new selection immediately invalidates the previous target.
        if (export) exportDestination = null; else stagedCiphertextSha256 = null;
        pendingPicker = export ? PICK_EXPORT : PICK_IMPORT;
        Intent intent = new Intent(export ? Intent.ACTION_CREATE_DOCUMENT : Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream");
        if (export) intent.putExtra(Intent.EXTRA_TITLE, "HeptaBao-passkey-backup.hbv");
        try { startActivityForResult(intent, pendingPicker); }
        catch (Exception error) { pendingPicker = 0; status.setText("document_picker_unavailable"); }
    }
    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != pendingPicker || pendingPicker == 0) return; pendingPicker = 0;
        if (resultCode != RESULT_OK || data == null || data.getData() == null) { status.setText("Document selection cancelled"); return; }
        Uri uri = data.getData();
        if (!"content".equals(uri.getScheme())) { status.setText("invalid_document"); return; }
        if (requestCode == PICK_EXPORT) { exportDestination = uri; status.setText("Destination chosen; enter password and write encrypted backup"); return; }
        Session.lock(); stagedCiphertextSha256 = null; busy = true; long selectionGeneration = ++generation;
        final DocumentIO documents = newDocument(selectionGeneration); documentJob = documents;
        status.setText("Reading encrypted document");
        worker.execute(() -> {
            String message; String digest = null;
            try { digest = VaultFiles.stage(this, uri, documents); message = "Ciphertext staged; enter password and import into a fresh store"; }
            catch (Exception error) { message = ProviderService.safe(error); }
            finally { documents.close(); if (documentJob == documents) documentJob = null; }
            final String result = message; final String verifiedDigest = digest;
            runOnUiThread(() -> {
                busy = false;
                if (generation == selectionGeneration) { stagedCiphertextSha256 = verifiedDigest; status.setText(result); }
            });
        });
    }
    private DocumentIO newDocument(long token) {
        return new DocumentIO(() -> runOnUiThread(() -> {
            if (generation == token) { generation++; status.setText("document_timeout"); }
        }));
    }
    private void cancelDocument() { DocumentIO operation = documentJob; if (operation != null) operation.cancel(); }
    @Override protected void onResume() { super.onResume(); foreground = true; }
    @Override protected void onPause() {
        foreground = false; generation++; cancelDocument();
        password.getText().clear(); super.onPause();
    }
    @Override protected void onDestroy() { worker.shutdown(); super.onDestroy(); }
}
