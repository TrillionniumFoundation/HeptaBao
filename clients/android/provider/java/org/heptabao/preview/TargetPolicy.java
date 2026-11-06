package org.heptabao.preview;

import android.app.assist.AssistStructure;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.view.View;
import android.view.autofill.AutofillId;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.Arrays;

/** Trust the system activity identity and installed signing certificate, never a claimed origin. */
final class TargetPolicy {
    static final class Rejected extends Exception {
        final String code;
        Rejected(String code) { super(code); this.code = code; }
    }
    static final class Target {
        final ComponentName component;
        final AutofillId username;
        final AutofillId password;
        Target(ComponentName component, AutofillId username, AutofillId password) {
            this.component = component; this.username = username; this.password = password;
        }
        boolean same(Target other) {
            return component.equals(other.component) && username.equals(other.username) && password.equals(other.password);
        }
    }
    static void certificate(Context context, String packageName) throws Rejected {
        if (!BuildConfig.TARGET_PACKAGE.equals(packageName)) throw new Rejected("wrong_package");
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
            if (info.signingInfo == null) throw new Rejected("wrong_certificate");
            Signature[] signers = info.signingInfo.getApkContentsSigners();
            // This qualification scope pins exactly one current signer. Rotation/multiple signers are unsupported.
            if (signers == null || signers.length != 1 || info.signingInfo.hasMultipleSigners()) throw new Rejected("wrong_certificate");
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray());
            byte[] expected = new byte[32];
            for (int i = 0; i < expected.length; i++) expected[i] = (byte)Integer.parseInt(BuildConfig.TARGET_CERT_SHA256.substring(i * 2, i * 2 + 2), 16);
            if (!MessageDigest.isEqual(digest, expected)) throw new Rejected("wrong_certificate");
        } catch (PackageManager.NameNotFoundException | GeneralSecurityException | IllegalArgumentException error) {
            throw new Rejected("wrong_certificate");
        }
    }
    static Target inspect(Context context, AssistStructure structure) throws Rejected {
        if (structure == null || structure.getActivityComponent() == null) throw new Rejected("missing_structure");
        ComponentName component = structure.getActivityComponent();
        certificate(context, component.getPackageName());
        if (!component.getClassName().equals("org.heptabao.fixture.FixtureActivity")) throw new Rejected("wrong_activity");
        if (structure.getWindowNodeCount() != 1) throw new Rejected("unsupported_windows");
        ArrayDeque<AssistStructure.ViewNode> queue = new ArrayDeque<>();
        queue.add(structure.getWindowNodeAt(0).getRootViewNode());
        AutofillId username = null, password = null;
        int visited = 0;
        while (!queue.isEmpty()) {
            AssistStructure.ViewNode node = queue.removeFirst();
            if (++visited > 2048) throw new Rejected("structure_too_large");
            String name = node.getClassName();
            if (node.getWebDomain() != null || node.getHtmlInfo() != null || (name != null && name.contains("WebView"))) throw new Rejected("webview_unsupported");
            String entry = node.getIdEntry();
            if ("login_username".equals(entry) || "login_password".equals(entry)) {
                if (!BuildConfig.TARGET_PACKAGE.equals(node.getIdPackage()) || !"android.widget.EditText".equals(name)
                    || node.getAutofillType() != View.AUTOFILL_TYPE_TEXT || node.getAutofillId() == null
                    || !node.isEnabled() || node.getVisibility() != View.VISIBLE) throw new Rejected("wrong_fields");
                String[] hints = node.getAutofillHints();
                if (hints == null) throw new Rejected("wrong_fields");
                if (entry.equals("login_username")) {
                    if (username != null || !Arrays.asList(hints).contains(View.AUTOFILL_HINT_USERNAME)) throw new Rejected("wrong_fields");
                    username = node.getAutofillId();
                } else {
                    if (password != null || !Arrays.asList(hints).contains(View.AUTOFILL_HINT_PASSWORD)) throw new Rejected("wrong_fields");
                    password = node.getAutofillId();
                }
            }
            int children = node.getChildCount();
            if (children > 2048 - visited || queue.size() + children > 2048) throw new Rejected("structure_too_large");
            for (int i = 0; i < children; i++) queue.add(node.getChildAt(i));
        }
        if (username == null || password == null || username.equals(password)) throw new Rejected("wrong_fields");
        return new Target(component, username, password);
    }
}
