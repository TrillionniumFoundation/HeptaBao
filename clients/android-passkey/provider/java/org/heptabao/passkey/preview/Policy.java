package org.heptabao.passkey.preview;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Bundle;
import android.service.credentials.CallingAppInfo;
import java.security.MessageDigest;
import org.heptabao.passkey.core.Codec;
import org.heptabao.passkey.core.Failure;
import org.heptabao.passkey.core.Protocol;

final class Policy {
    static String caller(Context context, CallingAppInfo info) throws Failure {
        Failure.require(info != null && Protocol.FIXTURE_PACKAGE.equals(info.getPackageName()), "wrong_application");
        Failure.require(info.getOrigin() == null, "privileged_origin_unsupported");
        byte[] pinned = Codec.unhex(BuildConfig.FIXTURE_CERT_SHA256);
        byte[] actual = signing(info.getSigningInfo());
        Failure.require(MessageDigest.isEqual(pinned, actual), "wrong_certificate");
        try {
            PackageInfo current = context.getPackageManager().getPackageInfo(Protocol.FIXTURE_PACKAGE,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES));
            Failure.require(MessageDigest.isEqual(pinned, signing(current.signingInfo)), "calling_application_changed");
        } catch (PackageManager.NameNotFoundException error) { throw new Failure("calling_application_missing"); }
        return "android:apk-key-hash:" + Codec.url(actual);
    }
    private static byte[] signing(SigningInfo info) throws Failure {
        Failure.require(info != null && !info.hasMultipleSigners(), "unsupported_signer_set");
        Signature[] signatures = info.getApkContentsSigners();
        Failure.require(signatures != null && signatures.length == 1, "unsupported_signer_set");
        return Codec.sha(signatures[0].toByteArray());
    }
    static String request(Bundle bundle) throws Failure {
        Failure.require(bundle != null && bundle.getByteArray(Protocol.CLIENT_DATA_HASH) == null, "client_data_hash_unsupported");
        String json = bundle.getString(Protocol.REQUEST_JSON);
        Failure.require(json != null && json.length() <= Protocol.MAX_REQUEST, "invalid_request"); return json;
    }
}
