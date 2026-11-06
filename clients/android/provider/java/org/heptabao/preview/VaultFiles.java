package org.heptabao.preview;

import android.content.Context;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.SystemClock;
import android.content.res.AssetFileDescriptor;
import android.util.AtomicFile;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicReference;

final class VaultFiles {
    private static AtomicFile file(Context context) { return new AtomicFile(new File(context.getFilesDir(), "vault.hbv")); }
    static boolean exists(Context context) { return file(context).getBaseFile().isFile(); }
    static byte[] read(Context context) throws IOException, VaultCrypto.Failure {
        try (InputStream input = file(context).openRead()) { return bounded(input); }
    }
    static void importCiphertext(Context context, Uri uri, CancellationSignal cancel, long deadline,
                                 AtomicReference<InputStream> active) throws IOException, VaultCrypto.Failure {
        if (uri == null || !"content".equals(uri.getScheme())) throw new VaultCrypto.Failure("unsupported_input");
        byte[] bytes;
        try (AssetFileDescriptor descriptor = context.getContentResolver().openAssetFileDescriptor(uri, "r", cancel)) {
            if (descriptor == null) throw new IOException();
            try (InputStream input = descriptor.createInputStream()) {
                active.set(input); cancel.throwIfCanceled(); bytes = bounded(input);
            } finally { active.set(null); }
        }
        cancel.throwIfCanceled();
        if (SystemClock.elapsedRealtime() >= deadline) throw new IOException();
        VaultCrypto.parse(bytes);
        AtomicFile target = file(context);
        FileOutputStream output = null;
        try {
            output = target.startWrite(); output.write(bytes);
            cancel.throwIfCanceled();
            if (SystemClock.elapsedRealtime() >= deadline) throw new IOException();
            target.finishWrite(output); output = null;
        } finally { if (output != null) target.failWrite(output); }
    }
    private static byte[] bounded(InputStream input) throws IOException, VaultCrypto.Failure {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (out.size() + read > VaultCrypto.MAX_FILE_BYTES) throw new VaultCrypto.Failure("input_too_large");
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
