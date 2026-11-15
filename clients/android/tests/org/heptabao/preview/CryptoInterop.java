package org.heptabao.preview;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;

/** Runs against a fresh envelope created by the actual Rust CLI. Prints no secrets. */
public final class CryptoInterop {
    interface Checked { void run() throws Exception; }
    private static int passed;
    private static void rejected(String code, Checked action) throws Exception {
        try { action.run(); throw new IllegalStateException("rejection_missing"); }
        catch (VaultCrypto.Failure failure) { if (!failure.code.equals(code)) throw new IllegalStateException("wrong_rejection_code"); }
        passed++;
    }
    private static String digest(char[] chars) throws Exception {
        byte[] bytes = new String(chars).getBytes(StandardCharsets.UTF_8);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes); StringBuilder out = new StringBuilder();
            for (byte value : digest) out.append(String.format(java.util.Locale.ROOT, "%02x", value & 255)); return out.toString();
        } finally { Arrays.fill(bytes, (byte)0); }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("fixture_directory_required");
        Path root = Path.of(args[0]); byte[] envelope = Files.readAllBytes(root.resolve("vault.hbv"));
        byte[] master = Files.readAllBytes(root.resolve("master.private"));
        Map<String,Object> expected = VaultCrypto.object(StrictJson.parse(Files.readAllBytes(root.resolve("expected.json"))));
        String id = VaultCrypto.string(expected.get("entry_id")), origin = VaultCrypto.string(expected.get("origin"));
        try {
            try (VaultCrypto.Login login = VaultCrypto.unlock(envelope, master, id, origin)) {
                if (!digest(login.username).equals(expected.get("username_sha256")) || !digest(login.password).equals(expected.get("password_sha256"))) throw new IllegalStateException("interop_digest_mismatch");
                passed++;
            }
            byte[] wrong = master.clone(); wrong[0] ^= 1;
            rejected("wrong_key_or_corrupt", () -> VaultCrypto.unlock(envelope, wrong, id, origin)); Arrays.fill(wrong, (byte)0);
            String encoded = new String(envelope, StandardCharsets.UTF_8);
            rejected("invalid_format", () -> VaultCrypto.parse(encoded.replaceFirst("\\{", "{\"unknown\":1,").getBytes(StandardCharsets.UTF_8)));
            rejected("invalid_format", () -> VaultCrypto.parse(encoded.replaceFirst("\\{", "{\"format\":1,").getBytes(StandardCharsets.UTF_8)));
            rejected("invalid_format", () -> VaultCrypto.parse(encoded.replace("\"memory_kib\":65536", "\"memory_kib\":1024").getBytes(StandardCharsets.UTF_8)));
            rejected("invalid_format", () -> VaultCrypto.parse(encoded.replace("\"revision\":1", "\"revision\":9223372036854775808").getBytes(StandardCharsets.UTF_8)));
            rejected("wrong_key_or_corrupt", () -> VaultCrypto.unlock(encoded.replace("\"revision\":1", "\"revision\":2").getBytes(StandardCharsets.UTF_8), master, id, origin));
            rejected("entry_not_mapped", () -> VaultCrypto.unlock(envelope, master, "wrong-entry", origin));
            rejected("invalid_format", () -> VaultCrypto.decode("AA==", 1));
            rejected("invalid_format", () -> VaultCrypto.decode("AB", 1));
            rejected("invalid_format", () -> StrictJson.parse(new byte[]{(byte)0xc0, (byte)0xaf}));
            rejected("input_too_large", () -> VaultCrypto.parse(new byte[VaultCrypto.MAX_FILE_BYTES + 1]));
            System.out.println("{\"ok\":true,\"checks\":" + passed + ",\"rust_to_java_digest_match\":true,\"kdf\":\"argon2id-v19-m65536-t3-p4\"}");
        } finally { Arrays.fill(master, (byte)0); }
    }
}
