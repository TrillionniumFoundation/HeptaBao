package org.heptabao.passkey.core;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/** Existing HeptaBao .hbv format 1. Imports an existing vault; no new password format. */
public final class Hbv {
    private static final String CIPHER = "AES-256-GCM";
    private static final int MAX_PLAINTEXT = 4 * 1024 * 1024;
    private static Map<String,Object> kdf() {
        return Json.map("algorithm", "argon2id", "version", 19L, "memory_kib", 65536L,
                        "iterations", 3L, "parallelism", 4L);
    }
    private static long unsigned(Object value) throws Failure {
        long number = Json.integer(value); Failure.require(number >= 0, "invalid_vault"); return number;
    }
    private static void equal(Object value, Object expected) throws Failure {
        Failure.require(expected.equals(value), "invalid_vault");
    }
    private static Map<String,Object> sealed(Object raw, boolean wrap) throws Failure {
        Map<String,Object> value = Json.object(raw); Json.keys(value, "nonce", "ciphertext");
        Codec.decodeStd(Json.string(value.get("nonce")), 12, 12);
        Codec.decodeStd(Json.string(value.get("ciphertext")), wrap ? 48 : 16, wrap ? 48 : Json.MAX_BYTES);
        return Json.map("nonce", value.get("nonce"), "ciphertext", value.get("ciphertext"));
    }
    private static Map<String,Object> envelope(byte[] file) throws Failure {
        Map<String,Object> value = Json.object(Json.parse(file));
        Json.keys(value, "format", "cipher", "kdf", "vault_id", "revision", "salt", "password_wrap", "recovery_wrap", "body");
        equal(value.get("format"), 1L); equal(value.get("cipher"), CIPHER);
        Map<String,Object> parameters = Json.object(value.get("kdf"));
        Json.keys(parameters, "algorithm", "version", "memory_kib", "iterations", "parallelism");
        for (Map.Entry<String,Object> item : kdf().entrySet()) equal(parameters.get(item.getKey()), item.getValue());
        Codec.decodeStd(Json.string(value.get("vault_id")), 16, 16);
        Codec.decodeStd(Json.string(value.get("salt")), 16, 16);
        unsigned(value.get("revision"));
        return Json.map("format", 1L, "cipher", CIPHER, "kdf", kdf(), "vault_id", value.get("vault_id"),
            "revision", value.get("revision"), "salt", value.get("salt"),
            "password_wrap", sealed(value.get("password_wrap"), true),
            "recovery_wrap", sealed(value.get("recovery_wrap"), true), "body", sealed(value.get("body"), false));
    }
    private static byte[] wrapAad(String vaultId, String role) throws Failure {
        return Json.bytes(Arrays.asList("heptabao-personal-vault/key-wrap/v1", 1L, vaultId, role));
    }
    private static byte[] bodyAad(Map<String,Object> envelope) throws Failure {
        return Json.bytes(Json.map("domain", "heptabao-personal-vault/body/v1", "format", 1L,
            "cipher", CIPHER, "kdf", kdf(), "vault_id", envelope.get("vault_id"),
            "revision", envelope.get("revision"), "salt", envelope.get("salt"),
            "password_wrap", envelope.get("password_wrap"), "recovery_wrap", envelope.get("recovery_wrap")));
    }
    public static byte[] passwordBytes(char[] password) throws Failure {
        ByteBuffer buffer = null;
        try {
            buffer = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(password));
            Failure.require(buffer.remaining() >= 12 && buffer.remaining() <= 1024, "invalid_password");
            byte[] result = new byte[buffer.remaining()]; buffer.get(result); return result;
        } catch (CharacterCodingException error) { throw new Failure("invalid_password"); }
        finally { if (buffer != null && buffer.hasArray()) Arrays.fill(buffer.array(), (byte)0); }
    }
    public static Unlocked unlock(byte[] file, byte[] password) throws Failure {
        Failure.require(password.length >= 12 && password.length <= 1024, "invalid_password");
        Map<String,Object> envelope = envelope(file);
        byte[] wrapping = new byte[32]; byte[] key = null;
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13).withMemoryAsKB(65536)
            .withIterations(3).withParallelism(4)
            .withSalt(Codec.decodeStd(Json.string(envelope.get("salt")), 16, 16)).build();
        try {
            Argon2BytesGenerator generator = new Argon2BytesGenerator(); generator.init(parameters);
            generator.generateBytes(password, wrapping);
            key = decrypt(wrapping, wrapAad(Json.string(envelope.get("vault_id")), "password"), Json.object(envelope.get("password_wrap")));
            Failure.require(key.length == 32, "wrong_key_or_corrupt");
            Unlocked result = unlockKey(file, envelope, key); key = null; return result;
        } catch (IllegalArgumentException error) { throw new Failure("invalid_vault"); }
        finally { Arrays.fill(wrapping, (byte)0); parameters.clear(); if (key != null) Arrays.fill(key, (byte)0); }
    }
    public static Unlocked unlockRecovery(byte[] file, byte[] recovery) throws Failure {
        Failure.require(recovery.length == 32, "invalid_recovery");
        Map<String,Object> envelope = envelope(file); byte[] key = null;
        try {
            key = decrypt(recovery, wrapAad(Json.string(envelope.get("vault_id")), "recovery"), Json.object(envelope.get("recovery_wrap")));
            Failure.require(key.length == 32, "wrong_key_or_corrupt");
            Unlocked result = unlockKey(file, envelope, key); key = null; return result;
        } finally { if (key != null) Arrays.fill(key, (byte)0); }
    }
    private static Unlocked unlockKey(byte[] file, Map<String,Object> envelope, byte[] key) throws Failure {
        byte[] clear = decrypt(key, bodyAad(envelope), Json.object(envelope.get("body")));
        try {
            Failure.require(clear.length <= MAX_PLAINTEXT, "input_limit");
            Map<String,Object> payload = Json.object(Json.parse(clear));
            validatePayload(payload);
            equal(payload.get("vault_id"), envelope.get("vault_id"));
            equal(payload.get("revision"), envelope.get("revision"));
            return new Unlocked(envelope, payload, key, Codec.sha(file));
        } finally { Arrays.fill(clear, (byte)0); }
    }
    private static byte[] decrypt(byte[] key, byte[] aad, Map<String,Object> sealed) throws Failure {
        byte[] encrypted = Codec.decodeStd(Json.string(sealed.get("ciphertext")), 16, Json.MAX_BYTES);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, Codec.decodeStd(Json.string(sealed.get("nonce")), 12, 12)));
            cipher.updateAAD(aad); return cipher.doFinal(encrypted);
        } catch (GeneralSecurityException error) { throw new Failure("wrong_key_or_corrupt"); }
        finally { Arrays.fill(encrypted, (byte)0); }
    }
    private static Map<String,Object> encrypt(byte[] key, byte[] aad, byte[] clear) throws Failure {
        byte[] nonce = Codec.random(12);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            byte[] encrypted = cipher.doFinal(clear);
            return Json.map("nonce", Codec.std(nonce), "ciphertext", Codec.std(encrypted));
        } catch (GeneralSecurityException error) { throw new Failure("encryption_failed"); }
    }
    private static void bounded(String value, int min, int max) throws Failure {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        try { Failure.require(bytes.length >= min && bytes.length <= max, "invalid_vault"); }
        finally { Arrays.fill(bytes, (byte)0); }
    }
    private static void validatePayload(Map<String,Object> payload) throws Failure {
        Json.keys(payload, "vault_id", "revision", "items");
        Codec.decodeStd(Json.string(payload.get("vault_id")), 16, 16); unsigned(payload.get("revision"));
        List<Object> items = Json.list(payload.get("items"));
        Failure.require(items.size() <= 4096, "capacity"); HashSet<String> ids = new HashSet<>();
        for (Object raw : items) {
            Map<String,Object> item = Json.object(raw);
            Json.keys(item, "id", "kind", "title", "username", "origin", "secret", "notes", "totp");
            String id = Json.string(item.get("id"));
            Failure.require(id.matches("[A-Za-z0-9_-]{1,64}") && ids.add(id), "invalid_vault");
            String kind = Json.string(item.get("kind"));
            Failure.require(kind.equals("login") || kind.equals("note") || kind.equals("api"), "invalid_vault");
            bounded(Json.string(item.get("title")), 1, 1024);
            if (item.get("username") != null) bounded(Json.string(item.get("username")), 0, 4096);
            if (item.get("origin") != null) Failure.require(httpsOrigin(Json.string(item.get("origin"))), "invalid_vault");
            String secret = Json.string(item.get("secret")); bounded(secret, 0, 65536);
            bounded(Json.string(item.get("notes")), 0, 65536);
            Failure.require(!kind.equals("login") || (item.get("origin") != null && !secret.isEmpty()), "invalid_vault");
            validateTotp(item.get("totp"));
        }
    }
    private static void validateTotp(Object raw) throws Failure {
        if (raw == null) return;
        Map<String,Object> value = Json.object(raw); Json.keys(value, "secret_base32", "algorithm", "digits", "period");
        String algorithm = Json.string(value.get("algorithm"));
        Failure.require(algorithm.equals("SHA1") || algorithm.equals("SHA256") || algorithm.equals("SHA512"), "invalid_vault");
        long digits = unsigned(value.get("digits")), period = unsigned(value.get("period"));
        Failure.require(digits >= 6 && digits <= 8 && period >= 15 && period <= 120, "invalid_vault");
        String seed = Json.string(value.get("secret_base32"));
        Failure.require(seed.matches("[A-Z2-7]{26,208}"), "invalid_vault");
        int residue = seed.length() % 8;
        Failure.require(residue == 0 || residue == 2 || residue == 4 || residue == 5 || residue == 7, "invalid_vault");
        int bits = 0, count = 0, bytes = 0;
        for (int i = 0; i < seed.length(); i++) {
            char c = seed.charAt(i); bits = (bits << 5) | (c >= 'A' && c <= 'Z' ? c - 'A' : c - '2' + 26); count += 5;
            if (count >= 8) { count -= 8; bytes++; bits &= (1 << count) - 1; }
        }
        Failure.require(bits == 0 && bytes >= 16 && bytes <= 128, "invalid_vault");
    }
    private static boolean httpsOrigin(String value) {
        if (!value.startsWith("https://")) return false;
        String authority = value.substring(8); if (authority.length() > 260) return false;
        String[] parts = authority.split(":", -1); if (parts.length > 2) return false;
        if (parts.length == 2) {
            if (!parts[1].matches("[1-9][0-9]{0,4}")) return false;
            int port = Integer.parseInt(parts[1]); if (port > 65535 || port == 443) return false;
        }
        String host = parts[0]; if (host.length() > 253 || !host.contains(".")) return false;
        String[] labels = host.split("\\.", -1); String last = labels[labels.length - 1];
        if (last.matches("[0-9]+") || last.matches("0x[0-9a-f]*")) return false;
        for (String label : labels) if (!label.matches("[a-z0-9-]{1,63}") || label.startsWith("-") || label.endsWith("-")) return false;
        return true;
    }
    public static final class Unlocked implements AutoCloseable {
        private final Map<String,Object> envelope;
        public final Map<String,Object> payload;
        public final byte[] expectedFileSha256;
        private byte[] key;
        private boolean staged;
        private Unlocked(Map<String,Object> envelope, Map<String,Object> payload, byte[] key, byte[] digest) {
            this.envelope = envelope; this.payload = payload; this.key = key; this.expectedFileSha256 = digest;
        }
        public String vaultId() throws Failure { open(); return Json.string(payload.get("vault_id")); }
        public long revision() throws Failure { open(); return unsigned(payload.get("revision")); }
        public List<Object> items() throws Failure { open(); return Json.list(payload.get("items")); }
        private void open() throws Failure { Failure.require(key != null, "locked"); }
        public byte[] encryptNext() throws Failure {
            open(); Failure.require(!staged, "outcome_requires_reopen"); staged = true;
            long revision = revision(); Failure.require(revision < Long.MAX_VALUE, "capacity");
            payload.put("revision", revision + 1); envelope.put("revision", revision + 1);
            validatePayload(payload); byte[] clear = Json.bytes(payload);
            try {
                Failure.require(clear.length <= MAX_PLAINTEXT, "capacity");
                envelope.put("body", encrypt(key, bodyAad(envelope), clear));
                byte[] output = Json.bytes(envelope); Failure.require(output.length <= Json.MAX_BYTES, "capacity"); return output;
            } finally { Arrays.fill(clear, (byte)0); }
        }
        @Override public void close() {
            if (key != null) Arrays.fill(key, (byte)0); key = null; payload.clear(); envelope.clear();
        }
    }
}
