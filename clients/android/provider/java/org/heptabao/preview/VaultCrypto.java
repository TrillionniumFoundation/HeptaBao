package org.heptabao.preview;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/** Read-only .hbv format 1 interoperability. No alternative KDF or homemade cipher. */
final class VaultCrypto {
    static final int MAX_FILE_BYTES = 8 * 1024 * 1024;
    static final class Failure extends Exception {
        final String code;
        Failure(String code) { super(code); this.code = code; }
    }
    static final class Login implements AutoCloseable {
        final char[] username;
        final char[] password;
        Login(String username, String password) {
            this.username = username.toCharArray(); this.password = password.toCharArray();
        }
        @Override public void close() { Arrays.fill(username, '\0'); Arrays.fill(password, '\0'); }
    }
    static final class Envelope {
        final String vaultId;
        final long revision;
        final String salt;
        final Sealed passwordWrap;
        final Sealed recoveryWrap;
        final Sealed body;
        Envelope(Map<String,Object> value) throws Failure {
            keys(value, "format", "cipher", "kdf", "vault_id", "revision", "salt", "password_wrap", "recovery_wrap", "body");
            number(value.get("format"), 1);
            equal(string(value.get("cipher")), "AES-256-GCM");
            Map<String,Object> kdf = object(value.get("kdf"));
            keys(kdf, "algorithm", "version", "memory_kib", "iterations", "parallelism");
            equal(string(kdf.get("algorithm")), "argon2id");
            number(kdf.get("version"), 19); number(kdf.get("memory_kib"), 65536);
            number(kdf.get("iterations"), 3); number(kdf.get("parallelism"), 4);
            vaultId = string(value.get("vault_id")); decode(vaultId, 16);
            revision = integer(value.get("revision"));
            salt = string(value.get("salt")); decode(salt, 16);
            passwordWrap = new Sealed(object(value.get("password_wrap")), 48);
            recoveryWrap = new Sealed(object(value.get("recovery_wrap")), 48);
            body = new Sealed(object(value.get("body")), -1);
        }
        byte[] aad() {
            return ("{\"domain\":\"heptabao-personal-vault/body/v1\",\"format\":1,\"cipher\":\"AES-256-GCM\","
                + "\"kdf\":{\"algorithm\":\"argon2id\",\"version\":19,\"memory_kib\":65536,\"iterations\":3,\"parallelism\":4},"
                + "\"vault_id\":\"" + vaultId + "\",\"revision\":" + revision + ",\"salt\":\"" + salt
                + "\",\"password_wrap\":" + passwordWrap.json() + ",\"recovery_wrap\":" + recoveryWrap.json() + "}")
                .getBytes(StandardCharsets.UTF_8);
        }
    }
    static final class Sealed {
        final String nonce;
        final String ciphertext;
        Sealed(Map<String,Object> value, int length) throws Failure {
            keys(value, "nonce", "ciphertext");
            nonce = string(value.get("nonce")); ciphertext = string(value.get("ciphertext"));
            decode(nonce, 12);
            byte[] checked = decode(ciphertext, length);
            if (checked.length < 16) throw bad();
        }
        String json() { return "{\"nonce\":\"" + nonce + "\",\"ciphertext\":\"" + ciphertext + "\"}"; }
    }
    static Envelope parse(byte[] file) throws Failure { return new Envelope(object(StrictJson.parse(file))); }
    static byte[] passwordBytes(char[] chars) throws Failure {
        ByteBuffer encoded = null;
        try {
            encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(chars));
            if (encoded.remaining() < 12 || encoded.remaining() > 1024) throw new Failure("invalid_password_length");
            byte[] result = new byte[encoded.remaining()]; encoded.get(result); return result;
        } catch (CharacterCodingException error) { throw new Failure("invalid_password_length"); }
        finally { if (encoded != null && encoded.hasArray()) Arrays.fill(encoded.array(), (byte)0); }
    }
    static Login unlock(byte[] file, byte[] password, String itemId, String origin) throws Failure {
        if (password.length < 12 || password.length > 1024) throw new Failure("invalid_password_length");
        Envelope env = parse(file);
        byte[] wrapping = new byte[32]; byte[] key = null; byte[] clear = null;
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13).withMemoryAsKB(65536)
            .withIterations(3).withParallelism(4).withSalt(decode(env.salt, 16)).build();
        try {
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params); generator.generateBytes(password, wrapping);
            byte[] wrapAad = ("[\"heptabao-personal-vault/key-wrap/v1\",1,\"" + env.vaultId + "\",\"password\"]")
                .getBytes(StandardCharsets.UTF_8);
            key = open(wrapping, wrapAad, env.passwordWrap);
            if (key.length != 32) throw bad();
            clear = open(key, env.aad(), env.body);
            Map<String,Object> payload = object(StrictJson.parse(clear));
            keys(payload, "vault_id", "revision", "items");
            equal(string(payload.get("vault_id")), env.vaultId);
            number(payload.get("revision"), env.revision);
            if (!(payload.get("items") instanceof List)) throw bad();
            List<?> items = (List<?>)payload.get("items");
            if (items.size() > 4096) throw bad();
            Set<String> ids = new HashSet<>();
            Login selected = null;
            try {
                for (Object raw : items) {
                    Map<String,Object> item = object(raw);
                    keys(item, "id", "kind", "title", "username", "origin", "secret", "notes", "totp");
                    String id = string(item.get("id"));
                    if (!id.matches("[A-Za-z0-9_-]{1,64}") || !ids.add(id)) throw bad();
                    String kind = string(item.get("kind"));
                    if (!kind.equals("login") && !kind.equals("note") && !kind.equals("api")) throw bad();
                    bounded(string(item.get("title")), 1, 1024);
                    String user = optional(item.get("username"));
                    if (user != null) bounded(user, 0, 4096);
                    String site = optional(item.get("origin"));
                    if (site != null && !httpsOrigin(site)) throw bad();
                    String secret = string(item.get("secret")); bounded(secret, 0, 65536);
                    bounded(string(item.get("notes")), 0, 65536);
                    if (kind.equals("login") && (site == null || secret.isEmpty())) throw bad();
                    checkTotp(item.get("totp"));
                    if (id.equals(itemId)) {
                        if (!kind.equals("login") || !origin.equals(site) || user == null || user.isEmpty()) throw new Failure("entry_not_mapped");
                        selected = new Login(user, secret);
                    }
                }
                if (selected == null) throw new Failure("entry_not_mapped");
                Login output = selected; selected = null; return output;
            } finally { if (selected != null) selected.close(); }
        } catch (IllegalArgumentException error) { throw bad(); }
        finally {
            Arrays.fill(wrapping, (byte)0); params.clear();
            if (key != null) Arrays.fill(key, (byte)0);
            if (clear != null) Arrays.fill(clear, (byte)0);
        }
    }
    private static byte[] open(byte[] key, byte[] aad, Sealed sealed) throws Failure {
        byte[] encrypted = decode(sealed.ciphertext, -1);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, decode(sealed.nonce, 12)));
            cipher.updateAAD(aad); return cipher.doFinal(encrypted);
        } catch (GeneralSecurityException error) { throw new Failure("wrong_key_or_corrupt"); }
        finally { Arrays.fill(encrypted, (byte)0); }
    }
    private static void checkTotp(Object raw) throws Failure {
        if (raw == null) return;
        Map<String,Object> config = object(raw);
        keys(config, "secret_base32", "algorithm", "digits", "period");
        String algorithm = string(config.get("algorithm"));
        if (!algorithm.equals("SHA1") && !algorithm.equals("SHA256") && !algorithm.equals("SHA512")) throw bad();
        long digits = integer(config.get("digits")), period = integer(config.get("period"));
        if (digits < 6 || digits > 8 || period < 15 || period > 120) throw bad();
        String encoded = string(config.get("secret_base32"));
        if (!encoded.matches("[A-Z2-7]{26,208}")) throw bad();
        int mod = encoded.length() % 8;
        if (mod != 0 && mod != 2 && mod != 4 && mod != 5 && mod != 7) throw bad();
        int bits = 0, count = 0, length = 0;
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            bits = (bits << 5) | (c >= 'A' && c <= 'Z' ? c - 'A' : c - '2' + 26); count += 5;
            if (count >= 8) { count -= 8; length++; bits &= (1 << count) - 1; }
        }
        if (bits != 0 || length < 16 || length > 128) throw bad();
    }
    private static boolean httpsOrigin(String value) {
        if (!value.startsWith("https://")) return false;
        String authority = value.substring(8);
        if (authority.isEmpty() || authority.length() > 260) return false;
        String[] parts = authority.split(":", -1);
        if (parts.length > 2) return false;
        if (parts.length == 2) {
            if (!parts[1].matches("[1-9][0-9]{0,4}")) return false;
            int port = Integer.parseInt(parts[1]); if (port > 65535 || port == 443) return false;
        }
        String host = parts[0]; if (host.length() > 253 || !host.contains(".")) return false;
        String[] labels = host.split("\\.", -1); String last = labels[labels.length - 1];
        if (last.matches("[0-9]+") || last.matches("0x[0-9a-fA-F]*")) return false;
        for (String label : labels) {
            if (!label.matches("[a-z0-9-]{1,63}") || label.startsWith("-") || label.endsWith("-")) return false;
        }
        return true;
    }
    static byte[] decode(String value, int exact) throws Failure {
        if (value.length() > MAX_FILE_BYTES || !value.matches("[A-Za-z0-9+/]*")) throw bad();
        try {
            byte[] result = Base64.getDecoder().decode(value);
            if ((exact >= 0 && result.length != exact) || !Base64.getEncoder().withoutPadding().encodeToString(result).equals(value)) throw bad();
            return result;
        } catch (IllegalArgumentException error) { throw bad(); }
    }
    private static void bounded(String value, int min, int max) throws Failure {
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x80) count++;
            else if (c < 0x800) count += 2;
            else if (Character.isHighSurrogate(c)) { i++; count += 4; }
            else count += 3;
        }
        if (count < min || count > max) throw bad();
    }
    @SuppressWarnings("unchecked") static Map<String,Object> object(Object raw) throws Failure {
        if (!(raw instanceof Map)) throw bad(); return (Map<String,Object>)raw;
    }
    static String string(Object raw) throws Failure { if (!(raw instanceof String)) throw bad(); return (String)raw; }
    private static String optional(Object raw) throws Failure { return raw == null ? null : string(raw); }
    private static long integer(Object raw) throws Failure { if (!(raw instanceof Long) || (Long)raw < 0) throw bad(); return (Long)raw; }
    private static void number(Object raw, long expected) throws Failure { if (integer(raw) != expected) throw bad(); }
    private static void equal(String raw, String expected) throws Failure { if (!raw.equals(expected)) throw bad(); }
    private static void keys(Map<String,Object> value, String... names) throws Failure {
        if (!value.keySet().equals(new HashSet<>(Arrays.asList(names)))) throw bad();
    }
    private static Failure bad() { return new Failure("invalid_format"); }
}
