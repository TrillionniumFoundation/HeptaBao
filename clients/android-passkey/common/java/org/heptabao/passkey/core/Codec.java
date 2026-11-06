package org.heptabao.passkey.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

public final class Codec {
    private static final SecureRandom RANDOM = new SecureRandom();
    public static byte[] random(int length) { byte[] bytes = new byte[length]; RANDOM.nextBytes(bytes); return bytes; }
    public static byte[] sha(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (NoSuchAlgorithmException error) { throw new IllegalStateException("sha256_unavailable"); }
    }
    public static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) value.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return value.toString();
    }
    public static byte[] unhex(String text) throws Failure {
        Failure.require(text != null && text.matches("[0-9a-f]{64}"), "invalid_digest");
        byte[] result = new byte[32];
        for (int i = 0; i < result.length; i++) result[i] = (byte)Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        return result;
    }
    public static String std(byte[] bytes) { return Base64.getEncoder().withoutPadding().encodeToString(bytes); }
    public static String url(byte[] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    public static byte[] decodeStd(String text, int min, int max) throws Failure { return decode(text, min, max, false); }
    public static byte[] decodeUrl(String text, int min, int max) throws Failure { return decode(text, min, max, true); }
    private static byte[] decode(String text, int min, int max, boolean url) throws Failure {
        Failure.require(text != null && text.length() <= ((long)max + 2) / 3 * 4 && text.matches(url ? "[A-Za-z0-9_-]*" : "[A-Za-z0-9+/]*"), "invalid_base64");
        try {
            byte[] bytes = (url ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(text);
            Failure.require(bytes.length >= min && bytes.length <= max && (url ? url(bytes) : std(bytes)).equals(text), "invalid_base64");
            return bytes;
        } catch (IllegalArgumentException error) { throw new Failure("invalid_base64"); }
    }
    public static byte[] concat(byte[]... chunks) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] bytes : chunks) out.write(bytes, 0, bytes.length);
        return out.toByteArray();
    }
    /** Definite-length CBOR encoding only; cryptographic operations use JCA. */
    public static byte[] cbor(Object value) throws Failure {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); cborInto(out, value, 0);
        Failure.require(out.size() <= 65536, "cbor_limit"); return out.toByteArray();
    }
    private static void head(ByteArrayOutputStream out, int major, long value) throws Failure {
        Failure.require(value >= 0 && value <= 0xffffffffL, "cbor_limit");
        if (value < 24) out.write((major << 5) | (int)value);
        else if (value <= 255) { out.write((major << 5) | 24); out.write((int)value); }
        else if (value <= 65535) { out.write((major << 5) | 25); out.write((int)(value >>> 8)); out.write((int)value); }
        else { out.write((major << 5) | 26); for (int shift = 24; shift >= 0; shift -= 8) out.write((int)(value >>> shift)); }
    }
    private static void cborInto(ByteArrayOutputStream out, Object value, int depth) throws Failure {
        Failure.require(depth <= 8 && out.size() <= 65536, "cbor_limit");
        if (value instanceof Integer || value instanceof Long) {
            long n = ((Number)value).longValue(); head(out, n < 0 ? 1 : 0, n < 0 ? -1 - n : n);
        } else if (value instanceof byte[]) {
            byte[] bytes = (byte[])value; head(out, 2, bytes.length); out.write(bytes, 0, bytes.length);
        } else if (value instanceof String) {
            byte[] bytes = ((String)value).getBytes(StandardCharsets.UTF_8); head(out, 3, bytes.length); out.write(bytes, 0, bytes.length);
        } else if (value instanceof Map) {
            Map<?,?> map = (Map<?,?>)value; head(out, 5, map.size());
            for (Map.Entry<?,?> item : map.entrySet()) { cborInto(out, item.getKey(), depth + 1); cborInto(out, item.getValue(), depth + 1); }
        } else throw new Failure("unsupported_cbor");
    }
}
