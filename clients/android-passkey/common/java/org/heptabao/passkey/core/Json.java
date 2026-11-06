package org.heptabao.passkey.core;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Bounded, duplicate-rejecting UTF-8 JSON. Integers only; no arbitrary Java serialization. */
public final class Json {
    public static final int MAX_BYTES = 8 * 1024 * 1024;
    private final String text;
    private int offset;
    private int nodes;
    private Json(String text) { this.text = text; }
    private static Failure bad() { return new Failure("invalid_json"); }
    public static Object parse(byte[] bytes) throws Failure {
        if (bytes.length > MAX_BYTES) throw new Failure("input_limit");
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            Json parser = new Json(text);
            Object value = parser.value(0); parser.space();
            if (parser.offset != text.length()) throw bad();
            return value;
        } catch (CharacterCodingException error) { throw bad(); }
    }
    public static Map<String,Object> parseObject(String value, int maximum) throws Failure {
        if (value == null || value.length() > maximum) throw new Failure("input_limit");
        ByteBuffer encoded = null; byte[] bytes = null;
        try {
            encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));
            if (encoded.remaining() > maximum) throw new Failure("input_limit");
            bytes = new byte[encoded.remaining()]; encoded.get(bytes); return object(parse(bytes));
        } catch (CharacterCodingException error) { throw bad(); }
        finally {
            if (bytes != null) Arrays.fill(bytes, (byte)0);
            if (encoded != null && encoded.hasArray()) Arrays.fill(encoded.array(), (byte)0);
        }
    }
    private void space() {
        while (offset < text.length() && " \n\r\t".indexOf(text.charAt(offset)) >= 0) offset++;
    }
    private boolean take(char expected) {
        space();
        if (offset < text.length() && text.charAt(offset) == expected) { offset++; return true; }
        return false;
    }
    private Object value(int depth) throws Failure {
        if (++nodes > 60000 || depth > 16) throw bad();
        space(); if (offset == text.length()) throw bad();
        if (text.charAt(offset) == '"') return stringValue();
        if (take('{')) {
            Map<String,Object> map = new LinkedHashMap<>();
            if (take('}')) return map;
            do {
                space(); String key = stringValue();
                if (map.containsKey(key) || !take(':')) throw bad();
                map.put(key, value(depth + 1));
                if (map.size() > 64) throw bad();
                if (take('}')) return map;
            } while (take(','));
            throw bad();
        }
        if (take('[')) {
            List<Object> list = new ArrayList<>();
            if (take(']')) return list;
            do {
                list.add(value(depth + 1));
                if (list.size() > 4096) throw bad();
                if (take(']')) return list;
            } while (take(','));
            throw bad();
        }
        if (text.startsWith("null", offset)) { offset += 4; return null; }
        if (text.startsWith("true", offset)) { offset += 4; return Boolean.TRUE; }
        if (text.startsWith("false", offset)) { offset += 5; return Boolean.FALSE; }
        int start = offset;
        if (text.charAt(offset) == '-') offset++;
        int digits = offset;
        while (offset < text.length() && text.charAt(offset) >= '0' && text.charAt(offset) <= '9') offset++;
        if (offset == digits || offset - digits > 19 || (offset - digits > 1 && text.charAt(digits) == '0')) throw bad();
        try { return Long.parseLong(text.substring(start, offset)); }
        catch (NumberFormatException error) { throw bad(); }
    }
    private String stringValue() throws Failure {
        if (offset == text.length() || text.charAt(offset++) != '"') throw bad();
        StringBuilder out = new StringBuilder();
        while (offset < text.length()) {
            char c = text.charAt(offset++);
            if (c == '"') { validSurrogates(out); return out.toString(); }
            if (c < 32) throw bad();
            if (c == '\\') {
                if (offset == text.length()) throw bad();
                c = text.charAt(offset++);
                switch (c) {
                    case '"': case '\\': case '/': break;
                    case 'b': c = '\b'; break;
                    case 'f': c = '\f'; break;
                    case 'n': c = '\n'; break;
                    case 'r': c = '\r'; break;
                    case 't': c = '\t'; break;
                    case 'u':
                        if (offset + 4 > text.length()) throw bad();
                        int code = 0;
                        for (int i = 0; i < 4; i++) {
                            char hex = text.charAt(offset++);
                            int n = hex >= '0' && hex <= '9' ? hex - '0' : hex >= 'a' && hex <= 'f' ? hex - 'a' + 10 : hex >= 'A' && hex <= 'F' ? hex - 'A' + 10 : -1;
                            if (n < 0) throw bad(); code = (code << 4) | n;
                        }
                        c = (char)code; break;
                    default: throw bad();
                }
            }
            out.append(c);
        }
        throw bad();
    }
    private static void validSurrogates(CharSequence value) throws Failure {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i == value.length() || !Character.isLowSurrogate(value.charAt(i))) throw bad();
            } else if (Character.isLowSurrogate(c)) throw bad();
        }
    }
    public static byte[] bytes(Object value) throws Failure { return write(value).getBytes(StandardCharsets.UTF_8); }
    public static String write(Object value) throws Failure {
        StringBuilder out = new StringBuilder(); append(out, value, 0);
        if (out.length() > MAX_BYTES) throw new Failure("output_limit");
        return out.toString();
    }
    private static void append(StringBuilder out, Object value, int depth) throws Failure {
        if (depth > 16 || out.length() > MAX_BYTES) throw new Failure("output_limit");
        if (value == null) out.append("null");
        else if (value instanceof String) {
            String text = (String)value; validSurrogates(text); out.append('"');
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                switch (c) {
                    case '"': out.append("\\\""); break;
                    case '\\': out.append("\\\\"); break;
                    case '\b': out.append("\\b"); break;
                    case '\f': out.append("\\f"); break;
                    case '\n': out.append("\\n"); break;
                    case '\r': out.append("\\r"); break;
                    case '\t': out.append("\\t"); break;
                    default:
                        if (c < 32) out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int)c));
                        else out.append(c);
                }
            }
            out.append('"');
        } else if (value instanceof Boolean || value instanceof Long || value instanceof Integer) out.append(value);
        else if (value instanceof List) {
            out.append('['); boolean comma = false;
            for (Object item : (List<?>)value) { if (comma) out.append(','); append(out, item, depth + 1); comma = true; }
            out.append(']');
        } else if (value instanceof Map) {
            out.append('{'); boolean comma = false;
            for (Map.Entry<?,?> item : ((Map<?,?>)value).entrySet()) {
                if (!(item.getKey() instanceof String)) throw bad();
                if (comma) out.append(','); append(out, item.getKey(), depth + 1); out.append(':'); append(out, item.getValue(), depth + 1); comma = true;
            }
            out.append('}');
        } else throw bad();
    }
    public static Map<String,Object> map(Object... pairs) {
        if (pairs.length % 2 != 0) throw new IllegalArgumentException("pairs");
        Map<String,Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String)pairs[i], pairs[i + 1]);
        return result;
    }
    @SuppressWarnings("unchecked") public static Map<String,Object> object(Object value) throws Failure {
        if (!(value instanceof Map)) throw bad(); return (Map<String,Object>)value;
    }
    @SuppressWarnings("unchecked") public static List<Object> list(Object value) throws Failure {
        if (!(value instanceof List)) throw bad(); return (List<Object>)value;
    }
    public static String string(Object value) throws Failure { if (!(value instanceof String)) throw bad(); return (String)value; }
    public static long integer(Object value) throws Failure { if (!(value instanceof Long) && !(value instanceof Integer)) throw bad(); return ((Number)value).longValue(); }
    public static boolean bool(Object value) throws Failure { if (!(value instanceof Boolean)) throw bad(); return (Boolean)value; }
    public static void keys(Map<String,Object> value, String... names) throws Failure {
        if (!value.keySet().equals(new HashSet<>(Arrays.asList(names)))) throw bad();
    }
    public static void allowed(Map<String,Object> value, String... names) throws Failure {
        if (!new HashSet<>(Arrays.asList(names)).containsAll(value.keySet())) throw bad();
    }
}
