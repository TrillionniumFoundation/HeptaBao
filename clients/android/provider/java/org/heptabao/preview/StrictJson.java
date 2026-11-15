package org.heptabao.preview;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Bounded JSON syntax only. Duplicate keys, floating point, and invalid UTF-8 fail closed. */
final class StrictJson {
    private final String text;
    private int offset;
    private int nodes;

    private StrictJson(String text) { this.text = text; }

    static Object parse(byte[] bytes) throws VaultCrypto.Failure {
        if (bytes.length > VaultCrypto.MAX_FILE_BYTES) throw new VaultCrypto.Failure("input_too_large");
        try {
            String value = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
            StrictJson parser = new StrictJson(value);
            Object result = parser.value(0);
            parser.space();
            if (parser.offset != value.length()) throw bad();
            return result;
        } catch (CharacterCodingException error) { throw bad(); }
    }

    private static VaultCrypto.Failure bad() { return new VaultCrypto.Failure("invalid_format"); }
    private void space() {
        while (offset < text.length()) {
            char c = text.charAt(offset);
            if (c != ' ' && c != '\n' && c != '\r' && c != '\t') break;
            offset++;
        }
    }
    private boolean take(char c) {
        space();
        if (offset < text.length() && text.charAt(offset) == c) { offset++; return true; }
        return false;
    }
    private Object value(int depth) throws VaultCrypto.Failure {
        if (++nodes > 60000 || depth > 16) throw bad();
        space();
        if (offset == text.length()) throw bad();
        char c = text.charAt(offset);
        if (c == '"') return string();
        if (take('{')) {
            Map<String,Object> result = new LinkedHashMap<>();
            if (take('}')) return result;
            do {
                space();
                String key = string();
                if (result.containsKey(key) || !take(':')) throw bad();
                result.put(key, value(depth + 1));
                if (result.size() > 32) throw bad();
                if (take('}')) return result;
            } while (take(','));
            throw bad();
        }
        if (take('[')) {
            List<Object> result = new ArrayList<>();
            if (take(']')) return result;
            do {
                result.add(value(depth + 1));
                if (result.size() > 4096) throw bad();
                if (take(']')) return result;
            } while (take(','));
            throw bad();
        }
        if (text.startsWith("null", offset)) { offset += 4; return null; }
        if (text.startsWith("true", offset)) { offset += 4; return Boolean.TRUE; }
        if (text.startsWith("false", offset)) { offset += 5; return Boolean.FALSE; }
        int start = offset;
        while (offset < text.length() && text.charAt(offset) >= '0' && text.charAt(offset) <= '9') offset++;
        if (offset == start || offset - start > 19 || (offset - start > 1 && text.charAt(start) == '0')) throw bad();
        try { return Long.parseLong(text.substring(start, offset)); }
        catch (NumberFormatException error) { throw bad(); }
    }
    private String string() throws VaultCrypto.Failure {
        if (offset == text.length() || text.charAt(offset++) != '"') throw bad();
        StringBuilder output = new StringBuilder();
        while (offset < text.length()) {
            char c = text.charAt(offset++);
            if (c == '"') {
                for (int i = 0; i < output.length(); i++) {
                    char current = output.charAt(i);
                    if (Character.isHighSurrogate(current)) {
                        if (++i == output.length() || !Character.isLowSurrogate(output.charAt(i))) throw bad();
                    } else if (Character.isLowSurrogate(current)) throw bad();
                }
                return output.toString();
            }
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
                            int digit = hex >= '0' && hex <= '9' ? hex - '0' :
                                hex >= 'a' && hex <= 'f' ? hex - 'a' + 10 :
                                hex >= 'A' && hex <= 'F' ? hex - 'A' + 10 : -1;
                            if (digit < 0) throw bad();
                            code = (code << 4) | digit;
                        }
                        c = (char)code;
                        break;
                    default: throw bad();
                }
            }
            output.append(c);
            if (output.length() > VaultCrypto.MAX_FILE_BYTES) throw bad();
        }
        throw bad();
    }
}
