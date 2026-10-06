package aimasker.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Minimal JSON reader/writer with no third-party dependency. Objects keep their key order and
 * numbers are kept as their original text so re-serialising does not change them.
 *
 * <p>Used for JWT payloads and for talking to the OpenCode REST API, so the extension stays free
 * of runtime dependencies.
 */
public final class MiniJson {

    /** A JSON number, kept verbatim. */
    public record Num(String text) {
    }

    private final String text;
    private int pos;

    private MiniJson(String text) {
        this.text = text;
    }

    /** Parses a complete JSON document; empty when the input is not valid JSON. */
    public static Optional<Object> parse(String text) {
        try {
            MiniJson parser = new MiniJson(text);
            Object value = parser.value(0);
            parser.skipWhitespace();
            return parser.pos == text.length() ? Optional.ofNullable(value).or(() -> Optional.of(NULL)) : Optional.empty();
        } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            return Optional.empty();
        }
    }

    /** Marker for JSON null (so it survives inside {@link Optional}). */
    public static final Object NULL = new Object() {
        @Override
        public String toString() {
            return "null";
        }
    };

    private Object value(int depth) {
        if (depth > 64) {
            throw new IllegalArgumentException("too deep");
        }
        skipWhitespace();
        char c = text.charAt(pos);
        switch (c) {
            case '{' -> {
                pos++;
                Map<String, Object> object = new LinkedHashMap<>();
                skipWhitespace();
                if (text.charAt(pos) == '}') {
                    pos++;
                    return object;
                }
                while (true) {
                    skipWhitespace();
                    String key = string();
                    skipWhitespace();
                    expect(':');
                    object.put(key, value(depth + 1));
                    skipWhitespace();
                    if (text.charAt(pos) == ',') {
                        pos++;
                    } else {
                        expect('}');
                        return object;
                    }
                }
            }
            case '[' -> {
                pos++;
                List<Object> array = new ArrayList<>();
                skipWhitespace();
                if (text.charAt(pos) == ']') {
                    pos++;
                    return array;
                }
                while (true) {
                    array.add(value(depth + 1));
                    skipWhitespace();
                    if (text.charAt(pos) == ',') {
                        pos++;
                    } else {
                        expect(']');
                        return array;
                    }
                }
            }
            case '"' -> {
                return string();
            }
            default -> {
                if (text.startsWith("true", pos)) {
                    pos += 4;
                    return Boolean.TRUE;
                }
                if (text.startsWith("false", pos)) {
                    pos += 5;
                    return Boolean.FALSE;
                }
                if (text.startsWith("null", pos)) {
                    pos += 4;
                    return NULL;
                }
                int start = pos;
                while (pos < text.length() && "+-0123456789.eE".indexOf(text.charAt(pos)) >= 0) {
                    pos++;
                }
                if (start == pos) {
                    throw new IllegalArgumentException("unexpected character");
                }
                return new Num(text.substring(start, pos));
            }
        }
    }

    private String string() {
        expect('"');
        StringBuilder out = new StringBuilder();
        while (true) {
            char c = text.charAt(pos++);
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char e = text.charAt(pos++);
            switch (e) {
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'u' -> {
                    out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                    pos += 4;
                }
                default -> out.append(e);
            }
        }
    }

    private void expect(char c) {
        if (text.charAt(pos) != c) {
            throw new IllegalArgumentException("expected " + c);
        }
        pos++;
    }

    private void skipWhitespace() {
        while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
            pos++;
        }
    }

    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out);
        return out.toString();
    }

    private static void write(Object value, StringBuilder out) {
        if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(entry.getKey().toString(), out);
                out.append(':');
                write(entry.getValue(), out);
            }
            out.append('}');
        } else if (value instanceof List<?> list) {
            out.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                write(list.get(i), out);
            }
            out.append(']');
        } else if (value instanceof String string) {
            writeString(string, out);
        } else if (value instanceof Num number) {
            out.append(number.text());
        } else {
            out.append(value);
        }
    }

    private static void writeString(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
