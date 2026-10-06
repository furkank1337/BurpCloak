package aimasker.core.validation;

import java.util.Map;

/**
 * Decoders that reveal values an attacker-free but encoding-heavy web page may still carry:
 * percent-encoding, HTML character references and JavaScript/JSON escapes. All decoders are
 * lenient (malformed sequences are kept verbatim) and never throw.
 */
final class TextViews {

    private static final Map<String, Character> NAMED_ENTITIES = Map.of(
            "amp", '&', "lt", '<', "gt", '>', "quot", '"', "apos", '\'',
            "period", '.', "sol", '/', "colon", ':', "commat", '@', "percnt", '%');

    private TextViews() {
    }

    /** Percent-decoding applied repeatedly (catches double encoding such as {@code %252e}). */
    static String urlDecodeFully(String text) {
        String current = text;
        for (int round = 0; round < 3; round++) {
            String next = urlDecodeOnce(current);
            if (next.equals(current)) {
                break;
            }
            current = next;
        }
        return current;
    }

    static String urlDecodeOnce(String text) {
        if (text.indexOf('%') < 0 && text.indexOf('+') < 0) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '%' && i + 2 < text.length() && hex(text.charAt(i + 1)) >= 0 && hex(text.charAt(i + 2)) >= 0) {
                out.append((char) (hex(text.charAt(i + 1)) * 16 + hex(text.charAt(i + 2))));
                i += 2;
            } else if (c == '+') {
                out.append(' ');
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    static String htmlDecode(String text) {
        if (text.indexOf('&') < 0) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length());
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            int semicolon = c == '&' ? text.indexOf(';', i + 1) : -1;
            if (semicolon > i + 1 && semicolon - i <= 12) {
                String ref = text.substring(i + 1, semicolon);
                int decoded = decodeReference(ref);
                if (decoded >= 0) {
                    out.appendCodePoint(decoded);
                    i = semicolon + 1;
                    continue;
                }
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

    private static int decodeReference(String ref) {
        try {
            if (ref.startsWith("#x") || ref.startsWith("#X")) {
                int value = Integer.parseInt(ref.substring(2), 16);
                return Character.isValidCodePoint(value) ? value : -1;
            }
            if (ref.startsWith("#")) {
                int value = Integer.parseInt(ref.substring(1));
                return Character.isValidCodePoint(value) ? value : -1;
            }
        } catch (NumberFormatException e) {
            return -1;
        }
        Character named = NAMED_ENTITIES.get(ref.toLowerCase(java.util.Locale.ROOT));
        return named == null ? -1 : named;
    }

    static String jsUnescape(String text) {
        if (text.indexOf('\\') < 0) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c != '\\' || i + 1 >= text.length()) {
                out.append(c);
                continue;
            }
            char kind = text.charAt(i + 1);
            if ((kind == 'u' || kind == 'U') && i + 5 < text.length() && hexRun(text, i + 2, 4)) {
                out.append((char) Integer.parseInt(text.substring(i + 2, i + 6), 16));
                i += 5;
            } else if ((kind == 'x' || kind == 'X') && i + 3 < text.length() && hexRun(text, i + 2, 2)) {
                out.append((char) Integer.parseInt(text.substring(i + 2, i + 4), 16));
                i += 3;
            } else {
                switch (kind) {
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'b', 'f', 'v', '0' -> out.append(' ');
                    default -> out.append(kind);
                }
                i += 1;
            }
        }
        return out.toString();
    }

    private static boolean hexRun(String text, int from, int count) {
        for (int i = from; i < from + count; i++) {
            if (hex(text.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    private static int hex(char c) {
        return Character.digit(c, 16);
    }
}
