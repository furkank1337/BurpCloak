package aimasker.core.http;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Describes where in a message a value was found, using only syntactic names. Names are
 * restricted to identifier characters (no dots), so they cannot contain a domain.
 */
final class LocationResolver {

    private static final int LOOKBEHIND = 400;
    /** Bound for the inline-script/style search so large pages stay linear. */
    private static final int BLOCK_LOOKBEHIND = 64 * 1024;
    private static final Pattern TAG_OPEN = Pattern.compile("<([A-Za-z][A-Za-z0-9-]{0,30})\\b[^<>]*$");
    private static final Pattern ATTRIBUTE = Pattern.compile("([A-Za-z_:][A-Za-z0-9_:-]{0,40})\\s*=\\s*[\"']?[^\"'<>]*$");
    private static final Pattern JSON_KEY = Pattern.compile("\"([A-Za-z_$][A-Za-z0-9_$-]{0,40})\"\\s*:\\s*\\[?\\s*\"[^\"]*$");
    private static final Pattern XML_ELEMENT = Pattern.compile("<([A-Za-z_][A-Za-z0-9_:-]{0,40})[^<>]*>[^<]*$");
    private static final Pattern FORM_PARAM = Pattern.compile("(?:^|&)([A-Za-z0-9_\\[\\]-]{1,40})=[^&]*$");
    private static final Pattern HEADER_NAME = Pattern.compile("[A-Za-z0-9-]{1,64}");

    private LocationResolver() {
    }

    static String startLine(MessageKind kind, String line, int offset) {
        if (kind == MessageKind.RESPONSE) {
            return "status-line";
        }
        int query = line.indexOf('?');
        return query >= 0 && offset > query ? "request-line query" : "request-line";
    }

    static String header(String redactedLine) {
        int colon = redactedLine.indexOf(':');
        String name = colon > 0 ? redactedLine.substring(0, colon).trim() : "";
        return HEADER_NAME.matcher(name).matches() ? "header:" + name : "header";
    }

    static String body(ContentKind kind, String body, int offset) {
        String before = body.substring(Math.max(0, offset - LOOKBEHIND), Math.min(offset, body.length()));
        String detail = switch (kind) {
            case HTML -> html(body, offset, before);
            case XML -> group(XML_ELEMENT, before).map(e -> "<" + e + ">").orElse("");
            case JSON -> group(JSON_KEY, before).map(k -> "key \"" + k + "\"").orElse("");
            case FORM -> group(FORM_PARAM, before).map(p -> "param " + p).orElse("");
            default -> "";
        };
        return detail.isEmpty() ? "body " + kind.label() : "body " + kind.label() + " " + detail;
    }

    private static String html(String body, int offset, String before) {
        Matcher tag = TAG_OPEN.matcher(before);
        if (tag.find()) {
            String name = tag.group(1).toLowerCase(Locale.ROOT);
            String attribute = group(ATTRIBUTE, before.substring(tag.start())).orElse(null);
            return attribute == null ? name : name + "[" + attribute.toLowerCase(Locale.ROOT) + "]";
        }
        if (lastIndexOfIgnoreCase(body, "<script", offset) > lastIndexOfIgnoreCase(body, "</script", offset)) {
            return "inline-script";
        }
        if (lastIndexOfIgnoreCase(body, "<style", offset) > lastIndexOfIgnoreCase(body, "</style", offset)) {
            return "inline-style";
        }
        return "text";
    }

    private static int lastIndexOfIgnoreCase(String text, String needle, int before) {
        int floor = Math.max(0, before - BLOCK_LOOKBEHIND);
        for (int i = Math.min(before, text.length()) - needle.length(); i >= floor; i--) {
            if (text.regionMatches(true, i, needle, 0, needle.length())) {
                return i;
            }
        }
        return -1;
    }

    private static java.util.Optional<String> group(Pattern pattern, String text) {
        Matcher matcher = pattern.matcher(text);
        return matcher.find() ? java.util.Optional.of(matcher.group(1)) : java.util.Optional.empty();
    }
}
