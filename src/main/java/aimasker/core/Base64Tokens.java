package aimasker.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds base64 / base64url tokens (JWT segments, Basic auth, encoded redirect parameters) so
 * sensitive values hidden inside them can be inspected. Decoded bytes are returned as an
 * ISO-8859-1 string, matching how this project represents raw HTTP bytes.
 */
public final class Base64Tokens {

    /** Minimum token length; shorter runs are mostly ordinary words. */
    public static final int MIN_LENGTH = 16;
    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9+/_-]{" + MIN_LENGTH + ",}={0,2}");

    private Base64Tokens() {
    }

    /** A candidate token: its span in the scanned text and the text it decodes to. */
    public record Token(int start, int end, String decoded) {
    }

    /**
     * Returns every decodable token. A run containing {@code /} (for example a URL path) is
     * also split into its segments, because the payload is often one path segment.
     */
    public static List<Token> find(String text) {
        List<Token> tokens = new ArrayList<>();
        Matcher matcher = TOKEN.matcher(text);
        while (matcher.find()) {
            int start = matcher.start();
            int end = matcher.end();
            decode(text.substring(start, end)).ifPresentOrElse(
                    decoded -> tokens.add(new Token(start, end, decoded)),
                    () -> addSegments(text, start, end, tokens));
        }
        return tokens;
    }

    private static void addSegments(String text, int start, int end, List<Token> tokens) {
        int segmentStart = start;
        for (int i = start; i <= end; i++) {
            if (i == end || text.charAt(i) == '/') {
                if (i - segmentStart >= MIN_LENGTH && !(segmentStart == start && i == end)) {
                    int from = segmentStart;
                    int to = i;
                    decode(text.substring(from, to)).ifPresent(decoded -> tokens.add(new Token(from, to, decoded)));
                }
                segmentStart = i + 1;
            }
        }
    }

    /** Decodes standard or URL-safe base64, with or without padding. */
    public static Optional<String> decode(String token) {
        String body = stripPadding(token);
        boolean urlAlphabet = body.indexOf('-') >= 0 || body.indexOf('_') >= 0;
        boolean stdAlphabet = body.indexOf('+') >= 0 || body.indexOf('/') >= 0;
        if ((urlAlphabet && stdAlphabet) || body.length() % 4 == 1 || body.isEmpty()) {
            return Optional.empty();
        }
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(body.replace('+', '-').replace('/', '_'));
            return Optional.of(new String(bytes, StandardCharsets.ISO_8859_1));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** Re-encodes {@code decoded} using the same alphabet and padding style as {@code original}. */
    public static String encodeLike(String original, String decoded) {
        byte[] bytes = decoded.getBytes(StandardCharsets.ISO_8859_1);
        boolean padded = original.endsWith("=");
        boolean url = original.indexOf('-') >= 0 || original.indexOf('_') >= 0
                || (original.indexOf('+') < 0 && original.indexOf('/') < 0 && !padded);
        Base64.Encoder encoder = url ? Base64.getUrlEncoder() : Base64.getEncoder();
        if (!padded) {
            encoder = encoder.withoutPadding();
        }
        return encoder.encodeToString(bytes);
    }

    private static String stripPadding(String token) {
        int end = token.length();
        while (end > 0 && token.charAt(end - 1) == '=') {
            end--;
        }
        return token.substring(0, end);
    }
}
