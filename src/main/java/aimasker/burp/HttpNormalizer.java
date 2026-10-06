package aimasker.burp;

import java.nio.charset.StandardCharsets;

/**
 * Makes an AI-written or round-tripped raw request valid on the wire: CRLF line endings, a
 * guaranteed {@code \r\n\r\n} header terminator (missing it hangs strict servers like IIS), and a
 * Content-Length that matches the actual body. Used before replaying and before sending to Repeater.
 */
public final class HttpNormalizer {

    private HttpNormalizer() {
    }

    public static byte[] normalize(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return raw;
        }
        String s = new String(raw, StandardCharsets.ISO_8859_1);
        int sep = s.indexOf("\r\n\r\n");
        int sepLen = 4;
        if (sep < 0) {
            int lf = s.indexOf("\n\n");
            if (lf >= 0) {
                sep = lf;
                sepLen = 2;
            }
        }
        String head = sep < 0 ? s : s.substring(0, sep);
        String body = sep < 0 ? "" : s.substring(sep + sepLen);
        String[] lines = head.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (!body.isEmpty() && line.regionMatches(true, 0, "content-length:", 0, 15)) {
                line = "Content-Length: " + body.length();  // ISO-8859-1: one char == one byte
            }
            if (i > 0) {
                out.append("\r\n");
            }
            out.append(line);
        }
        out.append("\r\n\r\n").append(body);
        return out.toString().getBytes(StandardCharsets.ISO_8859_1);
    }
}
