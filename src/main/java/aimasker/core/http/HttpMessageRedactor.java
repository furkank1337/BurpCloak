package aimasker.core.http;

import aimasker.core.RedactionEngine;
import aimasker.core.RedactionEvent;
import aimasker.core.RedactionOutcome;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.IntFunction;
import java.util.regex.Pattern;

/**
 * Turns a raw HTTP/1-style message (as Burp stores it, including HTTP/2 messages) into its
 * redacted form.
 *
 * <p>Steps: split start line, headers and body; undo chunked transfer coding and gzip/deflate
 * content coding so the body is inspectable; replace binary bodies with a placeholder; redact
 * each line and the body with location tracking; fix {@code Content-Length}.
 *
 * <p>Works on ISO-8859-1 strings so every byte maps to exactly one char and nothing is lost.
 * Any part that cannot be inspected is reported in {@link ProcessedMessage#unknownReasons()},
 * which makes the gateway fail closed.
 */
public final class HttpMessageRedactor {

    private static final Pattern CODING_NAME = Pattern.compile("[a-z0-9-]{1,20}");

    private final RedactionEngine engine;
    private final ProcessingOptions options;

    public HttpMessageRedactor(RedactionEngine engine, ProcessingOptions options) {
        this.engine = engine;
        this.options = options;
    }

    public ProcessedMessage process(byte[] raw, MessageKind kind) {
        return process(new String(raw, StandardCharsets.ISO_8859_1), kind);
    }

    public ProcessedMessage process(String raw, MessageKind kind) {
        List<LocatedEvent> events = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        List<String> unknown = new ArrayList<>();

        String newline = raw.contains("\r\n") ? "\r\n" : "\n";
        int separator = raw.indexOf(newline + newline);
        String head = separator >= 0 ? raw.substring(0, separator) : raw;
        String body = separator >= 0 ? raw.substring(separator + 2 * newline.length()) : null;
        List<String> lines = new ArrayList<>(List.of(head.split(newline, -1)));
        String originalBody = body;
        boolean hadContentLength = header(lines, "Content-Length") != null;
        boolean wasChunked = containsIgnoreCase(header(lines, "Transfer-Encoding"), "chunked");

        if (body != null && !body.isEmpty()) {
            body = normalizeBody(lines, body, notes, unknown);
        }
        ContentKind contentKind = body == null ? ContentKind.TEXT : ContentKind.of(header(lines, "Content-Type"), body);
        if (body != null && !body.isEmpty() && unknown.isEmpty()
                && options.omitBinaryBodies() && contentKind == ContentKind.BINARY) {
            body = "[Cloak: binary body omitted, " + body.length() + " bytes]";
            notes.add("binary body omitted");
        }

        if (options.processes(kind) && options.processHeaders()) {
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                boolean startLine = i == 0;
                RedactionOutcome outcome = engine.redact(line);
                if (outcome.changed()) {
                    lines.set(i, outcome.text());
                    String headerLocation = startLine ? null : LocationResolver.header(outcome.text());
                    locate(events, outcome, kind, offset -> startLine
                            ? LocationResolver.startLine(kind, line, offset)
                            : headerLocation);
                }
            }
        }
        if (options.processes(kind) && options.processBodies() && body != null && !body.isEmpty()) {
            String scanned = body;
            RedactionOutcome outcome = engine.redact(scanned);
            if (outcome.changed()) {
                body = outcome.text();
                locate(events, outcome, kind, offset -> LocationResolver.body(contentKind, scanned, offset));
            }
        }

        boolean dechunked = wasChunked && header(lines, "Transfer-Encoding") == null;
        if (body != null && (dechunked || (hadContentLength && !body.equals(originalBody)))) {
            setContentLength(lines, body.length());
        }
        String text = String.join(newline, lines) + (body == null ? "" : newline + newline + body);
        return new ProcessedMessage(text, events, notes, unknown);
    }

    /** Removes transfer and content codings. On failure leaves the body as-is and records why. */
    private static String normalizeBody(List<String> lines, String body, List<String> notes, List<String> unknown) {
        String result = body;
        String transferEncoding = header(lines, "Transfer-Encoding");
        if (containsIgnoreCase(transferEncoding, "chunked")) {
            Optional<String> dechunked = BodyCodecs.dechunk(result);
            if (dechunked.isEmpty()) {
                unknown.add("Chunked body is malformed or too large and cannot be inspected.");
                return body;
            }
            result = dechunked.get();
            removeHeader(lines, "Transfer-Encoding");
            notes.add("chunked body reassembled");
        }
        String contentEncoding = header(lines, "Content-Encoding");
        if (contentEncoding == null) {
            return result;
        }
        String[] codings = contentEncoding.toLowerCase(Locale.ROOT).split(",");
        for (int i = codings.length - 1; i >= 0; i--) {
            String coding = codings[i].trim();
            Optional<String> decoded = switch (coding) {
                case "", "identity" -> Optional.of(result);
                case "gzip", "x-gzip" -> BodyCodecs.gunzip(result);
                case "deflate" -> BodyCodecs.inflate(result);
                default -> Optional.empty();
            };
            if (decoded.isEmpty()) {
                String name = CODING_NAME.matcher(coding).matches() ? " (" + coding + ")" : "";
                unknown.add("Body uses an unsupported or corrupt Content-Encoding" + name + " and cannot be inspected.");
                return body;
            }
            result = decoded.get();
        }
        removeHeader(lines, "Content-Encoding");
        notes.add("body decoded from " + contentEncoding.trim().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9, -]", ""));
        return result;
    }

    private static void locate(List<LocatedEvent> out, RedactionOutcome outcome, MessageKind kind,
                               IntFunction<String> location) {
        for (RedactionEvent event : outcome.events()) {
            String where = location.apply(event.originalStart());
            if (!"plain".equals(event.encoding())) {
                where = where + " (" + event.encoding() + ")";
            }
            out.add(new LocatedEvent(event, kind, where));
        }
    }

    private static boolean containsIgnoreCase(String value, String needle) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(needle);
    }

    private static String header(List<String> lines, String name) {
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i);
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(name)) {
                return line.substring(colon + 1).trim();
            }
        }
        return null;
    }

    private static void removeHeader(List<String> lines, String name) {
        for (int i = lines.size() - 1; i >= 1; i--) {
            String line = lines.get(i);
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(name)) {
                lines.remove(i);
            }
        }
    }

    private static void setContentLength(List<String> lines, int length) {
        removeHeader(lines, "Content-Length");
        int insertAt = lines.size();
        while (insertAt > 1 && lines.get(insertAt - 1).isEmpty()) {
            insertAt--;
        }
        lines.add(insertAt, "Content-Length: " + length);
    }
}
