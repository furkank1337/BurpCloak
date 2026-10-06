package aimasker.core;

import aimasker.core.audit.Fingerprinter;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs every configured {@link Detector} over a piece of text, then looks inside base64
 * tokens (JWTs, Basic credentials, encoded parameters) and redacts values hidden there too.
 *
 * <p>Immutable and thread-safe. Contains no I/O.
 */
public final class RedactionEngine {

    /** How many layers of base64-inside-base64 are unwrapped. */
    private static final int MAX_ENCODING_DEPTH = 2;

    private final List<Detector> detectors;
    private final Fingerprinter fingerprinter;

    public RedactionEngine(List<Detector> detectors, Fingerprinter fingerprinter) {
        this.detectors = List.copyOf(detectors);
        this.fingerprinter = fingerprinter;
    }

    public boolean hasDetectors() {
        return !detectors.isEmpty();
    }

    public Fingerprinter fingerprinter() {
        return fingerprinter;
    }

    /** Union of all detectors' findings on {@code text} as-is (no decoding). */
    public List<Detection> detect(String text) {
        List<Detection> all = new ArrayList<>();
        for (Detector detector : detectors) {
            all.addAll(detector.detect(text));
        }
        return all;
    }

    public RedactionOutcome redact(String text) {
        return redact(text, MAX_ENCODING_DEPTH);
    }

    private RedactionOutcome redact(String text, int depth) {
        String current = text;
        List<RedactionEvent> events = new ArrayList<>();
        for (Detector detector : detectors) {
            RedactionOutcome outcome = detector.redact(current, fingerprinter);
            current = outcome.text();
            events.addAll(outcome.events());
        }
        if (depth > 0) {
            RedactionOutcome encoded = redactInsideBase64(current, depth);
            current = encoded.text();
            events.addAll(encoded.events());
        }
        return new RedactionOutcome(current, events);
    }

    private RedactionOutcome redactInsideBase64(String text, int depth) {
        List<Base64Tokens.Token> tokens = Base64Tokens.find(text);
        StringBuilder out = null;
        List<RedactionEvent> events = new ArrayList<>();
        int last = 0;
        for (Base64Tokens.Token token : tokens) {
            if (token.start() < last || !containsSensitive(token.decoded(), depth)) {
                continue;
            }
            RedactionOutcome inner = redact(token.decoded(), depth - 1);
            if (out == null) {
                out = new StringBuilder(text.length());
            }
            out.append(text, last, token.start());
            out.append(Base64Tokens.encodeLike(text.substring(token.start(), token.end()), inner.text()));
            for (RedactionEvent event : inner.events()) {
                events.add(new RedactionEvent(event.type(), event.fingerprint(), event.replacement(),
                        token.start(), "base64(" + event.encoding() + ")"));
            }
            last = token.end();
        }
        if (out == null) {
            return RedactionOutcome.unchanged(text);
        }
        out.append(text, last, text.length());
        return new RedactionOutcome(out.toString(), events);
    }

    private boolean containsSensitive(String decoded, int depth) {
        if (!detect(decoded).isEmpty()) {
            return true;
        }
        if (depth <= 1) {
            return false;
        }
        for (Base64Tokens.Token nested : Base64Tokens.find(decoded)) {
            if (!detect(nested.decoded()).isEmpty()) {
                return true;
            }
        }
        return false;
    }
}
