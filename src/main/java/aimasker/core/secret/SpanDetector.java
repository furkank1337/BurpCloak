package aimasker.core.secret;

import aimasker.core.Detection;
import aimasker.core.Detector;
import aimasker.core.EntityType;
import aimasker.core.RedactionEvent;
import aimasker.core.RedactionOutcome;
import aimasker.core.audit.Fingerprinter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Base class for detectors that find value spans and replace each one with a placeholder.
 * Subclasses only locate spans; {@link #detect} and {@link #redact} share that logic, which
 * keeps the detector contract (detect finds what redact replaces) true by construction.
 *
 * <p>Subclasses must not return spans whose text is already a {@link Placeholder}, so that
 * redacted output is clean when scanned again.
 */
abstract class SpanDetector implements Detector {

    /** A value to replace. */
    record Span(int start, int end, EntityType type, String kind) {
    }

    /** All candidate spans; may overlap, they are resolved here. */
    abstract List<Span> spans(String text);

    /** Replacement for a span; subclasses with structured output (JWTs) override this. */
    String replacement(String value, Span span, Fingerprinter fingerprinter) {
        return Placeholder.of(span.kind(), value, fingerprinter);
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> detections = new ArrayList<>();
        for (Span span : resolved(text)) {
            detections.add(new Detection(span.type(), span.start(), span.end()));
        }
        return detections;
    }

    @Override
    public RedactionOutcome redact(String text, Fingerprinter fingerprinter) {
        List<Span> spans = resolved(text);
        if (spans.isEmpty()) {
            return RedactionOutcome.unchanged(text);
        }
        StringBuilder out = new StringBuilder(text.length());
        List<RedactionEvent> events = new ArrayList<>(spans.size());
        int last = 0;
        for (Span span : spans) {
            String value = text.substring(span.start(), span.end());
            String replacement = replacement(value, span, fingerprinter);
            out.append(text, last, span.start()).append(replacement);
            events.add(new RedactionEvent(span.type(), fingerprinter.fingerprintExact(value), replacement,
                    span.start(), "plain"));
            last = span.end();
        }
        out.append(text, last, text.length());
        return new RedactionOutcome(out.toString(), events);
    }

    private List<Span> resolved(String text) {
        List<Span> spans = new ArrayList<>(spans(text));
        spans.removeIf(span -> span.end() <= span.start()
                || Placeholder.is(text.substring(span.start(), span.end())));
        if (spans.size() < 2) {
            return spans;
        }
        spans.sort(Comparator.comparingInt(Span::start)
                .thenComparing(Comparator.comparingInt(Span::end).reversed()));
        List<Span> selected = new ArrayList<>(spans.size());
        int lastEnd = -1;
        for (Span span : spans) {
            if (span.start() >= lastEnd) {
                selected.add(span);
                lastEnd = span.end();
            }
        }
        return selected;
    }
}
