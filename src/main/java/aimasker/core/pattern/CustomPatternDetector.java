package aimasker.core.pattern;

import aimasker.core.Detection;
import aimasker.core.Detector;
import aimasker.core.EntityType;
import aimasker.core.RedactionEvent;
import aimasker.core.RedactionOutcome;
import aimasker.core.audit.Fingerprinter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;

/**
 * Redacts values matching user-defined regular expressions. Implemented and tested but not yet
 * exposed in the UI; it plugs into {@link aimasker.core.RedactionEngine} like any detector.
 *
 * <p>Note: user-supplied expressions run on every message; patterns with catastrophic
 * backtracking will slow Burp down.
 */
public final class CustomPatternDetector implements Detector {

    public static final String ID = "custom";

    private final List<CustomPatternRule> rules;

    public CustomPatternDetector(List<CustomPatternRule> rules) {
        this.rules = List.copyOf(rules);
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.CUSTOM;
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> detections = new ArrayList<>();
        for (Span span : findAll(text)) {
            detections.add(new Detection(EntityType.CUSTOM, span.start, span.end));
        }
        return detections;
    }

    @Override
    public RedactionOutcome redact(String text, Fingerprinter fingerprinter) {
        List<Span> spans = findAll(text);
        if (spans.isEmpty()) {
            return RedactionOutcome.unchanged(text);
        }
        StringBuilder out = new StringBuilder(text.length());
        List<RedactionEvent> events = new ArrayList<>();
        int last = 0;
        for (Span span : spans) {
            out.append(text, last, span.start).append(span.rule.replacement());
            events.add(new RedactionEvent(EntityType.CUSTOM,
                    fingerprinter.fingerprint(text.substring(span.start, span.end)),
                    span.rule.replacement(), span.start, "plain"));
            last = span.end;
        }
        out.append(text, last, text.length());
        return new RedactionOutcome(out.toString(), events);
    }

    private List<Span> findAll(String text) {
        List<Span> spans = new ArrayList<>();
        for (CustomPatternRule rule : rules) {
            Matcher matcher = rule.pattern().matcher(text);
            while (matcher.find()) {
                if (matcher.end() > matcher.start()) {
                    spans.add(new Span(matcher.start(), matcher.end(), rule));
                }
            }
        }
        spans.sort(Comparator.comparingInt((Span s) -> s.start)
                .thenComparing(Comparator.comparingInt((Span s) -> s.end).reversed()));
        List<Span> selected = new ArrayList<>();
        int lastEnd = -1;
        for (Span span : spans) {
            if (span.start >= lastEnd) {
                selected.add(span);
                lastEnd = span.end;
            }
        }
        return selected;
    }

    private record Span(int start, int end, CustomPatternRule rule) {
    }
}
