package aimasker.core;

import java.util.List;

/**
 * Result of running a detector (or the whole engine) over a piece of text.
 *
 * @param text   the redacted text
 * @param events one entry per replaced value
 */
public record RedactionOutcome(String text, List<RedactionEvent> events) {
    public RedactionOutcome {
        events = List.copyOf(events);
    }

    public static RedactionOutcome unchanged(String text) {
        return new RedactionOutcome(text, List.of());
    }

    public boolean changed() {
        return !events.isEmpty();
    }
}
