package aimasker.core.http;

import java.util.List;

/**
 * An HTTP message after normalisation and redaction.
 *
 * @param text           the message as an ISO-8859-1 string (one char per byte)
 * @param events         every replaced value with its location
 * @param notes          transformations applied, e.g. "body decoded from gzip"
 * @param unknownReasons why parts could not be inspected; non-empty means fail closed
 */
public record ProcessedMessage(String text, List<LocatedEvent> events, List<String> notes, List<String> unknownReasons) {
    public ProcessedMessage {
        events = List.copyOf(events);
        notes = List.copyOf(notes);
        unknownReasons = List.copyOf(unknownReasons);
    }
}
