package aimasker.core.http;

import aimasker.core.RedactionEvent;

/**
 * A redaction event plus where in the HTTP message it happened, e.g. {@code header:Referer}
 * or {@code body html script[src]}. Locations are built only from syntax (header names,
 * tag and attribute names, identifier-like JSON keys), never from values.
 */
public record LocatedEvent(RedactionEvent event, MessageKind source, String location) {
}
