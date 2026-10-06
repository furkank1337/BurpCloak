package aimasker.core;

/**
 * A span of text that a detector considers sensitive. Deliberately carries only offsets,
 * never the matched value, so detections can be passed around and logged safely.
 *
 * @param type  category of the detected value
 * @param start inclusive start offset in the scanned text
 * @param end   exclusive end offset in the scanned text
 */
public record Detection(EntityType type, int start, int end) {
    public Detection {
        if (start < 0 || end < start) {
            throw new IllegalArgumentException("invalid detection span");
        }
    }
}
