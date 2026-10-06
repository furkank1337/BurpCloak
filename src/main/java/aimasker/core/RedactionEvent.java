package aimasker.core;

/**
 * One value that was replaced. Contains a keyed fingerprint of the original value, never the
 * value itself.
 *
 * @param type          category of the redacted value
 * @param fingerprint   keyed fingerprint of the original (canonicalised) value
 * @param replacement   the value written in its place (safe to show and log)
 * @param originalStart offset of the original value in the text handed to the detector
 * @param encoding      how the value was embedded, e.g. {@code plain} or {@code base64}
 */
public record RedactionEvent(
        EntityType type,
        String fingerprint,
        String replacement,
        int originalStart,
        String encoding) {
}
