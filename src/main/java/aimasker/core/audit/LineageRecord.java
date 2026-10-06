package aimasker.core.audit;

import aimasker.core.EntityType;
import java.time.Instant;

/**
 * Local record of one redaction. Holds a keyed fingerprint instead of the original value.
 *
 * @param entityId    stable per-session pseudonym for the original value, e.g. {@code DOMAIN_001}
 * @param type        category of the value
 * @param fingerprint keyed fingerprint of the original value
 * @param replacement value sent to the AI instead
 * @param source      e.g. {@code HTTP Response}
 * @param location    e.g. {@code body html script[src]}
 * @param timestamp   when the redaction happened
 */
public record LineageRecord(
        String entityId,
        EntityType type,
        String fingerprint,
        String replacement,
        String source,
        String location,
        Instant timestamp) {
}
