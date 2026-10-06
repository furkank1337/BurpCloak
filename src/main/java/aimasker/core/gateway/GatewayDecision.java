package aimasker.core.gateway;

import aimasker.core.http.LocatedEvent;
import aimasker.core.validation.Verdict;
import java.util.List;
import java.util.Optional;

/**
 * Outcome of preparing content for an AI.
 *
 * @param verdict      overall verdict
 * @param reasons      why the content was blocked (empty when allowed); contain no customer data
 * @param notes        transformations applied, e.g. "body decoded from gzip"
 * @param localPreview redacted text for display inside Burp only, also when blocked; it may
 *                     still contain leaked values and must never be sent anywhere
 * @param events       redacted values with locations
 * @param payload      present if and only if the verdict allows transmission
 */
public record GatewayDecision(
        Verdict verdict,
        List<String> reasons,
        List<String> notes,
        String localPreview,
        List<LocatedEvent> events,
        Optional<AiSafePayload> payload) {

    public GatewayDecision {
        reasons = List.copyOf(reasons);
        notes = List.copyOf(notes);
        events = List.copyOf(events);
        if (payload.isPresent() != verdict.allowsTransmission()) {
            throw new IllegalStateException("payload presence must match verdict");
        }
    }

    public boolean allowed() {
        return payload.isPresent();
    }

    static GatewayDecision blocked(Verdict verdict, List<String> reasons) {
        return new GatewayDecision(verdict, reasons, List.of(), "", List.of(), Optional.empty());
    }
}
