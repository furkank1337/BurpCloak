package aimasker.core.gateway;

import aimasker.core.RedactionEvent;
import aimasker.core.RedactionOutcome;
import aimasker.core.audit.AuditSink;
import aimasker.core.audit.LineageLog;
import aimasker.core.audit.LineageRecord;
import aimasker.core.audit.Statistics;
import aimasker.core.http.HttpMessageRedactor;
import aimasker.core.http.LocatedEvent;
import aimasker.core.http.MessageKind;
import aimasker.core.http.ProcessedMessage;
import aimasker.core.validation.ValidationResult;
import aimasker.core.validation.Verdict;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The single choke point between Burp data and any AI consumer:
 *
 * <pre>
 * RAW HTTP -> LOCAL REDACTION -> LEAKAGE VALIDATION -> AI-SAFE PAYLOAD -> AI
 * </pre>
 *
 * <p>Fail-closed rules implemented here:
 * <ul>
 *   <li>Disabled, or no targets configured: block ({@link Verdict#UNKNOWN}).</li>
 *   <li>Any part that cannot be inspected (unsupported compression, malformed chunking,
 *       internal error): block ({@link Verdict#UNKNOWN}).</li>
 *   <li>Validator finds a sensitive value in the exact outgoing text: block
 *       ({@link Verdict#LEAKAGE}).</li>
 *   <li>Only {@link Verdict#SAFE} and {@link Verdict#REDACTED} produce an {@link AiSafePayload}.</li>
 * </ul>
 */
public final class AiSafeGateway {

    static final String HEADER =
            "[Cloak] Customer identifiers in this HTTP exchange were replaced locally before sharing.";

    private final Supplier<RedactorState> state;
    private final LineageLog lineage;
    private final Statistics statistics;
    private final AuditSink audit;

    public AiSafeGateway(Supplier<RedactorState> state, LineageLog lineage, Statistics statistics, AuditSink audit) {
        this.state = state;
        this.lineage = lineage;
        this.statistics = statistics;
        this.audit = audit;
    }

    /** Prepares an exchange for transmission to an AI; updates statistics, lineage and audit log. */
    public GatewayDecision prepareExchange(HttpExchange exchange) {
        return evaluateExchange(exchange, true, false);
    }

    /**
     * Prepares an exchange for an AI in the requested mode. In reversible mode secrets become
     * encrypted tokens so {@link #unmask} can later restore the real request for replay.
     */
    public GatewayDecision prepareExchange(HttpExchange exchange, boolean reversible) {
        return evaluateExchange(exchange, true, reversible);
    }

    /** Same as {@link #prepareExchange} but without side effects; for local previews. */
    public GatewayDecision previewExchange(HttpExchange exchange) {
        return evaluateExchange(exchange, false, false);
    }

    /**
     * Previews a single pasted message. Messages starting with {@code HTTP/} are treated as
     * responses, everything else as requests.
     */
    public GatewayDecision previewRawMessage(String raw) {
        MessageKind kind = raw.stripLeading().startsWith("HTTP/") ? MessageKind.RESPONSE : MessageKind.REQUEST;
        return previewMessage(raw.stripLeading().getBytes(StandardCharsets.UTF_8), kind);
    }

    /** Previews one raw message without side effects; used by the "AI Safe" editor tab. */
    public GatewayDecision previewMessage(byte[] raw, MessageKind kind) {
        return evaluateMessage(raw, kind, false, false);
    }

    /**
     * Redacts and validates one raw message in the requested mode, recording statistics. Used by
     * the agent loop to mask a replayed response before it is handed back to the AI.
     */
    public GatewayDecision prepareMessage(byte[] raw, MessageKind kind, boolean reversible) {
        return evaluateMessage(raw, kind, true, reversible);
    }

    private GatewayDecision evaluateMessage(byte[] raw, MessageKind kind, boolean record, boolean reversible) {
        RedactorState current = state.get();
        Optional<GatewayDecision> precondition = checkPreconditions(current);
        if (precondition.isPresent()) {
            if (record) {
                statistics.unknownBlocked();
            }
            return precondition.get();
        }
        try {
            ProcessedMessage message = new HttpMessageRedactor(current.engineFor(reversible), current.config().processing())
                    .process(raw, kind);
            String text = truncate(latin1ToUtf8(message.text()), current.config().processing().maxPartChars());
            return decide(current, text, message.events(), message.notes(), message.unknownReasons(), record);
        } catch (RuntimeException e) {
            if (record) {
                statistics.unknownBlocked();
            }
            return internalError(e);
        }
    }

    /** Redacts and validates free text, such as a question typed by the user. */
    public GatewayDecision prepareText(String text) {
        return prepareText(text, false);
    }

    /** Redacts and validates free text in the requested mode. */
    public GatewayDecision prepareText(String text, boolean reversible) {
        RedactorState current = state.get();
        Optional<GatewayDecision> precondition = checkPreconditions(current);
        if (precondition.isPresent()) {
            return precondition.get();
        }
        try {
            RedactionOutcome outcome = current.engineFor(reversible).redact(text);
            List<LocatedEvent> events = new ArrayList<>();
            for (RedactionEvent event : outcome.events()) {
                events.add(new LocatedEvent(event, MessageKind.REQUEST, "prompt text"));
            }
            return decide(current, outcome.text(), events, List.of(), List.of(), true);
        } catch (RuntimeException e) {
            return internalError(e);
        }
    }

    /**
     * Turns an AI-proposed, masked request back into the real request bytes for replay:
     * reverses customer-domain replacements from the configuration, then decrypts every
     * reversible token with the local key. Only ever used inside the agent loop and the result
     * is never shown to the AI.
     *
     * @return the unmasked text as ISO-8859-1 bytes
     */
    public byte[] unmask(String maskedText) {
        RedactorState current = state.get();
        String text = maskedText;
        // Reverse hostname / domain replacements (e.g. api.redacted.com -> api.nday.blog).
        for (var rule : current.config().domainRules()) {
            if (!rule.replacement().equals(rule.target())) {
                text = text.replace(rule.replacement(), rule.target());
            }
        }
        // Decrypt reversible tokens ([COOKIE#...], [AUTH#...], ...) back to their originals.
        if (current.encryptor() != null) {
            text = aimasker.core.secret.Placeholder.unseal(text, current.encryptor());
        }
        return text.getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * Joins already-validated payloads and validates the result again, since two clean parts can
     * form a sensitive value at the seam.
     */
    public GatewayDecision compose(String separator, AiSafePayload... parts) {
        RedactorState current = state.get();
        Optional<GatewayDecision> precondition = checkPreconditions(current);
        if (precondition.isPresent()) {
            return precondition.get();
        }
        StringBuilder joined = new StringBuilder();
        boolean redacted = false;
        for (AiSafePayload part : parts) {
            if (!joined.isEmpty()) {
                joined.append(separator);
            }
            joined.append(part.text());
            redacted |= part.verdict() == Verdict.REDACTED;
        }
        ValidationResult validation = current.validator().validate(joined.toString());
        if (!validation.clean()) {
            return blockedAndCounted(validation.verdict(), validation.reasons(), true);
        }
        Verdict verdict = redacted ? Verdict.REDACTED : Verdict.SAFE;
        String text = joined.toString();
        return new GatewayDecision(verdict, List.of(), List.of(), text, List.of(),
                Optional.of(new AiSafePayload(text, verdict)));
    }

    private GatewayDecision evaluateExchange(HttpExchange exchange, boolean record, boolean reversible) {
        RedactorState current = state.get();
        Optional<GatewayDecision> precondition = checkPreconditions(current);
        if (precondition.isPresent()) {
            if (record) {
                count(exchange);
                statistics.unknownBlocked();
                audit.warn("BLOCKED verdict=UNKNOWN reason=" + precondition.get().reasons());
            }
            return precondition.get();
        }
        if (record) {
            count(exchange);
        }
        try {
            HttpMessageRedactor redactor = new HttpMessageRedactor(current.engineFor(reversible), current.config().processing());
            int maxChars = current.config().processing().maxPartChars();
            List<LocatedEvent> events = new ArrayList<>();
            List<String> notes = new ArrayList<>();
            List<String> unknown = new ArrayList<>();

            RedactionOutcome service = current.engineFor(reversible).redact(exchange.serviceUrl());
            for (RedactionEvent event : service.events()) {
                events.add(new LocatedEvent(event, MessageKind.REQUEST, "service"));
            }
            StringBuilder envelope = new StringBuilder(HEADER).append('\n')
                    .append("Service: ").append(service.text()).append("\n\n=== REQUEST ===\n");

            ProcessedMessage request = redactor.process(exchange.request(), MessageKind.REQUEST);
            append(envelope, request, maxChars, events, notes, unknown, "request");
            if (exchange.response() != null) {
                envelope.append("\n\n=== RESPONSE ===\n");
                ProcessedMessage response = redactor.process(exchange.response(), MessageKind.RESPONSE);
                append(envelope, response, maxChars, events, notes, unknown, "response");
            }
            return decide(current, envelope.toString(), events, notes, unknown, record);
        } catch (RuntimeException e) {
            if (record) {
                statistics.unknownBlocked();
            }
            return internalError(e);
        }
    }

    private static void append(StringBuilder envelope, ProcessedMessage message, int maxChars,
                               List<LocatedEvent> events, List<String> notes, List<String> unknown, String part) {
        envelope.append(truncate(latin1ToUtf8(message.text()), maxChars));
        events.addAll(message.events());
        for (String note : message.notes()) {
            notes.add(part + ": " + note);
        }
        for (String reason : message.unknownReasons()) {
            unknown.add(part + ": " + reason);
        }
    }

    private GatewayDecision decide(RedactorState current, String text, List<LocatedEvent> events,
                                   List<String> notes, List<String> unknown, boolean record) {
        ValidationResult validation = current.validator().validate(text);
        List<String> reasons = new ArrayList<>(validation.reasons());
        Verdict verdict;
        if (validation.verdict() == Verdict.LEAKAGE) {
            verdict = Verdict.LEAKAGE;
            reasons.addAll(unknown);
        } else if (validation.verdict() == Verdict.UNKNOWN || !unknown.isEmpty()) {
            verdict = Verdict.UNKNOWN;
            reasons.addAll(unknown);
        } else {
            verdict = events.isEmpty() ? Verdict.SAFE : Verdict.REDACTED;
        }
        Optional<AiSafePayload> payload = verdict.allowsTransmission()
                ? Optional.of(new AiSafePayload(text, verdict))
                : Optional.empty();
        if (record) {
            recordOutcome(verdict, reasons, events);
        }
        return new GatewayDecision(verdict, reasons, notes, text, events, payload);
    }

    private void recordOutcome(Verdict verdict, List<String> reasons, List<LocatedEvent> events) {
        List<LineageRecord> records = new ArrayList<>(events.size());
        for (LocatedEvent located : events) {
            RedactionEvent event = located.event();
            records.add(lineage.record(event.type(), event.fingerprint(), event.replacement(),
                    located.source().label(), located.location()));
        }
        statistics.valuesRedacted(events.size());
        switch (verdict) {
            case LEAKAGE -> statistics.leakageBlocked();
            case UNKNOWN -> statistics.unknownBlocked();
            default -> statistics.allowed();
        }
        if (state.get().config().verboseAudit()) {
            for (LineageRecord record : records) {
                audit.info(record.type() + " detected entity=" + record.entityId() + " fingerprint="
                        + record.fingerprint() + " location=" + record.location() + " action=REDACTED");
            }
        }
        if (verdict.allowsTransmission()) {
            audit.info("verdict=" + verdict + " values_redacted=" + events.size() + " action=ALLOW");
        } else {
            audit.warn("verdict=" + verdict + " action=BLOCK reasons=" + reasons);
        }
    }

    private GatewayDecision blockedAndCounted(Verdict verdict, List<String> reasons, boolean record) {
        if (record) {
            if (verdict == Verdict.LEAKAGE) {
                statistics.leakageBlocked();
            } else {
                statistics.unknownBlocked();
            }
            audit.warn("verdict=" + verdict + " action=BLOCK reasons=" + reasons);
        }
        return GatewayDecision.blocked(verdict, reasons);
    }

    private static Optional<GatewayDecision> checkPreconditions(RedactorState current) {
        if (current == null) {
            return Optional.of(GatewayDecision.blocked(Verdict.UNKNOWN,
                    List.of("Cloak is not initialised; AI transmission is blocked.")));
        }
        if (!current.config().enabled()) {
            return Optional.of(GatewayDecision.blocked(Verdict.UNKNOWN,
                    List.of("Cloak is disabled; AI transmission is blocked (fail-closed).")));
        }
        if (current.config().domainRules().isEmpty() || !current.engine().hasDetectors()) {
            return Optional.of(GatewayDecision.blocked(Verdict.UNKNOWN,
                    List.of("No target domains are configured; AI transmission is blocked (fail-closed).")));
        }
        return Optional.empty();
    }

    private void count(HttpExchange exchange) {
        statistics.requestScanned();
        if (exchange.response() != null) {
            statistics.responseScanned();
        }
    }

    private GatewayDecision internalError(RuntimeException e) {
        // Only the exception type is logged: messages from lower layers are not guaranteed clean.
        audit.warn("verdict=UNKNOWN action=BLOCK internal_error=" + e.getClass().getSimpleName());
        return GatewayDecision.blocked(Verdict.UNKNOWN,
                List.of("Internal error while redacting (" + e.getClass().getSimpleName() + "); blocking."));
    }

    /** Raw HTTP is handled as Latin-1; the AI receives it decoded as UTF-8 (lossy for binary). */
    static String latin1ToUtf8(String latin1) {
        return new String(latin1.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
    }

    /** Truncation happens after redaction, so a cut can never expose a partial original value. */
    static String truncate(String text, int maxChars) {
        if (text.length() <= maxChars) {
            return text;
        }
        int cut = maxChars;
        if (Character.isHighSurrogate(text.charAt(cut - 1))) {
            cut--;
        }
        return text.substring(0, cut) + "\n[Cloak: truncated " + (text.length() - cut) + " chars]";
    }
}
