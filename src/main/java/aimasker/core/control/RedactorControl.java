package aimasker.core.control;

/**
 * Control surface for the redactor, shaped for a future MCP (or other agent-facing) layer.
 *
 * <p>This interface controls the redaction engine; it is not the engine and never exposes
 * customer data. In particular {@link #getStatus()} reports replacements, counts and
 * fingerprints, never target domains, because its caller may be an AI agent.
 *
 * <p>Intended tool mapping: {@code enable_redaction}, {@code disable_redaction},
 * {@code add_domain}, {@code remove_domain}, {@code get_status}.
 */
public interface RedactorControl {

    void enableRedaction();

    void disableRedaction();

    /**
     * @param target      domain to redact (normalised: scheme, port, path and wildcards removed)
     * @param replacement replacement, or {@code null} for the default
     * @throws IllegalArgumentException for invalid input; the message never echoes the input
     */
    void addDomain(String target, String replacement);

    /** @return {@code true} if a rule was removed */
    boolean removeDomain(String target);

    RedactorStatus getStatus();
}
