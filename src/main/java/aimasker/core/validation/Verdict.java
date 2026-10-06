package aimasker.core.validation;

/**
 * Outcome of preparing a message for an AI. Only {@link #SAFE} and {@link #REDACTED} permit
 * transmission; everything else fails closed.
 */
public enum Verdict {
    /** No sensitive value was present. */
    SAFE(true),
    /** Sensitive values were replaced and the validator confirmed none remain. */
    REDACTED(true),
    /** The message could not be fully inspected (unsupported encoding, error, disabled). */
    UNKNOWN(false),
    /** A sensitive value is still present after redaction. */
    LEAKAGE(false);

    private final boolean allowsTransmission;

    Verdict(boolean allowsTransmission) {
        this.allowsTransmission = allowsTransmission;
    }

    public boolean allowsTransmission() {
        return allowsTransmission;
    }
}
