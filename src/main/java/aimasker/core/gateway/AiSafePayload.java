package aimasker.core.gateway;

import aimasker.core.validation.Verdict;

/**
 * Text that has passed redaction and leakage validation. The constructor is package-private:
 * only {@link AiSafeGateway} can create instances, so any code that accepts an
 * {@code AiSafePayload} (for example the Burp AI client) can only ever receive validated text.
 */
public final class AiSafePayload {

    private final String text;
    private final Verdict verdict;

    AiSafePayload(String text, Verdict verdict) {
        if (!verdict.allowsTransmission()) {
            throw new IllegalStateException("payload cannot be created for verdict " + verdict);
        }
        this.text = text;
        this.verdict = verdict;
    }

    public String text() {
        return text;
    }

    public Verdict verdict() {
        return verdict;
    }

    @Override
    public String toString() {
        return "AiSafePayload[" + verdict + ", " + text.length() + " chars]";
    }
}
