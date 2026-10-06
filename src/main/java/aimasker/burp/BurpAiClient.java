package aimasker.burp;

import aimasker.core.gateway.AiSafePayload;
import burp.api.montoya.ai.Ai;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.PromptOptions;

/**
 * Sends prompts to Burp AI through the Montoya {@code Ai} API.
 *
 * <p>Accepts only {@link AiSafePayload}, which can only be produced by the gateway after
 * redaction and validation, so un-redacted data cannot reach this method by construction.
 */
final class BurpAiClient {

    /** Constant text; contains no customer data. */
    static final String SYSTEM_PROMPT = String.join("\n",
            "You are assisting an authorised penetration tester.",
            "Customer identifiers in the material below were replaced locally before it was shared with you.",
            "Hostnames such as *.redacted.com or tokens such as [REDACTED_DOMAIN] are pseudonyms:",
            "do not try to resolve, visit or de-anonymise them, and keep using them as-is in your answer.",
            "Some bodies may be truncated or omitted; say so when it limits your analysis.");

    private final Ai ai;

    BurpAiClient(Ai ai) {
        this.ai = ai;
    }

    boolean isAvailable() {
        return ai.isEnabled();
    }

    /**
     * Blocking call; never invoke on the Swing event thread.
     *
     * @throws IllegalStateException when Burp AI is not enabled for this extension
     * @throws burp.api.montoya.ai.chat.PromptException when the prompt fails
     */
    String ask(AiSafePayload prompt) {
        if (!ai.isEnabled()) {
            throw new IllegalStateException("Burp AI is not available to this extension. Enable AI in Burp "
                    + "and tick 'Use AI' for Cloak under Extensions > Installed.");
        }
        return ai.prompt().execute(
                PromptOptions.promptOptions().withTemperature(0.2),
                Message.systemMessage(SYSTEM_PROMPT),
                Message.userMessage(prompt.text())).content();
    }
}
