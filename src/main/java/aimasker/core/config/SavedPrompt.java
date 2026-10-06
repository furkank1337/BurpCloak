package aimasker.core.config;

/**
 * A reusable analysis prompt shown in the agent chat panel.
 *
 * @param name short label, e.g. {@code SQLi}
 * @param text the instruction sent to the AI, e.g. "Check for SQL injection in all parameters."
 */
public record SavedPrompt(String name, String text) {

    public SavedPrompt {
        name = name == null ? "" : name.strip();
        text = text == null ? "" : text.strip();
        if (name.isEmpty() || text.isEmpty()) {
            throw new IllegalArgumentException("prompt name and text are required");
        }
        if (name.length() > 64) {
            throw new IllegalArgumentException("prompt name is too long");
        }
        // The name is a one-line label; the text may be multi-line (stored base64-encoded).
        if (name.indexOf('\t') >= 0 || name.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("prompt name may not contain tabs or newlines");
        }
    }
}
