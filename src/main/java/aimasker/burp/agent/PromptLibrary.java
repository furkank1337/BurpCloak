package aimasker.burp.agent;

import aimasker.core.config.SavedPrompt;
import java.util.ArrayList;
import java.util.List;

/** Built-in analysis prompts, merged with the user's saved prompts for the chat panel. */
public final class PromptLibrary {

    private static final List<SavedPrompt> DEFAULTS = List.of(
            new SavedPrompt("SQL injection",
                    "Check this request for SQL injection. Inject safe, non-destructive probes into each "
                    + "parameter, compare responses and timing, and avoid stacked or destructive queries."),
            new SavedPrompt("Reflected XSS",
                    "Check this request for reflected XSS. Try context-appropriate markers in each parameter "
                    + "and look for them reflected unescaped in the response."),
            new SavedPrompt("Authentication bypass",
                    "Check whether this endpoint can be accessed without valid authentication: try removing or "
                    + "altering auth headers/cookies and observe the response."),
            new SavedPrompt("IDOR",
                    "Check for IDOR / broken object-level authorization: vary identifiers in the request and see "
                    + "whether other objects become accessible."),
            new SavedPrompt("SSRF",
                    "Check whether any parameter that takes a URL or host can be pointed elsewhere, indicating a "
                    + "possible SSRF. Do not target anything outside the authorized scope."));

    private PromptLibrary() {
    }

    public static List<SavedPrompt> defaults() {
        return DEFAULTS;
    }

    /** Built-in prompts first, then the user's saved ones. */
    public static List<SavedPrompt> merged(List<SavedPrompt> saved) {
        List<SavedPrompt> all = new ArrayList<>(DEFAULTS);
        all.addAll(saved);
        return all;
    }
}
