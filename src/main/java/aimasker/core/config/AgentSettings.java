package aimasker.core.config;

/**
 * Settings for the OpenCode-driven agent loop. The AI itself is configured inside OpenCode
 * (provider, model, API key); this tells the extension how to reach the OpenCode server, how far
 * to let the loop run, the system prompt ("rules"), and how results integrate with Burp.
 *
 * @param opencodeUrl         base URL of a running {@code opencode serve}
 * @param opencodeModel       model id, e.g. {@code deepseek/deepseek-chat}
 * @param opencodePassword    HTTP basic-auth password; blank for none
 * @param maxIterations       replay rounds in a single-endpoint session
 * @param rateLimitMs         minimum delay between replayed requests, ms
 * @param rules               custom system prompt; blank means the built-in default
 * @param maxEndpoints        batch: cap on distinct endpoints analysed
 * @param endpointIterations  batch: replay rounds per endpoint during deep testing
 * @param parallelism         batch: how many endpoints to deep-test concurrently
 * @param addToSiteMap        add replayed (real) traffic to Burp's site map
 * @param createIssues        register vulnerable findings as Burp audit issues
 */
public record AgentSettings(
        String opencodeUrl,
        String opencodeModel,
        String opencodePassword,
        int maxIterations,
        int rateLimitMs,
        String rules,
        int maxEndpoints,
        int endpointIterations,
        int parallelism,
        boolean addToSiteMap,
        boolean createIssues) {

    public static final String DEFAULT_URL = "http://127.0.0.1:4096";
    public static final String DEFAULT_MODEL = "deepseek/deepseek-chat";

    public AgentSettings {
        opencodeUrl = opencodeUrl == null || opencodeUrl.isBlank() ? DEFAULT_URL : opencodeUrl.trim();
        while (opencodeUrl.endsWith("/")) {  // avoid "host//session" which some servers reject with 405
            opencodeUrl = opencodeUrl.substring(0, opencodeUrl.length() - 1);
        }
        if (opencodeUrl.isBlank()) {
            opencodeUrl = DEFAULT_URL;
        }
        opencodeModel = opencodeModel == null || opencodeModel.isBlank() ? DEFAULT_MODEL : opencodeModel.trim();
        opencodePassword = opencodePassword == null ? "" : opencodePassword;
        rules = rules == null ? "" : rules;
        if (maxIterations < 1 || maxIterations > 1000) {
            throw new IllegalArgumentException("maxIterations must be between 1 and 1000");
        }
        if (rateLimitMs < 0 || rateLimitMs > 600_000) {
            throw new IllegalArgumentException("rateLimitMs must be between 0 and 600000");
        }
        if (maxEndpoints < 1 || maxEndpoints > 10_000) {
            throw new IllegalArgumentException("maxEndpoints must be between 1 and 10000");
        }
        if (endpointIterations < 1 || endpointIterations > 100) {
            throw new IllegalArgumentException("endpointIterations must be between 1 and 100");
        }
        if (parallelism < 1 || parallelism > 10) {
            throw new IllegalArgumentException("parallelism must be between 1 and 10");
        }
    }

    public static AgentSettings defaults() {
        return new AgentSettings(DEFAULT_URL, DEFAULT_MODEL, "", 12, 750, "", 50, 4, 1, true, true);
    }

    public boolean hasPassword() {
        return !opencodePassword.isBlank();
    }

    public AgentSettings withRules(String value) {
        return new AgentSettings(opencodeUrl, opencodeModel, opencodePassword, maxIterations, rateLimitMs, value,
                maxEndpoints, endpointIterations, parallelism, addToSiteMap, createIssues);
    }

    public AgentSettings withMaxIterations(int value) {
        return new AgentSettings(opencodeUrl, opencodeModel, opencodePassword, value, rateLimitMs, rules,
                maxEndpoints, endpointIterations, parallelism, addToSiteMap, createIssues);
    }
}
