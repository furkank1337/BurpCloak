package aimasker.core.config;

import aimasker.core.domain.DomainRule;
import aimasker.core.http.ProcessingOptions;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Plain-text, line-based serialisation of {@link RedactorConfig}. No third-party parser is
 * needed, which keeps the extension free of runtime dependencies.
 *
 * <pre>
 * version=1
 * enabled=true
 * domain=nday.blog\tredacted.com\tN-Day Security,NDay Labs
 * customField=internalRef
 * opencodeUrl=http://127.0.0.1:4096
 * prompt=SQLi\tCheck for SQL injection in all parameters.
 * </pre>
 *
 * <p>Multi-valued keys ({@code domain}, {@code customField}, {@code prompt}) may repeat; all
 * other keys appear at most once. Unknown single-value keys are rejected so a corrupt file falls
 * back to the blocking default rather than being silently half-applied.
 */
public final class ConfigCodec {

    public static final int VERSION = 1;

    private ConfigCodec() {
    }

    public static String encode(RedactorConfig config) {
        ProcessingOptions p = config.processing();
        AgentSettings a = config.agent();
        StringBuilder out = new StringBuilder();
        out.append("# Cloak configuration\n");
        out.append("version=").append(VERSION).append('\n');
        out.append("enabled=").append(config.enabled()).append('\n');
        out.append("keepSubdomainLabels=").append(config.keepSubdomainLabels()).append('\n');
        out.append("autoBrandKeywords=").append(config.autoBrandKeywords()).append('\n');
        out.append("maskSecrets=").append(config.masking().secrets()).append('\n');
        out.append("maskPersonalData=").append(config.masking().personalData()).append('\n');
        out.append("maskIpAddresses=").append(config.masking().ipAddresses()).append('\n');
        out.append("processRequests=").append(p.processRequests()).append('\n');
        out.append("processResponses=").append(p.processResponses()).append('\n');
        out.append("processHeaders=").append(p.processHeaders()).append('\n');
        out.append("processBodies=").append(p.processBodies()).append('\n');
        out.append("omitBinaryBodies=").append(p.omitBinaryBodies()).append('\n');
        out.append("maxPartChars=").append(p.maxPartChars()).append('\n');
        out.append("verboseAudit=").append(config.verboseAudit()).append('\n');
        out.append("opencodeUrl=").append(a.opencodeUrl()).append('\n');
        out.append("opencodeModel=").append(a.opencodeModel()).append('\n');
        out.append("opencodePassword=").append(encodeBlob(a.opencodePassword())).append('\n');
        out.append("agentMaxIterations=").append(a.maxIterations()).append('\n');
        out.append("agentRateLimitMs=").append(a.rateLimitMs()).append('\n');
        out.append("agentMaxEndpoints=").append(a.maxEndpoints()).append('\n');
        out.append("agentEndpointIterations=").append(a.endpointIterations()).append('\n');
        out.append("agentParallelism=").append(a.parallelism()).append('\n');
        out.append("agentAddToSiteMap=").append(a.addToSiteMap()).append('\n');
        out.append("agentCreateIssues=").append(a.createIssues()).append('\n');
        out.append("agentRules=").append(encodeBlob(a.rules())).append('\n');
        for (DomainRule rule : config.domainRules()) {
            out.append("domain=").append(rule.target()).append('\t').append(rule.replacement());
            if (!rule.keywords().isEmpty()) {
                out.append('\t').append(String.join(",", rule.keywords()));
            }
            out.append('\n');
        }
        for (String name : config.customFieldNames()) {
            out.append("customField=").append(name).append('\n');
        }
        for (SavedPrompt prompt : config.prompts()) {
            // base64 so a multi-line prompt text can't break the line-based format.
            out.append("prompt=b64\t").append(encodeBlob(prompt.name()))
                    .append('\t').append(encodeBlob(prompt.text())).append('\n');
        }
        return out.toString();
    }

    /**
     * @throws ConfigException on any malformed or unknown content; callers must then fall back
     *                         to a blocking configuration rather than guess
     */
    public static RedactorConfig decode(String text) {
        Map<String, String> values = new HashMap<>();
        List<DomainRule> rules = new ArrayList<>();
        List<String> customFieldNames = new ArrayList<>();
        List<SavedPrompt> prompts = new ArrayList<>();
        int lineNumber = 0;
        for (String line : text.split("\n")) {
            lineNumber++;
            String trimmed = line.strip();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq <= 0) {
                throw new ConfigException("Malformed configuration line " + lineNumber + ".");
            }
            String key = trimmed.substring(0, eq);
            String value = trimmed.substring(eq + 1);
            switch (key) {
                case "domain" -> rules.add(parseDomain(value, lineNumber));
                case "customField" -> customFieldNames.add(value);
                case "prompt" -> prompts.add(parsePrompt(value, lineNumber));
                default -> {
                    if (values.put(key, value) != null) {
                        throw new ConfigException("Duplicate configuration key on line " + lineNumber + ".");
                    }
                }
            }
        }
        if (!String.valueOf(VERSION).equals(values.remove("version"))) {
            throw new ConfigException("Unsupported configuration version.");
        }
        RedactorConfig defaults = RedactorConfig.defaults();
        ProcessingOptions d = defaults.processing();
        AgentSettings da = defaults.agent();
        try {
            ProcessingOptions processing = new ProcessingOptions(
                    bool(values, "processRequests", d.processRequests()),
                    bool(values, "processResponses", d.processResponses()),
                    bool(values, "processHeaders", d.processHeaders()),
                    bool(values, "processBodies", d.processBodies()),
                    bool(values, "omitBinaryBodies", d.omitBinaryBodies()),
                    integer(values, "maxPartChars", d.maxPartChars()));
            AgentSettings agent = new AgentSettings(
                    string(values, "opencodeUrl", da.opencodeUrl()),
                    string(values, "opencodeModel", da.opencodeModel()),
                    decodeBlob(string(values, "opencodePassword", "")),
                    integer(values, "agentMaxIterations", da.maxIterations()),
                    integer(values, "agentRateLimitMs", da.rateLimitMs()),
                    decodeBlob(string(values, "agentRules", "")),
                    integer(values, "agentMaxEndpoints", da.maxEndpoints()),
                    integer(values, "agentEndpointIterations", da.endpointIterations()),
                    integer(values, "agentParallelism", da.parallelism()),
                    bool(values, "agentAddToSiteMap", da.addToSiteMap()),
                    bool(values, "agentCreateIssues", da.createIssues()));
            RedactorConfig config = new RedactorConfig(
                    bool(values, "enabled", defaults.enabled()),
                    rules,
                    bool(values, "keepSubdomainLabels", defaults.keepSubdomainLabels()),
                    bool(values, "autoBrandKeywords", defaults.autoBrandKeywords()),
                    new MaskingOptions(
                            bool(values, "maskSecrets", defaults.masking().secrets()),
                            bool(values, "maskPersonalData", defaults.masking().personalData()),
                            bool(values, "maskIpAddresses", defaults.masking().ipAddresses())),
                    processing,
                    bool(values, "verboseAudit", defaults.verboseAudit()),
                    customFieldNames,
                    agent,
                    prompts);
            if (!values.isEmpty()) {
                throw new ConfigException("Unknown configuration key.");
            }
            return config;
        } catch (IllegalArgumentException e) {
            throw e instanceof ConfigException ce ? ce : new ConfigException("Invalid configuration: " + e.getMessage());
        }
    }

    private static DomainRule parseDomain(String value, int lineNumber) {
        String[] parts = value.split("\t", -1);
        if (parts.length != 2 && parts.length != 3) {
            throw new ConfigException("Malformed domain rule on line " + lineNumber + ".");
        }
        try {
            return DomainRule.of(parts[0], parts[1],
                    parts.length == 3 ? DomainRule.parseKeywords(parts[2]) : List.of());
        } catch (IllegalArgumentException e) {
            throw new ConfigException("Invalid domain rule on line " + lineNumber + ": " + e.getMessage());
        }
    }

    private static SavedPrompt parsePrompt(String value, int lineNumber) {
        try {
            String[] parts = value.split("\t", -1);
            // New format: b64 \t <name-b64> \t <text-b64>
            if (parts.length >= 3 && parts[0].equals("b64")) {
                return new SavedPrompt(decodeBlob(parts[1]), decodeBlob(parts[2]));
            }
            // Legacy format: <name> \t <text>
            int tab = value.indexOf('\t');
            if (tab < 0) {
                throw new ConfigException("Malformed prompt on line " + lineNumber + ".");
            }
            return new SavedPrompt(value.substring(0, tab), value.substring(tab + 1));
        } catch (IllegalArgumentException e) {
            throw new ConfigException("Invalid prompt on line " + lineNumber + ": " + e.getMessage());
        }
    }

    private static String encodeBlob(String password) {
        if (password.isEmpty()) {
            return "";
        }
        return Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8));
    }

    private static String decodeBlob(String stored) {
        if (stored.isEmpty()) {
            return "";
        }
        try {
            return new String(Base64.getDecoder().decode(stored), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new ConfigException("Invalid stored value.");
        }
    }

    private static String string(Map<String, String> values, String key, String fallback) {
        String value = values.remove(key);
        return value == null ? fallback : value;
    }

    private static boolean bool(Map<String, String> values, String key, boolean fallback) {
        String value = values.remove(key);
        if (value == null) {
            return fallback;
        }
        return switch (value) {
            case "true" -> true;
            case "false" -> false;
            default -> throw new ConfigException("Invalid boolean for " + key + ".");
        };
    }

    private static int integer(Map<String, String> values, String key, int fallback) {
        String value = values.remove(key);
        if (value == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new ConfigException("Invalid number for " + key + ".");
        }
    }

    public static final class ConfigException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        public ConfigException(String message) {
            super(message);
        }
    }
}
