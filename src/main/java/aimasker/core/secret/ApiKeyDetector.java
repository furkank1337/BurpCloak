package aimasker.core.secret;

import aimasker.core.EntityType;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Secrets recognisable by their format alone: vendor API keys, private key blocks, and
 * credentials embedded in URLs or connection strings ({@code postgres://user:pass@host}).
 */
public final class ApiKeyDetector extends SpanDetector {

    public static final String ID = "api-key";

    /**
     * @param hints literal substrings, at least one of which must occur for the (slower)
     *              pattern to run at all
     */
    private record Format(String kind, EntityType type, Pattern pattern, int group, String... hints) {
        static Format of(String kind, String regex, String... hints) {
            return new Format(kind, EntityType.API_KEY,
                    Pattern.compile("(?<![A-Za-z0-9_])(?:" + regex + ")(?![A-Za-z0-9_])"), 0, hints);
        }
    }

    private static final List<Format> FORMATS = List.of(
            Format.of("AWS_KEY", "(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA|ABIA|ACCA)[A-Z0-9]{16}",
                    "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "AIPA", "ABIA", "ACCA"),
            Format.of("GITHUB_TOKEN", "gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255}",
                    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
            Format.of("GITLAB_TOKEN", "glpat-[A-Za-z0-9_-]{20,}", "glpat-"),
            Format.of("SLACK_TOKEN", "xox[abposr]-[A-Za-z0-9-]{10,}", "xox"),
            Format.of("GOOGLE_API_KEY", "AIza[0-9A-Za-z_-]{35}", "AIza"),
            Format.of("STRIPE_KEY", "(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}", "_live_", "_test_"),
            Format.of("OPENAI_KEY", "sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{40,}",
                    "T3BlbkFJ", "sk-proj-"),
            Format.of("ANTHROPIC_KEY", "sk-ant-[A-Za-z0-9_-]{20,}", "sk-ant-"),
            Format.of("SENDGRID_KEY", "SG\\.[A-Za-z0-9_-]{16,32}\\.[A-Za-z0-9_-]{16,64}", "SG."),
            Format.of("TWILIO_KEY", "SK[0-9a-f]{32}", "SK"),
            Format.of("MAILGUN_KEY", "key-[0-9a-z]{32}", "key-"),
            Format.of("NPM_TOKEN", "npm_[A-Za-z0-9]{36}", "npm_"),
            Format.of("PYPI_TOKEN", "pypi-[A-Za-z0-9_-]{50,}", "pypi-"),
            Format.of("DIGITALOCEAN_TOKEN", "do[por]_v1_[a-f0-9]{64}", "_v1_"),
            Format.of("SHOPIFY_TOKEN", "shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}", "shpat_", "shpca_", "shppa_", "shpss_"),
            Format.of("HUGGINGFACE_TOKEN", "hf_[A-Za-z0-9]{34,}", "hf_"),
            Format.of("GOOGLE_OAUTH", "ya29\\.[0-9A-Za-z_-]{20,}", "ya29."),
            Format.of("SQUARE_TOKEN", "sq0(?:atp|csp)-[0-9A-Za-z_-]{22,}", "sq0atp-", "sq0csp-"),
            Format.of("SLACK_APP_TOKEN", "xapp-[0-9]-[A-Za-z0-9-]{10,}", "xapp-"),
            new Format("AZURE_KEY", EntityType.API_KEY,
                    Pattern.compile("(?<=AccountKey=)[A-Za-z0-9+/]{80,100}={0,2}"), 0, "AccountKey="),
            new Format("SLACK_WEBHOOK", EntityType.API_KEY,
                    Pattern.compile("(?<=hooks\\.slack\\.com/services/)[A-Za-z0-9/]{20,}"), 0, "hooks.slack.com"),
            new Format("PRIVATE_KEY", EntityType.SECRET, Pattern.compile(
                    "-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\\s\\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
                    0, "PRIVATE KEY"));

    /** {@code user:password@} right after {@code scheme://}; starts with a literal so it scans fast. */
    private static final Pattern URL_CREDENTIALS = Pattern.compile("://([^\\s:/@\"'<>\\[\\]]{1,128}:[^\\s/@\"'<>]{1,256})@");
    private static final Pattern SCHEME = Pattern.compile("(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{1,20}$");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.API_KEY;
    }

    @Override
    List<Span> spans(String text) {
        List<Span> spans = new ArrayList<>();
        for (Format format : FORMATS) {
            if (!containsAny(text, format.hints)) {
                continue;
            }
            Matcher matcher = format.pattern.matcher(text);
            while (matcher.find()) {
                spans.add(new Span(matcher.start(format.group), matcher.end(format.group), format.type, format.kind));
            }
        }
        if (text.indexOf('@') >= 0) {
            Matcher credentials = URL_CREDENTIALS.matcher(text);
            while (credentials.find()) {
                String before = text.substring(Math.max(0, credentials.start() - 22), credentials.start());
                if (SCHEME.matcher(before).find()) {
                    spans.add(new Span(credentials.start(1), credentials.end(1), EntityType.SECRET, "CREDENTIALS"));
                }
            }
        }
        return spans;
    }

    private static boolean containsAny(String text, String[] hints) {
        for (String hint : hints) {
            if (text.contains(hint)) {
                return true;
            }
        }
        return false;
    }
}
