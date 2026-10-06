package aimasker.core.domain;

import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A customer domain to hide and the value that replaces it.
 *
 * <p>The target is stored in canonical form: lower-case ASCII (IDNA/punycode), no scheme,
 * port, path or wildcard. Construct instances through {@link #of(String, String)} so user
 * input is normalised and validated.
 *
 * @param target      canonical target domain, e.g. {@code nday.blog}
 * @param replacement replacement for the target part of a hostname, e.g. {@code redacted.com}
 *                    or {@code [REDACTED_DOMAIN]}
 * @param keywords    extra brand / organisation names tied to this customer, e.g.
 *                    {@code N-Day Security}; matched loosely (see
 *                    {@link aimasker.core.keyword.KeywordDetector})
 */
public record DomainRule(String target, String replacement, List<String> keywords) {

    public static final String DEFAULT_REPLACEMENT = "redacted.com";
    /** Brand keywords shorter than this (letters/digits only) cause too many false positives. */
    public static final int MIN_KEYWORD_CHARS = 4;

    /** Second-level labels under country TLDs, e.g. the {@code co} in {@code example.co.uk}. */
    private static final Set<String> SECOND_LEVEL = Set.of(
            "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gen", "bel", "biz", "info",
            "k12", "ltd", "plc", "tv", "web");

    private static final Pattern LABEL = Pattern.compile("[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?");
    /**
     * Replacements are written into arbitrary contexts (JSON strings, HTML attributes, URLs),
     * so they are limited to characters that cannot change the surrounding syntax.
     */
    private static final Pattern REPLACEMENT = Pattern.compile("[A-Za-z0-9._\\-\\[\\]]{1,253}");

    public DomainRule {
        if (target == null || replacement == null) {
            throw new IllegalArgumentException("target and replacement are required");
        }
        keywords = List.copyOf(keywords == null ? List.of() : keywords);
    }

    public DomainRule(String target, String replacement) {
        this(target, replacement, List.of());
    }

    /**
     * Normalises and validates user input.
     *
     * @throws InvalidRuleException with a message that does not echo the input
     */
    public static DomainRule of(String rawTarget, String rawReplacement) {
        return of(rawTarget, rawReplacement, List.of());
    }

    /**
     * @param rawKeywords extra brand names; blank entries are ignored
     * @throws InvalidRuleException with a message that does not echo the input
     */
    public static DomainRule of(String rawTarget, String rawReplacement, List<String> rawKeywords) {
        String target = normalizeTarget(rawTarget);
        String replacement = rawReplacement == null ? "" : rawReplacement.trim();
        if (replacement.isEmpty()) {
            replacement = DEFAULT_REPLACEMENT;
        }
        if (!REPLACEMENT.matcher(replacement).matches()) {
            throw new InvalidRuleException(
                    "Replacement may only contain letters, digits, '.', '-', '_', '[' and ']'.");
        }
        return new DomainRule(target, replacement, normalizeKeywords(rawKeywords));
    }

    /** Parses a comma-separated keyword list as typed in the UI. */
    public static List<String> parseKeywords(String commaSeparated) {
        List<String> keywords = new ArrayList<>();
        if (commaSeparated != null) {
            for (String part : commaSeparated.split(",")) {
                if (!part.isBlank()) {
                    keywords.add(part.strip());
                }
            }
        }
        return keywords;
    }

    private static List<String> normalizeKeywords(List<String> raw) {
        Set<String> result = new LinkedHashSet<>();
        for (String keyword : raw == null ? List.<String>of() : raw) {
            String value = keyword == null ? "" : keyword.strip();
            if (value.isEmpty()) {
                continue;
            }
            if (value.length() > 64 || value.chars().anyMatch(c -> c == ',' || c == '\t' || Character.isISOControl(c))) {
                throw new InvalidRuleException("A keyword is too long or contains ',', tab or control characters.");
            }
            if (alphanumeric(value).length() < MIN_KEYWORD_CHARS) {
                throw new InvalidRuleException("Keywords need at least " + MIN_KEYWORD_CHARS + " letters or digits.");
            }
            result.add(value);
        }
        return List.copyOf(result);
    }

    /** Letters and digits of {@code value}, lower-cased; the part of a keyword that is matched. */
    public static String alphanumeric(String value) {
        StringBuilder out = new StringBuilder();
        value.codePoints().filter(Character::isLetterOrDigit).forEach(out::appendCodePoint);
        return out.toString().toLowerCase(Locale.ROOT);
    }

    /**
     * Brand name derived from the domain: the registrable label, e.g. {@code nday} for
     * {@code nday.blog} or {@code example} for {@code www.example.co.uk}. Empty when the label is
     * too short to match safely.
     */
    public Optional<String> autoKeyword() {
        String[] labels = target.split("\\.");
        if (labels.length < 2) {
            return Optional.empty();
        }
        int index = labels.length - 2;
        if (labels.length >= 3 && labels[labels.length - 1].length() == 2 && SECOND_LEVEL.contains(labels[index])) {
            index--;
        }
        String label = IDN.toUnicode(labels[index], IDN.ALLOW_UNASSIGNED);
        String keyword = alphanumeric(label);
        return keyword.length() >= MIN_KEYWORD_CHARS ? Optional.of(keyword) : Optional.empty();
    }

    /**
     * Text written in place of a brand keyword: the first label of a hostname replacement
     * ({@code redacted.com -> redacted}), otherwise {@code [REDACTED]}.
     */
    public String keywordReplacement() {
        if (replacementIsHostname()) {
            return replacement.substring(0, replacement.indexOf('.'));
        }
        return "[REDACTED]";
    }

    public DomainRule withReplacement(String value) {
        return of(target, value, keywords);
    }

    public DomainRule withKeywords(List<String> value) {
        return of(target, replacement, value);
    }

    /** Strips scheme, credentials, path, port and wildcards; converts to lower-case punycode. */
    public static String normalizeTarget(String raw) {
        if (raw == null) {
            throw new InvalidRuleException("Target domain is empty.");
        }
        String value = raw.trim();
        int scheme = value.indexOf("://");
        if (scheme >= 0) {
            value = value.substring(scheme + 3);
        } else if (value.startsWith("//")) {
            value = value.substring(2);
        }
        value = cutAtFirst(value, "/?#");
        int at = value.lastIndexOf('@');
        if (at >= 0) {
            value = value.substring(at + 1);
        }
        int colon = value.lastIndexOf(':');
        if (colon >= 0 && value.indexOf(':') == colon) {
            value = value.substring(0, colon);
        }
        while (value.startsWith("*.") || value.startsWith(".")) {
            value = value.substring(value.startsWith("*.") ? 2 : 1);
        }
        while (value.endsWith(".")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.isEmpty()) {
            throw new InvalidRuleException("Target domain is empty.");
        }
        String ascii;
        try {
            ascii = IDN.toASCII(value, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw new InvalidRuleException("Target is not a valid domain name.");
        }
        if (ascii.length() > 253) {
            throw new InvalidRuleException("Target domain is longer than 253 characters.");
        }
        for (String label : ascii.split("\\.", -1)) {
            if (!LABEL.matcher(label).matches()) {
                throw new InvalidRuleException("Target is not a valid domain name.");
            }
        }
        return ascii;
    }

    private static String cutAtFirst(String value, String stopChars) {
        for (int i = 0; i < value.length(); i++) {
            if (stopChars.indexOf(value.charAt(i)) >= 0) {
                return value.substring(0, i);
            }
        }
        return value;
    }

    /** Target split into DNS labels, e.g. {@code [nday, blog]}. */
    public List<String> labels() {
        return List.of(target.split("\\."));
    }

    /**
     * Every textual spelling of the target to search for: the punycode form, the Unicode form
     * (for text already decoded as UTF-8) and the UTF-8 bytes viewed as ISO-8859-1 (for raw
     * HTTP bytes, which this project handles as Latin-1 strings).
     */
    public Set<String> spellings() {
        Set<String> spellings = new LinkedHashSet<>();
        spellings.add(target);
        String unicode = IDN.toUnicode(target, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
        if (!unicode.equals(target)) {
            spellings.add(unicode);
            spellings.add(new String(unicode.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1));
        }
        return spellings;
    }

    /** True when the replacement is hostname-shaped, so an encoded dot style can be mirrored. */
    boolean replacementIsHostname() {
        return replacement.indexOf('.') >= 0 && replacement.indexOf('[') < 0;
    }

    /** Thrown for invalid user input. Messages never contain the rejected value. */
    public static final class InvalidRuleException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        public InvalidRuleException(String message) {
            super(message);
        }
    }
}
