package aimasker.core.domain;

import aimasker.core.Detection;
import aimasker.core.Detector;
import aimasker.core.EntityType;
import aimasker.core.RedactionEvent;
import aimasker.core.RedactionOutcome;
import aimasker.core.audit.Fingerprinter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds and replaces customer domains and all of their subdomains using hostname boundaries.
 *
 * <p>Matching rules for target {@code nday.blog}:
 * <ul>
 *   <li>{@code nday.blog}, {@code api.nday.blog}, {@code foo.api.nday.blog} match (any case).</li>
 *   <li>{@code notnday.blog} and {@code example-nday.blog} do not: the character before the
 *       target is part of a different DNS label.</li>
 *   <li>{@code nday.blog.example.com} does not: the target is followed by another label.</li>
 *   <li>Dots may be written encoded ({@code nday%2Eblog}, <code>nday&#92;u002eblog</code>,
 *       {@code nday&#46;blog}); the replacement mirrors the same encoding.</li>
 *   <li>A target directly after an escape sequence such as {@code %2F}, <code>&#92;u002F</code>,
 *       <code>&#92;x2F</code> or <code>&#92;n</code> counts as a boundary, so {@code https%3A%2F%2Fnday.blog}
 *       is matched even though the preceding character is a hex digit.</li>
 * </ul>
 *
 * <p>Only the target part of a hostname is replaced by default, keeping the structure that
 * matters to an analyst: {@code https://api.nday.blog:8443/x} becomes
 * {@code https://api.redacted.com:8443/x}.
 */
public final class DomainDetector implements Detector {

    public static final String ID = "domain";

    /** Every way a hostname dot may be spelled in HTTP, JavaScript, JSON or HTML. */
    private static final String DOT =
            "(?:\\.|%2e|%252e|\\\\u002e|\\\\x2e|&#0{0,2}46;|&#x0{0,2}2e;|&period;)";
    private static final String[] DOT_TOKENS = {
        ".", "%2e", "%252e", "\\u002e", "\\x2e",
        "&#46;", "&#046;", "&#0046;", "&#x2e;", "&#x02e;", "&#x002e;", "&period;",
    };
    private static final Pattern DOT_PATTERN = Pattern.compile(DOT, Pattern.CASE_INSENSITIVE);
    private static final String LABEL_CHAR = "[A-Za-z0-9_-]";
    /** An escape sequence that ends right before the target acts as a hostname boundary. */
    private static final Pattern ESCAPE_BEFORE = Pattern.compile(
            "(?:%(?:25)?[0-9a-f]{2}|\\\\u00[0-9a-f]{2}|\\\\x[0-9a-f]{2}|\\\\[nrtbfv0])$",
            Pattern.CASE_INSENSITIVE);

    private final List<CompiledRule> rules;
    private final boolean keepSubdomainLabels;

    /**
     * @param rules               domains to redact
     * @param keepSubdomainLabels {@code true}: {@code api.nday.blog -> api.redacted.com};
     *                            {@code false}: {@code api.nday.blog -> redacted.com}
     */
    public DomainDetector(List<DomainRule> rules, boolean keepSubdomainLabels) {
        List<CompiledRule> compiled = new ArrayList<>();
        for (DomainRule rule : rules) {
            compiled.add(CompiledRule.of(rule));
        }
        this.rules = List.copyOf(compiled);
        this.keepSubdomainLabels = keepSubdomainLabels;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.DOMAIN;
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> detections = new ArrayList<>();
        for (Match match : findAll(text)) {
            detections.add(new Detection(EntityType.DOMAIN, match.start, match.end));
        }
        return detections;
    }

    @Override
    public RedactionOutcome redact(String text, Fingerprinter fingerprinter) {
        List<Match> matches = findAll(text);
        if (matches.isEmpty()) {
            return RedactionOutcome.unchanged(text);
        }
        StringBuilder out = new StringBuilder(text.length());
        List<RedactionEvent> events = new ArrayList<>(matches.size());
        int last = 0;
        for (Match match : matches) {
            out.append(text, last, match.start);
            String replacement = replacementFor(text, match);
            out.append(replacement);
            events.add(new RedactionEvent(
                    EntityType.DOMAIN,
                    fingerprinter.fingerprint(canonicalHost(text, match)),
                    replacement,
                    match.start,
                    "plain"));
            last = match.end;
        }
        out.append(text, last, text.length());
        return new RedactionOutcome(out.toString(), events);
    }

    private List<Match> findAll(String text) {
        List<Match> candidates = new ArrayList<>();
        for (CompiledRule rule : rules) {
            for (Pattern pattern : rule.patterns) {
                Matcher matcher = pattern.matcher(text);
                int from = 0;
                while (from <= text.length() && matcher.find(from)) {
                    int targetStart = matcher.start();
                    int start = extendOverSubdomains(text, targetStart);
                    if (start == targetStart && !leftBoundary(text, targetStart)) {
                        from = targetStart + 1;
                        continue;
                    }
                    candidates.add(new Match(start, targetStart, matcher.end(), rule));
                    from = matcher.end();
                }
            }
        }
        return removeOverlaps(candidates);
    }

    /** Keeps the leftmost, longest, most specific match wherever candidates overlap. */
    private static List<Match> removeOverlaps(List<Match> candidates) {
        if (candidates.size() < 2) {
            return candidates;
        }
        candidates.sort(Comparator.comparingInt((Match m) -> m.start)
                .thenComparing(Comparator.comparingInt((Match m) -> m.end).reversed())
                .thenComparing(Comparator.comparingInt((Match m) -> m.rule.rule.target().length()).reversed()));
        List<Match> selected = new ArrayList<>(candidates.size());
        int lastEnd = -1;
        for (Match match : candidates) {
            if (match.start >= lastEnd) {
                selected.add(match);
                lastEnd = match.end;
            }
        }
        return selected;
    }

    /**
     * Walks left from the target over {@code label + dot} pairs and returns where the full
     * hostname starts. Returns {@code targetStart} when the target has no subdomain.
     */
    private static int extendOverSubdomains(String text, int targetStart) {
        int pos = targetStart;
        while (true) {
            int dotLength = dotTokenEndingAt(text, pos);
            if (dotLength == 0) {
                return pos;
            }
            int labelEnd = pos - dotLength;
            int labelStart = labelEnd;
            while (labelStart > 0 && isLabelChar(text.charAt(labelStart - 1))) {
                labelStart--;
            }
            labelStart = skipEscapeRemainder(text, labelStart, labelEnd);
            if (labelStart >= labelEnd) {
                return pos;
            }
            pos = labelStart;
        }
    }

    /**
     * Label scanning treats hex digits of a preceding escape as label characters, e.g. the
     * {@code 2F} in {@code %2Fapi.nday.blog}. Skip them so they stay outside the hostname.
     */
    private static int skipEscapeRemainder(String text, int labelStart, int labelEnd) {
        if (labelStart == 0) {
            return labelStart;
        }
        char before = text.charAt(labelStart - 1);
        int skip = 0;
        if (before == '%') {
            if (hexRun(text, labelStart, labelEnd, 4) && text.startsWith("25", labelStart)) {
                skip = 4;
            } else if (hexRun(text, labelStart, labelEnd, 2)) {
                skip = 2;
            }
        } else if (before == '\\' && labelStart < labelEnd) {
            char kind = Character.toLowerCase(text.charAt(labelStart));
            if (kind == 'u' && hexRun(text, labelStart + 1, labelEnd, 4)) {
                skip = 5;
            } else if (kind == 'x' && hexRun(text, labelStart + 1, labelEnd, 2)) {
                skip = 3;
            } else if ("nrtbfv0".indexOf(kind) >= 0) {
                skip = 1;
            }
        }
        return labelStart + skip;
    }

    private static boolean hexRun(String text, int from, int limit, int count) {
        if (from + count > limit) {
            return false;
        }
        for (int i = from; i < from + count; i++) {
            if (Character.digit(text.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    private static int dotTokenEndingAt(String text, int pos) {
        for (String token : DOT_TOKENS) {
            int from = pos - token.length();
            if (from >= 0 && text.regionMatches(true, from, token, 0, token.length())) {
                return token.length();
            }
        }
        return 0;
    }

    private static boolean leftBoundary(String text, int targetStart) {
        if (targetStart == 0 || !isLabelChar(text.charAt(targetStart - 1))) {
            return true;
        }
        String before = text.substring(Math.max(0, targetStart - 6), targetStart);
        return ESCAPE_BEFORE.matcher(before).find();
    }

    private static boolean isLabelChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    }

    private String replacementFor(String text, Match match) {
        String replacement = match.rule.rule.replacement();
        if (match.rule.rule.replacementIsHostname()) {
            Matcher dot = DOT_PATTERN.matcher(text).region(match.targetStart, match.end);
            if (dot.find() && !".".equals(dot.group())) {
                replacement = replacement.replace(".", dot.group());
            }
        }
        return keepSubdomainLabels ? text.substring(match.start, match.targetStart) + replacement : replacement;
    }

    private static String canonicalHost(String text, Match match) {
        return DOT_PATTERN.matcher(text.substring(match.start, match.end)).replaceAll(".").toLowerCase(Locale.ROOT);
    }

    private record Match(int start, int targetStart, int end, CompiledRule rule) {
    }

    private record CompiledRule(DomainRule rule, List<Pattern> patterns) {
        static CompiledRule of(DomainRule rule) {
            List<Pattern> patterns = new ArrayList<>();
            for (String spelling : rule.spellings()) {
                StringBuilder regex = new StringBuilder();
                String[] labels = spelling.split("\\.");
                for (int i = 0; i < labels.length; i++) {
                    if (i > 0) {
                        regex.append(DOT);
                    }
                    regex.append(Pattern.quote(labels[i]));
                }
                // Right boundary: not followed by more label characters or by ".<label>".
                regex.append("(?!").append(LABEL_CHAR).append(")(?!").append(DOT).append(LABEL_CHAR).append(')');
                patterns.add(Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE));
            }
            return new CompiledRule(rule, List.copyOf(patterns));
        }
    }
}
