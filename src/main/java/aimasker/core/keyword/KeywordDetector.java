package aimasker.core.keyword;

import aimasker.core.Detection;
import aimasker.core.Detector;
import aimasker.core.EntityType;
import aimasker.core.RedactionEvent;
import aimasker.core.RedactionOutcome;
import aimasker.core.audit.Fingerprinter;
import aimasker.core.domain.DomainRule;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Redacts brand / organisation names tied to a customer domain, which show up in page titles,
 * copyright lines, JS identifiers and so on even when no hostname is present.
 *
 * <p>For each rule the keywords are the user-supplied ones plus, optionally, the registrable
 * label of the domain ({@code nday} for {@code nday.blog}). A keyword is matched on its letters
 * and digits with an optional separator between any two of them, so {@code nday} catches
 * {@code N-Day}, {@code NDay}, {@code N Day}, {@code n_day}, {@code N%20Day} and {@code NDAY}.
 *
 * <p>Boundaries: no letter or digit directly before (an escape such as {@code %2F} or
 * {@code \n} counts as a boundary); no lower-case letter or digit directly after, so
 * {@code ndays} and {@code ndayblog} are left alone while camel case such as {@code NDayBlog}
 * is still caught.
 *
 * <p>The replacement follows the case of the match: {@code N-Day -> Redacted},
 * {@code NDAY -> REDACTED}, {@code nday -> redacted}.
 */
public final class KeywordDetector implements Detector {

    public static final String ID = "keyword";

    private static final String SEPARATOR = "(?:[ \\t_-]|%20|\\+|&nbsp;)?";
    private static final String LEFT_BOUNDARY = "(?:(?<![\\p{L}\\p{N}])|(?<=%[0-9A-Fa-f]{2})"
            + "|(?<=\\\\u00[0-9A-Fa-f]{2})|(?<=\\\\x[0-9A-Fa-f]{2})|(?<=\\\\[nrtbfv0]))";
    private static final String RIGHT_BOUNDARY = "(?![\\p{Ll}\\p{N}])";
    private static final Pattern LOWER_WORD = Pattern.compile("[a-z0-9-]+");

    private final List<CompiledKeyword> keywords;

    /**
     * @param rules        customer rules (their manual keywords are always used)
     * @param autoKeywords also derive a keyword from each domain's registrable label
     */
    public KeywordDetector(List<DomainRule> rules, boolean autoKeywords) {
        List<CompiledKeyword> compiled = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (DomainRule rule : rules) {
            List<String> candidates = new ArrayList<>(rule.keywords());
            if (autoKeywords) {
                rule.autoKeyword().ifPresent(candidates::add);
            }
            for (String keyword : candidates) {
                String letters = DomainRule.alphanumeric(keyword);
                if (letters.length() >= DomainRule.MIN_KEYWORD_CHARS && seen.add(letters)) {
                    compiled.add(new CompiledKeyword(compile(letters), rule.keywordReplacement(), letters.length()));
                }
            }
        }
        this.keywords = List.copyOf(compiled);
    }

    /** Keywords that will be matched, as letters/digits; for display in the UI. */
    public static List<String> effectiveKeywords(DomainRule rule, boolean autoKeywords) {
        List<String> result = new ArrayList<>(rule.keywords());
        if (autoKeywords) {
            rule.autoKeyword().ifPresent(keyword -> result.add(keyword + " (auto)"));
        }
        return result;
    }

    public boolean isEmpty() {
        return keywords.isEmpty();
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.BRAND;
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> detections = new ArrayList<>();
        for (Span span : findAll(text)) {
            detections.add(new Detection(EntityType.BRAND, span.start, span.end));
        }
        return detections;
    }

    @Override
    public RedactionOutcome redact(String text, Fingerprinter fingerprinter) {
        List<Span> spans = findAll(text);
        if (spans.isEmpty()) {
            return RedactionOutcome.unchanged(text);
        }
        StringBuilder out = new StringBuilder(text.length());
        List<RedactionEvent> events = new ArrayList<>(spans.size());
        int last = 0;
        for (Span span : spans) {
            String original = text.substring(span.start, span.end);
            String replacement = matchCase(original, span.keyword.replacement);
            out.append(text, last, span.start).append(replacement);
            events.add(new RedactionEvent(EntityType.BRAND,
                    fingerprinter.fingerprint(DomainRule.alphanumeric(original)), replacement, span.start, "plain"));
            last = span.end;
        }
        out.append(text, last, text.length());
        return new RedactionOutcome(out.toString(), events);
    }

    private List<Span> findAll(String text) {
        List<Span> spans = new ArrayList<>();
        for (CompiledKeyword keyword : keywords) {
            Matcher matcher = keyword.pattern.matcher(text);
            while (matcher.find()) {
                spans.add(new Span(matcher.start(), matcher.end(), keyword));
            }
        }
        if (spans.size() < 2) {
            return spans;
        }
        spans.sort(Comparator.comparingInt((Span s) -> s.start)
                .thenComparing(Comparator.comparingInt((Span s) -> s.end).reversed()));
        List<Span> selected = new ArrayList<>(spans.size());
        int lastEnd = -1;
        for (Span span : spans) {
            if (span.start >= lastEnd) {
                selected.add(span);
                lastEnd = span.end;
            }
        }
        return selected;
    }

    private static Pattern compile(String letters) {
        StringBuilder regex = new StringBuilder(LEFT_BOUNDARY).append("(?iu:");
        int[] codePoints = letters.codePoints().toArray();
        for (int i = 0; i < codePoints.length; i++) {
            if (i > 0) {
                regex.append(SEPARATOR);
            }
            regex.append(Pattern.quote(new String(Character.toChars(codePoints[i]))));
        }
        return Pattern.compile(regex.append(')').append(RIGHT_BOUNDARY).toString());
    }

    /** {@code N-Day -> Redacted}, {@code NDAY -> REDACTED}, otherwise the replacement as-is. */
    private static String matchCase(String original, String replacement) {
        if (!LOWER_WORD.matcher(replacement).matches()) {
            return replacement;
        }
        String letters = original.codePoints().filter(Character::isLetter)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
        if (letters.length() > 1 && letters.equals(letters.toUpperCase(Locale.ROOT))) {
            return replacement.toUpperCase(Locale.ROOT);
        }
        if (!letters.isEmpty() && Character.isUpperCase(letters.codePointAt(0))) {
            return Character.toUpperCase(replacement.charAt(0)) + replacement.substring(1);
        }
        return replacement;
    }

    private record CompiledKeyword(Pattern pattern, String replacement, int length) {
    }

    private record Span(int start, int end, CompiledKeyword keyword) {
    }
}
