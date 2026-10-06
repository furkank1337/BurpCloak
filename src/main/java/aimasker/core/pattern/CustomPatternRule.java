package aimasker.core.pattern;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A user-defined regular expression and its replacement, e.g. {@code EMP-[0-9]{6}} to
 * {@code [EMPLOYEE_ID]}.
 *
 * @param name        label shown in the UI and lineage; must not contain customer data
 * @param pattern     compiled expression
 * @param replacement literal replacement text
 */
public record CustomPatternRule(String name, Pattern pattern, String replacement) {

    public static CustomPatternRule of(String name, String regex, String replacement) {
        if (regex == null || regex.isBlank()) {
            throw new IllegalArgumentException("Pattern is empty.");
        }
        try {
            Pattern pattern = Pattern.compile(regex);
            if (pattern.matcher("").matches()) {
                throw new IllegalArgumentException("Pattern must not match the empty string.");
            }
            return new CustomPatternRule(name, pattern, replacement);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Pattern is not a valid regular expression.", e);
        }
    }
}
