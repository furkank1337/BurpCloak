package aimasker.core.validation;

import java.util.List;

/**
 * Result of a leakage scan. Reasons never contain the sensitive value.
 *
 * @param verdict {@link Verdict#SAFE}, {@link Verdict#LEAKAGE} or {@link Verdict#UNKNOWN}
 * @param reasons human-readable explanations for a non-SAFE verdict
 */
public record ValidationResult(Verdict verdict, List<String> reasons) {
    public ValidationResult {
        reasons = List.copyOf(reasons);
    }

    public boolean clean() {
        return verdict == Verdict.SAFE;
    }
}
