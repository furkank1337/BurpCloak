package aimasker.core.control;

import aimasker.core.audit.Statistics;
import java.util.List;

/**
 * Agent-safe status snapshot. Deliberately contains no target domains.
 *
 * @param enabled      whether AI transmission is possible at all
 * @param ruleCount    number of configured domain rules
 * @param rules        per rule: fingerprint of the target and its replacement
 * @param statistics   gateway counters
 */
public record RedactorStatus(boolean enabled, int ruleCount, List<RuleSummary> rules, Statistics.Snapshot statistics) {

    public RedactorStatus {
        rules = List.copyOf(rules);
    }

    public record RuleSummary(String targetFingerprint, String replacement) {
    }
}
