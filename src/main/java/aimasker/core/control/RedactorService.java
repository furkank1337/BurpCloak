package aimasker.core.control;

import aimasker.core.audit.AuditSink;
import aimasker.core.audit.Fingerprinter;
import aimasker.core.audit.LineageLog;
import aimasker.core.audit.Statistics;
import aimasker.core.config.ConfigCodec;
import aimasker.core.config.ConfigStore;
import aimasker.core.config.RedactorConfig;
import aimasker.core.crypto.Encryptor;
import aimasker.core.domain.DomainRule;
import aimasker.core.gateway.AiSafeGateway;
import aimasker.core.gateway.RedactorState;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;

/**
 * Owns the current configuration, persists it, and hands out the {@link AiSafeGateway}.
 * The UI and any future agent-control layer both go through this class.
 */
public final class RedactorService implements RedactorControl {

    private final ConfigStore store;
    private final Fingerprinter fingerprinter;
    private final Encryptor encryptor;
    private final AuditSink audit;
    private final AtomicReference<RedactorState> state = new AtomicReference<>();
    private final Statistics statistics = new Statistics();
    private final LineageLog lineage = new LineageLog();
    private final AiSafeGateway gateway;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public RedactorService(ConfigStore store, Fingerprinter fingerprinter, Encryptor encryptor, AuditSink audit) {
        this.store = store;
        this.fingerprinter = fingerprinter;
        this.encryptor = encryptor;
        this.audit = audit;
        this.state.set(RedactorState.of(loadConfig(), fingerprinter, encryptor));
        this.gateway = new AiSafeGateway(state::get, lineage, statistics, audit);
    }

    /** A stored configuration that cannot be read is replaced by the blocking default. */
    private RedactorConfig loadConfig() {
        Optional<String> stored = store.load();
        if (stored.isEmpty()) {
            return RedactorConfig.defaults();
        }
        try {
            return ConfigCodec.decode(stored.get());
        } catch (IllegalArgumentException e) {
            audit.warn("Stored configuration could not be loaded (" + e.getMessage()
                    + "); starting with no targets, so AI transmission is blocked.");
            return RedactorConfig.defaults();
        }
    }

    public AiSafeGateway gateway() {
        return gateway;
    }

    public RedactorConfig config() {
        return state.get().config();
    }

    public Statistics statistics() {
        return statistics;
    }

    public LineageLog lineage() {
        return lineage;
    }

    public Fingerprinter fingerprinter() {
        return fingerprinter;
    }

    /** Listener runs after every configuration change, on the calling thread. */
    public void addChangeListener(Runnable listener) {
        listeners.add(listener);
    }

    /**
     * Applies a configuration change atomically and persists it.
     *
     * @throws IllegalArgumentException if the resulting configuration is invalid; the current
     *                                  configuration is then left untouched
     */
    public RedactorConfig update(UnaryOperator<RedactorConfig> change) {
        RedactorState next = state.updateAndGet(current -> RedactorState.of(change.apply(current.config()), fingerprinter, encryptor));
        store.save(ConfigCodec.encode(next.config()));
        for (Runnable listener : listeners) {
            listener.run();
        }
        return next.config();
    }

    @Override
    public void enableRedaction() {
        update(config -> config.withEnabled(true));
        audit.info("Redaction ENABLED");
    }

    @Override
    public void disableRedaction() {
        update(config -> config.withEnabled(false));
        audit.info("Redaction DISABLED; AI transmission is blocked until re-enabled");
    }

    @Override
    public void addDomain(String target, String replacement) {
        DomainRule parsed = DomainRule.of(target, replacement);
        List<String> existingKeywords = config().domainRules().stream()
                .filter(r -> r.target().equals(parsed.target()))
                .findFirst().map(DomainRule::keywords).orElse(List.of());
        DomainRule rule = parsed.withKeywords(existingKeywords);
        update(config -> config.withRuleAdded(rule));
        audit.info("Domain rule added fingerprint=" + fingerprinter.fingerprint(rule.target())
                + " replacement=" + rule.replacement());
    }

    @Override
    public boolean removeDomain(String target) {
        String normalized = DomainRule.normalizeTarget(target);
        boolean present = config().domainRules().stream().anyMatch(r -> r.target().equals(normalized));
        if (present) {
            update(config -> config.withRuleRemoved(normalized));
            audit.info("Domain rule removed fingerprint=" + fingerprinter.fingerprint(normalized));
        }
        return present;
    }

    @Override
    public RedactorStatus getStatus() {
        RedactorConfig config = config();
        List<RedactorStatus.RuleSummary> rules = new ArrayList<>();
        for (DomainRule rule : config.domainRules()) {
            rules.add(new RedactorStatus.RuleSummary(fingerprinter.fingerprint(rule.target()), rule.replacement()));
        }
        return new RedactorStatus(config.enabled(), rules.size(), rules, statistics.snapshot());
    }
}
