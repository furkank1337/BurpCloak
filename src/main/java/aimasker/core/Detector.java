package aimasker.core;

import aimasker.core.audit.Fingerprinter;
import java.util.List;

/**
 * A pluggable recogniser for one kind of sensitive data.
 *
 * <p>Contract every implementation must honour:
 * <ul>
 *   <li>Pure and local: no I/O, no network, no logging of matched values.</li>
 *   <li>Immutable and thread-safe once constructed.</li>
 *   <li>{@link #detect} must find everything {@link #redact} would replace, because the
 *       leakage validator relies on {@code detect} to prove a message is clean.</li>
 *   <li>The output of {@link #redact} must not be detected again by the same detector
 *       (replacements must be disjoint from the sensitive values).</li>
 * </ul>
 */
public interface Detector {

    /** Stable identifier, e.g. {@code "domain"}. */
    String id();

    EntityType entityType();

    /** Finds every sensitive span in {@code text}. Spans must not overlap. */
    List<Detection> detect(String text);

    /** Replaces every sensitive span in {@code text}. */
    RedactionOutcome redact(String text, Fingerprinter fingerprinter);
}
