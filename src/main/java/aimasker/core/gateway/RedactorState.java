package aimasker.core.gateway;

import aimasker.core.RedactionEngine;
import aimasker.core.audit.Fingerprinter;
import aimasker.core.config.RedactorConfig;
import aimasker.core.crypto.Encryptor;
import aimasker.core.validation.LeakageValidator;

/**
 * A configuration together with the engines and validator compiled from it. Swapped atomically
 * whenever the configuration changes.
 *
 * <p>Two engines are compiled from the same detectors:
 * <ul>
 *   <li>{@link #engine()} — one-way fingerprint placeholders ({@code [COOKIE:3f9a1c2b]}), used
 *       by the existing "Ask Burp AI" / "Copy AI-safe" flows.</li>
 *   <li>{@link #reversibleEngine()} — encrypted, reversible tokens ({@code [COOKIE#<b64url>]}),
 *       used by the agent loop so Burp can decrypt and replay the real request.</li>
 * </ul>
 * Detection is identical in both modes, so a single {@link #validator()} (built on the one-way
 * engine) scans outgoing text regardless of mode.
 */
public record RedactorState(
        RedactorConfig config,
        RedactionEngine engine,
        RedactionEngine reversibleEngine,
        LeakageValidator validator,
        Encryptor encryptor) {

    public static RedactorState of(RedactorConfig config, Fingerprinter fingerprinter, Encryptor encryptor) {
        RedactionEngine engine = new RedactionEngine(config.detectors(), fingerprinter);
        RedactionEngine reversibleEngine = new RedactionEngine(config.detectors(), fingerprinter.withEncryptor(encryptor));
        return new RedactorState(config, engine, reversibleEngine, new LeakageValidator(engine), encryptor);
    }

    /** The engine for the requested mode. */
    public RedactionEngine engineFor(boolean reversible) {
        return reversible ? reversibleEngine : engine;
    }
}
