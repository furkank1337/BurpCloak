package aimasker.core.audit;

import aimasker.core.crypto.Encryptor;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Produces non-reversible identifiers for sensitive values so they can be correlated in logs
 * and lineage records without being written out.
 *
 * <p>Uses HMAC-SHA256 with a locally stored secret rather than a plain SHA-256: customer
 * domains are low-entropy, so an unkeyed hash of {@code nday.blog} could be reversed by simply
 * hashing candidate domains.
 */
public final class Fingerprinter {

    public static final int KEY_BYTES = 32;
    private static final String ALGORITHM = "HmacSHA256";

    private final SecretKeySpec key;
    /** Present only in the reversible (agent) mode; {@code null} for one-way fingerprinting. */
    private final Encryptor encryptor;

    public Fingerprinter(byte[] key) {
        if (key == null || key.length < 16) {
            throw new IllegalArgumentException("fingerprint key must be at least 16 bytes");
        }
        this.key = new SecretKeySpec(key.clone(), ALGORITHM);
        this.encryptor = null;
    }

    private Fingerprinter(SecretKeySpec key, Encryptor encryptor) {
        this.key = key;
        this.encryptor = encryptor;
    }

    /**
     * A copy of this fingerprinter that also carries an {@link Encryptor}, turning placeholders
     * into reversible encrypted tokens. Used to build the agent-session redaction engine; the
     * fingerprint (lineage) key is unchanged.
     */
    public Fingerprinter withEncryptor(Encryptor encryptor) {
        if (encryptor == null) {
            throw new IllegalArgumentException("encryptor is required");
        }
        return new Fingerprinter(this.key, encryptor);
    }

    /** @return the encryptor for reversible tokens, or {@code null} in one-way mode */
    public Encryptor encryptor() {
        return encryptor;
    }

    public static byte[] newKey() {
        byte[] key = new byte[KEY_BYTES];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /** Returns {@code hmac:<32 hex chars>} for the lower-cased value. */
    public String fingerprint(String value) {
        return "hmac:" + HexFormat.of().formatHex(hmac(value.toLowerCase(Locale.ROOT)), 0, 16);
    }

    /**
     * Returns {@code hmac:<32 hex chars>} for the value as-is. Used for secrets, where
     * {@code abc} and {@code ABC} are different tokens.
     */
    public String fingerprintExact(String value) {
        return "hmac:" + HexFormat.of().formatHex(hmac(value), 0, 16);
    }

    /**
     * Eight hex characters identifying {@code value}, used inside placeholders such as
     * {@code [COOKIE:3f9a1c2b]} so the same secret gets the same placeholder everywhere.
     * 32 bits of a keyed hash reveal nothing about the value.
     */
    public String shortId(String value) {
        return HexFormat.of().formatHex(hmac(value), 0, 4);
    }

    private byte[] hmac(String value) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            // HmacSHA256 is mandatory on every JRE; reaching this is a broken runtime.
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
