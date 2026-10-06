package aimasker.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reversible, deterministic authenticated encryption for placeholder payloads.
 *
 * <p>Used only in the agent ("reversible") redaction mode. A masked value becomes a token
 * {@code [KIND#<b64url(nonce‖ciphertext‖tag)>]} whose payload only this extension can decrypt,
 * because the key never leaves Burp. OpenCode / the AI sees ciphertext and nothing else.
 *
 * <p>Design notes:
 * <ul>
 *   <li><b>Deterministic.</b> The GCM nonce is derived from the value itself
 *       ({@code HMAC-SHA256(nonceKey, kind‖value)[0..12]}), so the same value always yields the
 *       same token and session correlation is preserved. A nonce only ever repeats for the same
 *       plaintext, so GCM nonce-reuse is not a problem here. This deliberately leaks equality
 *       (same value → same token); it is not IND-CPA. That is the intended trade-off.</li>
 *   <li><b>Authenticated.</b> If the AI tampers with a token, GCM authentication fails and
 *       {@link #open} throws, so the replay is rejected.</li>
 *   <li><b>Key separation.</b> The AES key and the nonce-MAC key are two independent sub-keys
 *       derived from the root key with HKDF-SHA256, so this never reuses the raw fingerprint key
 *       bytes.</li>
 * </ul>
 *
 * <p>Values are handled as ISO-8859-1 (one byte per char), matching how the rest of the project
 * represents raw HTTP bytes, so a sealed value round-trips byte-for-byte.
 */
public final class Encryptor {

    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String HMAC = "HmacSHA256";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int AES_KEY_BYTES = 32;

    private final SecretKeySpec aesKey;
    private final byte[] nonceKey;

    public Encryptor(byte[] rootKey) {
        if (rootKey == null || rootKey.length < 16) {
            throw new IllegalArgumentException("root key must be at least 16 bytes");
        }
        byte[] prk = hkdfExtract(rootKey);
        this.aesKey = new SecretKeySpec(hkdfExpand(prk, "cloak-aes-v1", AES_KEY_BYTES), AES);
        this.nonceKey = hkdfExpand(prk, "cloak-nonce-v1", AES_KEY_BYTES);
    }

    /** Encrypts {@code value} and returns the url-safe, unpadded base64 token payload. */
    public String seal(String kind, String value) {
        byte[] data = value.getBytes(StandardCharsets.ISO_8859_1);
        byte[] nonce = deterministicNonce(kind, value);
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ciphertext = cipher.doFinal(data);
            byte[] blob = new byte[NONCE_BYTES + ciphertext.length];
            System.arraycopy(nonce, 0, blob, 0, NONCE_BYTES);
            System.arraycopy(ciphertext, 0, blob, NONCE_BYTES, ciphertext.length);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(blob);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM sealing failed", e);
        }
    }

    /**
     * Decrypts a token payload produced by {@link #seal}.
     *
     * @throws IllegalArgumentException if the payload is malformed or fails authentication
     *                                  (so a tampered token cannot be replayed)
     */
    public String open(String payload) {
        byte[] blob;
        try {
            blob = Base64.getUrlDecoder().decode(payload);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("not a valid token payload");
        }
        if (blob.length <= NONCE_BYTES) {
            throw new IllegalArgumentException("token payload too short");
        }
        byte[] nonce = Arrays.copyOfRange(blob, 0, NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(blob, NONCE_BYTES, blob.length);
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(TAG_BITS, nonce));
            byte[] data = cipher.doFinal(ciphertext);
            return new String(data, StandardCharsets.ISO_8859_1);
        } catch (GeneralSecurityException e) {
            // Includes AEADBadTagException: tampered or wrong-key token.
            throw new IllegalArgumentException("token authentication failed");
        }
    }

    private byte[] deterministicNonce(String kind, String value) {
        byte[] mac = hmac(nonceKey, (kind + "\u0000" + value).getBytes(StandardCharsets.ISO_8859_1));
        return Arrays.copyOfRange(mac, 0, NONCE_BYTES);
    }

    // --- HKDF-SHA256 (RFC 5869) -------------------------------------------------------------

    private static byte[] hkdfExtract(byte[] ikm) {
        byte[] salt = new byte[32]; // all-zero salt, per RFC 5869 when none is supplied
        return hmac(salt, ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, String info, int length) {
        byte[] infoBytes = info.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int generated = 0;
        byte counter = 1;
        while (generated < length) {
            byte[] input = new byte[previous.length + infoBytes.length + 1];
            System.arraycopy(previous, 0, input, 0, previous.length);
            System.arraycopy(infoBytes, 0, input, previous.length, infoBytes.length);
            input[input.length - 1] = counter;
            previous = hmac(prk, input);
            int take = Math.min(previous.length, length - generated);
            System.arraycopy(previous, 0, out, generated, take);
            generated += take;
            counter++;
        }
        return out;
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
