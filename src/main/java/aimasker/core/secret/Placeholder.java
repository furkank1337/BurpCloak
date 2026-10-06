package aimasker.core.secret;

import aimasker.core.audit.Fingerprinter;
import aimasker.core.crypto.Encryptor;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Placeholders written in place of secrets and personal data.
 *
 * <p>Two shapes exist, chosen by the mode of the {@link Fingerprinter}:
 * <ul>
 *   <li><b>One-way</b> (no encryptor): {@code [COOKIE:3f9a1c2b]} — a keyed hash suffix, so the
 *       same value always gets the same placeholder but the original cannot be recovered. Used
 *       by "Ask Burp AI" / "Copy AI-safe".</li>
 *   <li><b>Reversible</b> (with encryptor): {@code [COOKIE:<b64url>]} — the payload is the
 *       original value encrypted with a key that only Burp holds, so the agent loop can decrypt
 *       it to replay the real request while the AI only ever sees ciphertext.</li>
 * </ul>
 *
 * <p>Both shapes use {@code :} as the separator on purpose: unlike {@code #} (which ends a URL
 * query / fragment and so would split the token during re-parsing), {@code :} is treated as part
 * of a value by every detector, so a reversible token survives being scanned again intact.
 */
public final class Placeholder {

    /** Matches any placeholder this project writes: one-way, reversible, or bare {@code [REDACTED]}. */
    private static final Pattern ANY =
            Pattern.compile("\\[[A-Z][A-Z0-9_]*(?::[A-Za-z0-9_-]+)?\\]");
    /** A token with a capturing group for its kind and payload (one-way id or encrypted blob). */
    private static final Pattern REVERSIBLE =
            Pattern.compile("\\[([A-Z][A-Z0-9_]*):([A-Za-z0-9_-]+)\\]");

    private Placeholder() {
    }

    public static String of(String kind, String value, Fingerprinter fingerprinter) {
        Encryptor encryptor = fingerprinter.encryptor();
        if (encryptor != null) {
            return "[" + kind + ":" + encryptor.seal(kind, value) + "]";
        }
        return "[" + kind + ":" + fingerprinter.shortId(value) + "]";
    }

    public static boolean is(CharSequence value) {
        return ANY.matcher(value).matches();
    }

    /**
     * Replaces every reversible token in {@code text} with the decrypted original value. Tokens
     * that do not decrypt with this encryptor (e.g. content that merely looks like a token, or a
     * tampered one) are left untouched. Used to turn an AI-proposed masked request back into the
     * real request just before it is replayed.
     */
    public static String unseal(String text, Encryptor encryptor) {
        if (text.indexOf('[') < 0) {
            return text;
        }
        Matcher matcher = REVERSIBLE.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        while (matcher.find()) {
            String replacement;
            try {
                replacement = Matcher.quoteReplacement(encryptor.open(matcher.group(2)));
            } catch (IllegalArgumentException e) {
                replacement = Matcher.quoteReplacement(matcher.group());
            }
            matcher.appendReplacement(out, replacement);
        }
        matcher.appendTail(out);
        return out.toString();
    }
}
