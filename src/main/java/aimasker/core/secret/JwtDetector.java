package aimasker.core.secret;

import aimasker.core.EntityType;
import aimasker.core.MiniJson;
import aimasker.core.audit.Fingerprinter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Masks JSON Web Tokens while keeping what matters for testing.
 *
 * <p>A JWS keeps its header (algorithm, key id) and the timing/authorisation claims listed in
 * {@link #KEPT_CLAIMS}. Every other claim value becomes a placeholder, and the signature is
 * replaced so the token cannot be replayed:
 *
 * <pre>
 * eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJleHAiOjE3MDB9.abc  ->
 * eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJbQ0xBSU06M2Y5YTFjMmJdIiwiZXhwIjoxNzAwfQ.REDACTED_SIG_3f9a1c2b
 * </pre>
 *
 * <p>An encrypted JWE (five segments) is replaced entirely by {@code [JWE:xxxxxxxx]}.
 */
public final class JwtDetector extends SpanDetector {

    public static final String ID = "jwt";

    /** Claims that describe the token rather than the user; kept for analysis. */
    static final Set<String> KEPT_CLAIMS = Set.of(
            "exp", "iat", "nbf", "auth_time", "typ", "token_use", "scope", "scp", "roles", "role",
            "amr", "acr", "ver", "version", "grant_type", "alg");

    private static final String SEGMENT = "[A-Za-z0-9_-]";
    private static final Pattern JWE = Pattern.compile(
            "(?<![\\w-])eyJ" + SEGMENT + "{2,}\\." + SEGMENT + "*\\." + SEGMENT + "+\\." + SEGMENT + "+\\." + SEGMENT + "+(?![\\w.-])");
    private static final Pattern JWS = Pattern.compile(
            "(?<![\\w-])(eyJ" + SEGMENT + "{2,})\\.(" + SEGMENT + "{2,})\\.(" + SEGMENT + "*)(?![\\w-])");
    private static final Pattern MASKED_SIGNATURE = Pattern.compile("REDACTED_SIG_[0-9a-f]{8}");
    static final String MASKED_PAYLOAD = "REDACTED_PAYLOAD";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.JWT;
    }

    @Override
    List<Span> spans(String text) {
        List<Span> spans = new ArrayList<>();
        if (text.indexOf("eyJ") < 0) {
            return spans;
        }
        Matcher jwe = JWE.matcher(text);
        while (jwe.find()) {
            spans.add(new Span(jwe.start(), jwe.end(), EntityType.JWT, "JWE"));
        }
        Matcher jws = JWS.matcher(text);
        while (jws.find()) {
            if (!isMasked(jws.group(2), jws.group(3))) {
                spans.add(new Span(jws.start(), jws.end(), EntityType.JWT, "JWT"));
            }
        }
        return spans;
    }

    @Override
    String replacement(String value, Span span, Fingerprinter fingerprinter) {
        if (span.kind().equals("JWE")) {
            return Placeholder.of("JWE", value, fingerprinter);
        }
        String[] parts = value.split("\\.", -1);
        String payload = maskPayload(parts[1], fingerprinter).orElse(MASKED_PAYLOAD);
        return parts[0] + "." + payload + ".REDACTED_SIG_" + fingerprinter.shortId(value);
    }

    /** Re-encodes the payload with every non-kept claim value replaced by a placeholder. */
    private static Optional<String> maskPayload(String segment, Fingerprinter fingerprinter) {
        return decodeObject(segment).map(claims -> {
            Map<String, Object> masked = new LinkedHashMap<>();
            for (Map.Entry<String, Object> claim : claims.entrySet()) {
                Object value = claim.getValue();
                masked.put(claim.getKey(), keep(claim.getKey(), value)
                        ? value
                        : Placeholder.of("CLAIM", MiniJson.write(value), fingerprinter));
            }
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(MiniJson.write(masked).getBytes(StandardCharsets.UTF_8));
        });
    }

    private static boolean keep(String claim, Object value) {
        return KEPT_CLAIMS.contains(claim) || value instanceof Boolean || value == MiniJson.NULL
                || (value instanceof String s && Placeholder.is(s));
    }

    /** A token we produced: masked signature and a payload without unmasked claims. */
    private static boolean isMasked(String payload, String signature) {
        if (!MASKED_SIGNATURE.matcher(signature).matches()) {
            return false;
        }
        if (payload.equals(MASKED_PAYLOAD)) {
            return true;
        }
        return decodeObject(payload).map(claims -> claims.entrySet().stream()
                .allMatch(claim -> keep(claim.getKey(), claim.getValue()))).orElse(false);
    }

    @SuppressWarnings("unchecked")
    private static Optional<Map<String, Object>> decodeObject(String segment) {
        try {
            String json = new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8);
            return MiniJson.parse(json).filter(Map.class::isInstance).map(object -> (Map<String, Object>) object);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
