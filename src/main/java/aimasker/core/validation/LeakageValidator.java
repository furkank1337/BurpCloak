package aimasker.core.validation;

import aimasker.core.Base64Tokens;
import aimasker.core.Detection;
import aimasker.core.RedactionEngine;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Second, independent line of defence: scans the exact text that is about to be sent to an AI
 * and reports whether any sensitive value is still recognisable.
 *
 * <p>Besides the text itself it scans decoded views (percent-decoding, HTML references,
 * JavaScript escapes, UTF-16 and base64 tokens) so that a value the redactor could not rewrite
 * in place, such as {@code nday%2Eblog} written with an encoded letter, still blocks the message.
 * Any internal error yields {@link Verdict#UNKNOWN}, which blocks transmission.
 */
public final class LeakageValidator {

    /** Messages above this size are not scanned and therefore blocked. */
    public static final int MAX_SCAN_CHARS = 50 * 1024 * 1024;
    private static final int MAX_BASE64_TOKENS = 200_000;

    private final RedactionEngine engine;

    public LeakageValidator(RedactionEngine engine) {
        this.engine = engine;
    }

    public ValidationResult validate(String text) {
        try {
            return scan(text);
        } catch (RuntimeException | StackOverflowError e) {
            return new ValidationResult(Verdict.UNKNOWN,
                    List.of("Leakage validator failed (" + e.getClass().getSimpleName() + "); blocking."));
        }
    }

    private ValidationResult scan(String text) {
        if (text == null) {
            return new ValidationResult(Verdict.UNKNOWN, List.of("Nothing to validate; blocking."));
        }
        if (text.length() > MAX_SCAN_CHARS) {
            return new ValidationResult(Verdict.UNKNOWN,
                    List.of("Message too large to validate (" + text.length() + " chars); blocking."));
        }
        Map<String, String> views = new LinkedHashMap<>();
        views.put("raw", text);
        views.put("url-decoded", TextViews.urlDecodeFully(text));
        views.put("html-decoded", TextViews.htmlDecode(text));
        views.put("js-unescaped", TextViews.jsUnescape(text));
        String combined = text;
        for (int round = 0; round < 2; round++) {
            combined = TextViews.urlDecodeFully(TextViews.htmlDecode(TextViews.jsUnescape(combined)));
        }
        views.put("fully-decoded", combined);
        if (text.indexOf('\0') >= 0) {
            views.put("utf16-stripped", text.replace("\0", ""));
        }

        List<Base64Tokens.Token> tokens = new ArrayList<>(Base64Tokens.find(text));
        if (!combined.equals(text)) {
            tokens.addAll(Base64Tokens.find(combined));
        }
        if (tokens.size() > MAX_BASE64_TOKENS) {
            return new ValidationResult(Verdict.UNKNOWN,
                    List.of("Too many encoded tokens to validate; blocking."));
        }
        StringBuilder decoded = new StringBuilder();
        for (Base64Tokens.Token token : tokens) {
            decoded.append(token.decoded()).append('\n');
            for (Base64Tokens.Token nested : Base64Tokens.find(token.decoded())) {
                decoded.append(nested.decoded()).append('\n');
            }
        }
        if (!decoded.isEmpty()) {
            String base64View = decoded.toString();
            views.put("base64-decoded", base64View);
            views.put("base64-decoded+unescaped", TextViews.jsUnescape(base64View));
        }

        List<String> reasons = new ArrayList<>();
        for (Map.Entry<String, String> view : views.entrySet()) {
            List<Detection> detections = engine.detect(view.getValue());
            if (!detections.isEmpty()) {
                reasons.add("Sensitive " + detections.get(0).type() + " value still present after redaction ("
                        + detections.size() + " occurrence(s), view: " + view.getKey() + ").");
            }
        }
        return reasons.isEmpty()
                ? new ValidationResult(Verdict.SAFE, List.of())
                : new ValidationResult(Verdict.LEAKAGE, reasons);
    }
}
