package aimasker.core.secret;

import aimasker.core.EntityType;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Masks UUID / GUID values (e.g. {@code 550e8400-e29b-41d4-a716-446655440000}). These are often
 * object identifiers, session ids or account references, so they are useful to correlate (the
 * same id maps to the same token) while being hidden from the AI. The all-zero nil UUID is left
 * alone as it carries no information.
 */
public final class UuidDetector extends SpanDetector {

    public static final String ID = "uuid";

    private static final Pattern UUID = Pattern.compile(
            "(?<![0-9A-Fa-f-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Fa-f-])");
    private static final String NIL = "00000000-0000-0000-0000-000000000000";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.CUSTOM;
    }

    @Override
    List<Span> spans(String text) {
        List<Span> spans = new ArrayList<>();
        if (text.indexOf('-') < 0) {
            return spans;
        }
        Matcher m = UUID.matcher(text);
        while (m.find()) {
            if (!m.group().equalsIgnoreCase(NIL)) {
                spans.add(new Span(m.start(), m.end(), EntityType.CUSTOM, "UUID"));
            }
        }
        return spans;
    }
}
