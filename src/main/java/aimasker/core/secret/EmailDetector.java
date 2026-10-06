package aimasker.core.secret;

import aimasker.core.EntityType;
import aimasker.core.audit.Fingerprinter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Masks the local part of e-mail addresses and keeps the domain, which gives useful context
 * (customer domains have already been replaced by the domain detector):
 * {@code jane.doe@nday.blog -> [EMAIL:3f9a1c2b]@redacted.com}.
 */
public final class EmailDetector extends SpanDetector {

    public static final String ID = "email";

    private static final Pattern EMAIL = Pattern.compile(
            "(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@((?:[A-Za-z0-9-]{1,63}\\.)+([A-Za-z]{2,24}))(?![A-Za-z0-9-])");
    /** "logo@2x.png" and similar asset names are not addresses. */
    private static final Set<String> FILE_EXTENSIONS = Set.of(
            "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "bmp", "css", "js", "mjs", "map", "json",
            "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "pdf", "html", "htm", "txt", "xml");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.EMAIL;
    }

    @Override
    List<Span> spans(String text) {
        List<Span> spans = new ArrayList<>();
        if (text.indexOf('@') < 0) {
            return spans;
        }
        Matcher m = EMAIL.matcher(text);
        while (m.find()) {
            String local = m.group(1);
            if (FILE_EXTENSIONS.contains(m.group(3).toLowerCase(Locale.ROOT)) || local.startsWith(".")
                    || local.matches("\\d+(?:\\.\\d+)*")) {
                continue;
            }
            spans.add(new Span(m.start(1), m.end(1), EntityType.EMAIL, "EMAIL"));
        }
        return spans;
    }

    @Override
    String replacement(String value, Span span, Fingerprinter fingerprinter) {
        return Placeholder.of("EMAIL", value.toLowerCase(Locale.ROOT), fingerprinter);
    }
}
