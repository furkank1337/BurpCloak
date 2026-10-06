package aimasker.core.secret;

import aimasker.core.EntityType;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Masks values by the name they are stored under: credentials, tokens, session cookies and
 * personal fields, wherever they appear.
 *
 * <ul>
 *   <li>Headers: {@code Authorization} / {@code Proxy-Authorization} (the scheme is kept),
 *       {@code Cookie} and {@code Set-Cookie} (names and attributes are kept), and any header
 *       whose name contains token, key, secret, session, csrf, password, ...</li>
 *   <li>Query strings and form bodies, including percent-encoded ones nested in other
 *       parameters: {@code password=...}, {@code access_token=...}, {@code %3Ftoken%3D...}</li>
 *   <li>JSON, JavaScript and attributes: {@code "password": "..."}, {@code token = '...'},
 *       also with escaped quotes ({@code \"password\":\"...\"})</li>
 *   <li>XML elements: {@code <password>...</password>}</li>
 *   <li>HTML {@code <input>} / {@code <meta>} fields named like a secret, or of type password</li>
 *   <li>Multipart form fields</li>
 * </ul>
 *
 * JWT-shaped values are left to {@link JwtDetector}, which masks them without destroying
 * their structure.
 */
public final class SensitiveFieldDetector extends SpanDetector {

    public static final String ID = "sensitive-field";

    private final boolean secrets;
    private final boolean personal;
    /** User-defined field names ("extra params"), normalised the same way as built-in names. */
    private final Set<String> customNames;

    /**
     * @param secrets  mask credentials, tokens and cookies
     * @param personal mask personal fields (username, email, phone, ...)
     */
    public SensitiveFieldDetector(boolean secrets, boolean personal) {
        this(secrets, personal, List.of());
    }

    /**
     * @param customNames extra field names to mask wherever they appear as a key, in requests or
     *                    responses; always masked when present, regardless of {@code secrets} /
     *                    {@code personal}
     */
    public SensitiveFieldDetector(boolean secrets, boolean personal, List<String> customNames) {
        this.secrets = secrets;
        this.personal = personal;
        Set<String> normalized = new LinkedHashSet<>();
        for (String name : customNames) {
            String n = SensitiveNames.normalize(name);
            if (!n.isEmpty()) {
                normalized.add(n);
            }
        }
        this.customNames = Set.copyOf(normalized);
    }

    /** Classification of a field name: its placeholder type/kind and whether it is enabled. */
    private record FieldClass(EntityType type, String kind, boolean enabled) {
    }

    private FieldClass classify(String name) {
        if (matchesCustom(name)) {
            return new FieldClass(EntityType.CUSTOM, "CUSTOM", true);
        }
        SensitiveNames.Category category = SensitiveNames.classify(name);
        if (category == null) {
            return null;
        }
        return new FieldClass(type(category), kind(category), enabled(category));
    }

    private boolean matchesCustom(String name) {
        if (customNames.isEmpty()) {
            return false;
        }
        String normalized = SensitiveNames.normalize(name);
        return !normalized.isEmpty() && customNames.contains(normalized);
    }

    private static final Pattern HEADER = Pattern.compile("(?im)^([A-Za-z0-9-]{1,64})[ \\t]*:[ \\t]*(.*?)[ \\t]*$");
    private static final Pattern COOKIE_PAIR = Pattern.compile("(?:^|;)\\s*([^=;\\s]+)=([^;]*)");
    private static final Pattern XML_ELEMENT = Pattern.compile(
            "<([A-Za-z_][A-Za-z0-9_.:-]{0,63})(?:\\s[^<>]*)?>([^<]{1,4096})</\\1\\s*>");
    private static final Pattern FORM_TAG = Pattern.compile("(?i)<(?:input|meta)\\b[^<>]{0,2048}>");
    private static final Pattern TAG_NAME = Pattern.compile("(?i)\\b(?:name|id|property)\\s*=\\s*[\"']?([^\"'\\s>]{1,64})");
    private static final Pattern TAG_PASSWORD = Pattern.compile("(?i)\\btype\\s*=\\s*[\"']?password\\b");
    private static final Pattern TAG_VALUE = Pattern.compile("(?i)\\b(?:value|content)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')");
    private static final Pattern MULTIPART = Pattern.compile(
            "(?i)content-disposition:[^\\r\\n]*?\\bname=\"([^\"]{1,64})\"(?![^\\r\\n]*filename=)[^\\r\\n]*\\r?\\n(?:[^\\r\\n]+\\r?\\n)*\\r?\\n([^\\r\\n]*)");
    private static final Pattern JWT_VALUE = Pattern.compile("eyJ[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]*");
    private static final Pattern PLACEHOLDER_SEQUENCE =
            Pattern.compile("(?:\\s*\\[[A-Z][A-Z0-9_]*(?::[A-Za-z0-9_-]+)?\\]\\s*)+");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.SECRET;
    }

    @Override
    List<Span> spans(String text) {
        List<Span> spans = new ArrayList<>();
        headers(text, spans);
        keyValues(text, spans);
        xml(text, spans);
        formTags(text, spans);
        multipart(text, spans);
        return spans;
    }

    private void headers(String text, List<Span> spans) {
        if ((!secrets && customNames.isEmpty()) || text.indexOf(':') < 0) {
            return;
        }
        Matcher m = HEADER.matcher(text);
        while (m.find()) {
            String name = m.group(1);
            int valueStart = m.start(2);
            String value = m.group(2);
            if (value.isEmpty()) {
                continue;
            }
            if (matchesCustom(name)) {
                add(spans, valueStart, m.end(2), value, EntityType.CUSTOM, "CUSTOM");
            } else if (!secrets) {
                continue;
            } else if (name.equalsIgnoreCase("cookie")) {
                cookiePairs(value, valueStart, false, spans);
            } else if (name.equalsIgnoreCase("set-cookie")) {
                cookiePairs(value, valueStart, true, spans);
            } else if (name.equalsIgnoreCase("authorization") || name.equalsIgnoreCase("proxy-authorization")) {
                int space = value.indexOf(' ');
                boolean hasScheme = space > 0 && value.substring(0, space).matches("[A-Za-z][A-Za-z0-9_-]{1,30}");
                int credentialsStart = hasScheme ? space + 1 : 0;
                while (credentialsStart < value.length() && value.charAt(credentialsStart) == ' ') {
                    credentialsStart++;
                }
                add(spans, valueStart + credentialsStart, m.end(2), value.substring(credentialsStart), EntityType.SECRET, "AUTH");
            } else if (SensitiveNames.isSecretHeader(name)) {
                add(spans, valueStart, m.end(2), value, EntityType.SECRET, "SECRET");
            }
        }
    }

    private void cookiePairs(String value, int offset, boolean setCookie, List<Span> spans) {
        Matcher m = COOKIE_PAIR.matcher(value);
        while (m.find()) {
            String cookieValue = m.group(2).strip();
            int start = offset + m.start(2) + (m.group(2).length() - m.group(2).stripLeading().length());
            add(spans, start, start + cookieValue.length(), cookieValue, EntityType.COOKIE, "COOKIE");
            if (setCookie) {
                return; // only the first pair of Set-Cookie is the cookie; the rest are attributes
            }
        }
    }

    /** A field name found to the left of a separator. */
    private record Key(String name, char quote, boolean escapedQuote, boolean spaced) {
    }

    /**
     * Single pass over every {@code :}, {@code =} and {@code %3D}: reads the name to the left
     * and, when it is sensitive, the value to the right. Covers query strings, form bodies,
     * percent-encoded parameters nested in other parameters, JSON, JavaScript and attributes.
     */
    private void keyValues(String text, List<Span> spans) {
        int n = text.length();
        for (int i = 0; i < n; i++) {
            char c = text.charAt(i);
            int separatorLength;
            boolean equals;
            if (c == ':') {
                separatorLength = 1;
                equals = false;
            } else if (c == '=') {
                separatorLength = 1;
                equals = true;
            } else if (c == '%' && i + 2 < n && text.charAt(i + 1) == '3' && (text.charAt(i + 2) | 0x20) == 'd') {
                separatorLength = 3;
                equals = true;
            } else {
                continue;
            }
            Key key = keyBefore(text, i, equals);
            if (key == null) {
                continue;
            }
            FieldClass fieldClass = classify(key.name);
            if (fieldClass == null || !fieldClass.enabled()) {
                continue;
            }
            int[] value = valueAfter(text, i + separatorLength, key, equals, separatorLength == 3);
            if (value != null) {
                add(spans, value[0], value[1], text.substring(value[0], value[1]), fieldClass.type(), fieldClass.kind());
            }
        }
    }

    private static Key keyBefore(String text, int separator, boolean equals) {
        int j = separator;
        while (j > 0 && (text.charAt(j - 1) == ' ' || text.charAt(j - 1) == '\t')) {
            j--;
        }
        if (j == 0) {
            return null;
        }
        char quote = 0;
        boolean escaped = false;
        int nameEnd = j;
        char last = text.charAt(j - 1);
        if (last == '"' || last == '\'') {
            quote = last;
            escaped = last == '"' && j >= 2 && text.charAt(j - 2) == '\\';
            nameEnd = escaped ? j - 2 : j - 1;
        }
        int nameStart = nameEnd;
        while (nameStart > 0 && nameEnd - nameStart < 96) {
            char ch = text.charAt(nameStart - 1);
            if (isNameChar(ch)) {
                nameStart--;
            } else if (nameStart >= 3 && text.charAt(nameStart - 3) == '%' && text.charAt(nameStart - 2) == '5'
                    && "BbDd".indexOf(ch) >= 0) {
                nameStart -= 3; // percent-encoded [ or ]
            } else {
                break;
            }
        }
        if (nameStart == nameEnd) {
            return null;
        }
        if (quote != 0) {
            if (nameStart < 1 || text.charAt(nameStart - 1) != quote
                    || (escaped && (nameStart < 2 || text.charAt(nameStart - 2) != '\\'))) {
                return null;
            }
        } else if (nameStart >= 1 && text.charAt(nameStart - 1) == '%' && nameEnd - nameStart > 2
                && Character.digit(text.charAt(nameStart), 16) >= 0 && Character.digit(text.charAt(nameStart + 1), 16) >= 0) {
            nameStart += 2; // the hex digits of a preceding escape such as %3F or %26
        } else if (!equals && !Character.isLetter(text.charAt(nameStart)) && text.charAt(nameStart) != '_'
                && text.charAt(nameStart) != '$') {
            return null; // "12:30" and similar are not keys
        }
        return new Key(text.substring(nameStart, nameEnd), quote, escaped, j < separator);
    }

    private static boolean isNameChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '_' || c == '-' || c == '.' || c == '$' || c == '[' || c == ']';
    }

    /** Returns {@code {start, end}} of the value, or {@code null} when there is none. */
    private static int[] valueAfter(String text, int pos, Key key, boolean equals, boolean encodedSeparator) {
        int n = text.length();
        int k = pos;
        if (!encodedSeparator) {
            while (k < n && (text.charAt(k) == ' ' || text.charAt(k) == '\t')) {
                k++;
            }
        }
        boolean spaced = key.spaced || k > pos;
        if (k >= n) {
            return null;
        }
        if (key.escapedQuote) {
            if (!text.startsWith("\\\"", k)) {
                return null;
            }
            int close = text.indexOf("\\\"", k + 2);
            return close < 0 || close - k > 4096 || text.substring(k + 2, close).indexOf('\n') >= 0
                    ? null : new int[] {k + 2, close};
        }
        char c = text.charAt(k);
        if (c == '"' || c == '\'') {
            for (int e = k + 1; e < n && e - k <= 4096; e++) {
                char ch = text.charAt(e);
                if (ch == '\\') {
                    e++;
                } else if (ch == '\n' || ch == '\r') {
                    return null;
                } else if (ch == c) {
                    return new int[] {k + 1, e};
                }
            }
            return null;
        }
        if (equals) {
            // Unquoted values only in query/form style ("a=b&c=d"); "token = getToken()" is code.
            if (spaced) {
                return null;
            }
            int e = k;
            while (e < n && "&#\"'<>; \t\r\n".indexOf(text.charAt(e)) < 0 && !encodedDelimiterAt(text, e)) {
                e++;
            }
            if (e == k || text.substring(k, e).indexOf('(') >= 0) {
                return null;
            }
            return new int[] {k, e};
        }
        int e = k;
        if (e < n && text.charAt(e) == '-') {
            e++;
        }
        int digits = e;
        while (e < n && Character.isDigit(text.charAt(e)) && e - digits < 40) {
            e++;
        }
        if (e == digits) {
            return null;
        }
        if (e + 1 < n && text.charAt(e) == '.' && Character.isDigit(text.charAt(e + 1))) {
            e++;
            while (e < n && Character.isDigit(text.charAt(e))) {
                e++;
            }
        }
        if (e < n && (Character.isLetterOrDigit(text.charAt(e)) || text.charAt(e) == '_' || text.charAt(e) == '.')) {
            return null;
        }
        return new int[] {k, e};
    }

    /** {@code %26} (&), {@code %3B} (;) or {@code %23} (#) end an encoded parameter value. */
    private static boolean encodedDelimiterAt(String text, int i) {
        if (i + 2 >= text.length() || text.charAt(i) != '%') {
            return false;
        }
        char a = text.charAt(i + 1);
        char b = (char) (text.charAt(i + 2) | 0x20);
        return (a == '2' && (b == '6' || b == '3')) || (a == '3' && b == 'b');
    }

    private void xml(String text, List<Span> spans) {
        if (text.indexOf("</") < 0) {
            return;
        }
        Matcher m = XML_ELEMENT.matcher(text);
        while (m.find()) {
            String name = m.group(1);
            int colon = name.indexOf(':');
            addNamed(spans, colon >= 0 ? name.substring(colon + 1) : name, m.start(2), m.end(2), m.group(2));
        }
    }

    private void formTags(String text, List<Span> spans) {
        Matcher tag = FORM_TAG.matcher(text);
        while (tag.find()) {
            String markup = tag.group();
            Matcher name = TAG_NAME.matcher(markup);
            FieldClass fieldClass = null;
            while (name.find() && fieldClass == null) {
                fieldClass = classify(name.group(1));
            }
            if (fieldClass == null && TAG_PASSWORD.matcher(markup).find()) {
                fieldClass = new FieldClass(EntityType.SECRET, "SECRET", secrets);
            }
            if (fieldClass == null || !fieldClass.enabled()) {
                continue;
            }
            Matcher value = TAG_VALUE.matcher(markup);
            if (value.find()) {
                int group = value.group(1) != null ? 1 : 2;
                add(spans, tag.start() + value.start(group), tag.start() + value.end(group), value.group(group),
                        fieldClass.type(), fieldClass.kind());
            }
        }
    }

    private void multipart(String text, List<Span> spans) {
        if (text.indexOf("ontent-") < 0 && text.indexOf("ONTENT-") < 0) {
            return;
        }
        Matcher m = MULTIPART.matcher(text);
        while (m.find()) {
            addNamed(spans, m.group(1), m.start(2), m.end(2), m.group(2));
        }
    }

    private boolean enabled(SensitiveNames.Category category) {
        return category == SensitiveNames.Category.SECRET ? secrets : personal;
    }

    private void addNamed(List<Span> spans, String name, int start, int end, String value) {
        FieldClass fieldClass = classify(name);
        if (fieldClass != null && fieldClass.enabled()) {
            add(spans, start, end, value, fieldClass.type(), fieldClass.kind());
        }
    }

    private static void add(List<Span> spans, int start, int end, String value, EntityType type, String kind) {
        String trimmed = value.strip();
        if (trimmed.isEmpty() || trimmed.equals("null") || trimmed.equals("undefined")
                || trimmed.equals("true") || trimmed.equals("false")
                || JWT_VALUE.matcher(trimmed).matches()
                || PLACEHOLDER_SEQUENCE.matcher(trimmed).matches()) {
            return;
        }
        spans.add(new SpanDetector.Span(start, end, type, kind));
    }

    private static EntityType type(SensitiveNames.Category category) {
        return category == SensitiveNames.Category.SECRET ? EntityType.SECRET : EntityType.PERSONAL;
    }

    private static String kind(SensitiveNames.Category category) {
        return category == SensitiveNames.Category.SECRET ? "SECRET" : "PERSONAL";
    }
}
