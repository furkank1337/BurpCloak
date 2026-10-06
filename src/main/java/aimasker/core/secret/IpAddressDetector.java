package aimasker.core.secret;

import aimasker.core.EntityType;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Masks IPv4 and IPv6 addresses. Private and public IPv4 addresses get different placeholders
 * ({@code [IP_PRIVATE:...]}, {@code [IP_PUBLIC:...]}) since the distinction matters for testing.
 * Loopback, unspecified and broadcast addresses are left alone.
 */
public final class IpAddressDetector extends SpanDetector {

    public static final String ID = "ip";

    private static final String OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
    private static final Pattern IPV4 = Pattern.compile(
            "(?<![\\d.])(" + OCTET + ")\\.(" + OCTET + ")\\.(" + OCTET + ")\\.(" + OCTET + ")(?!\\.?\\d)");
    private static final String HEX = "[0-9A-Fa-f]{1,4}";
    /** Full eight-group form, or a compressed form containing "::". */
    private static final Pattern IPV6 = Pattern.compile(
            "(?<![\\w:.])(?:(?:" + HEX + ":){7}" + HEX
            + "|(?:" + HEX + "(?::" + HEX + "){0,6})?::(?:" + HEX + "(?::" + HEX + "){0,6})?)(?![\\w:])");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.IP;
    }

    @Override
    List<Span> spans(String text) {
        List<Span> spans = new ArrayList<>();
        Matcher v4 = IPV4.matcher(text);
        int from = nextDottedDigits(text, 0);
        while (from >= 0 && from < text.length() && v4.find(from)) {
            int next = nextDottedDigits(text, v4.end());
            from = next < 0 ? -1 : Math.max(next, v4.end());
            int a = Integer.parseInt(v4.group(1));
            int b = Integer.parseInt(v4.group(2));
            String address = v4.group();
            if (a == 127 || address.equals("0.0.0.0") || address.equals("255.255.255.255")) {
                continue;
            }
            spans.add(new Span(v4.start(), v4.end(), EntityType.IP, isPrivate(a, b) ? "IP_PRIVATE" : "IP_PUBLIC"));
        }
        ipv6(text, spans);
        return spans;
    }

    /**
     * Start of the next run that could begin an IPv4 address ("d.d"), or -1. Lets the regex
     * skip text without dotted digits instead of being tried at every position.
     */
    private static int nextDottedDigits(String text, int from) {
        for (int i = text.indexOf('.', from); i >= 0; i = text.indexOf('.', i + 1)) {
            if (i > 0 && i + 1 < text.length() && Character.isDigit(text.charAt(i - 1))
                    && Character.isDigit(text.charAt(i + 1))) {
                int start = i - 1;
                while (start > from && start > i - 3 && Character.isDigit(text.charAt(start - 1))) {
                    start--;
                }
                return start;
            }
        }
        return -1;
    }

    /** Expands each ':' into the surrounding run of hex digits and colons, then validates it. */
    private static void ipv6(String text, List<Span> spans) {
        int n = text.length();
        int covered = -1;
        for (int i = text.indexOf(':'); i >= 0; i = text.indexOf(':', i + 1)) {
            if (i < covered) {
                continue;
            }
            int start = i;
            while (start > 0 && isHexOrColon(text.charAt(start - 1))) {
                start--;
            }
            int end = i + 1;
            while (end < n && isHexOrColon(text.charAt(end))) {
                end++;
            }
            covered = end;
            Matcher v6 = IPV6.matcher(text).region(start, end).useTransparentBounds(true).useAnchoringBounds(false);
            while (v6.find()) {
                if (plausibleIpv6(v6.group())) {
                    spans.add(new Span(v6.start(), v6.end(), EntityType.IP, "IPV6"));
                }
            }
        }
    }

    private static boolean isHexOrColon(char c) {
        return c == ':' || Character.digit(c, 16) >= 0;
    }

    private static boolean isPrivate(int a, int b) {
        return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)
                || (a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127);
    }

    /**
     * Filters out loopback/unspecified and things like CSS "a::b": a compressed address needs
     * at least three groups, or a first group of three or more hex digits (fe80::1, 2001::5).
     */
    private static boolean plausibleIpv6(String candidate) {
        if (!candidate.contains("::")) {
            return true;
        }
        String[] groups = candidate.split(":+", -1);
        int nonEmpty = 0;
        for (String group : groups) {
            if (!group.isEmpty()) {
                nonEmpty++;
            }
        }
        if (nonEmpty == 0 || candidate.equals("::1")) {
            return false;
        }
        return nonEmpty >= 3 || groups[0].length() >= 3;
    }
}
