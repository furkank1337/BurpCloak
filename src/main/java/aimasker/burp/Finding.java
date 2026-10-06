package aimasker.burp;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A vulnerability the AI reported, with enough (real, local) context to reproduce it in Repeater,
 * raise a Burp issue, or export a report. Request/response bytes are the real, unmasked traffic.
 */
public record Finding(
        String time,
        String endpoint,
        String title,
        String status,
        String summary,
        String host,
        int port,
        boolean secure,
        byte[] request,
        byte[] response) {

    public boolean vulnerable() {
        return status != null && status.toLowerCase().startsWith("vuln");
    }

    /** An unconfirmed / "potential" finding (the model's verdict was inconclusive). */
    public boolean potential() {
        return status != null && status.toLowerCase().contains("inconclus");
    }

    Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("time", time);
        m.put("endpoint", endpoint);
        m.put("title", title);
        m.put("status", status);
        m.put("summary", summary);
        m.put("host", host);
        m.put("port", new aimasker.core.MiniJson.Num(Integer.toString(port)));
        m.put("secure", secure);
        m.put("req", Base64.getEncoder().encodeToString(request == null ? new byte[0] : request));
        m.put("resp", Base64.getEncoder().encodeToString(response == null ? new byte[0] : response));
        return m;
    }

    static Finding fromMap(Map<?, ?> m) {
        return new Finding(
                str(m, "time"), str(m, "endpoint"), str(m, "title"), str(m, "status"), str(m, "summary"),
                str(m, "host"), parseInt(m.get("port")), Boolean.TRUE.equals(m.get("secure")),
                decode(str(m, "req")), decode(str(m, "resp")));
    }

    private static String str(Map<?, ?> m, String k) {
        Object v = m.get(k);
        return v == null ? "" : v.toString();
    }

    private static int parseInt(Object v) {
        try {
            return v == null ? 0 : Integer.parseInt(v.toString());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static byte[] decode(String b64) {
        try {
            return b64 == null || b64.isEmpty() ? new byte[0] : Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return new byte[0];
        }
    }
}
