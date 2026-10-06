package aimasker.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Bridges Cloak findings and traffic into Burp's own Target views: the site map, audit issues,
 * and Repeater. All inputs here are UNMASKED (real) data, used only locally inside Burp. Every
 * method is best-effort and never throws into the caller.
 */
public final class BurpSink {

    private final MontoyaApi api;

    public BurpSink(MontoyaApi api) {
        this.api = api;
    }

    /** Adds a replayed (real) request/response to Burp's site map so the endpoint shows in Target. */
    public void addToSiteMap(byte[] rawRequest, byte[] rawResponse, String host, int port, boolean secure) {
        try {
            api.siteMap().add(requestResponse(rawRequest, rawResponse, host, port, secure));
        } catch (RuntimeException e) {
            api.logging().logToError("[Cloak] site map add failed: " + e.getClass().getSimpleName());
        }
    }

    /** Opens the (unmasked) request in Burp Repeater for manual verification. */
    public void sendToRepeater(byte[] rawRequest, String host, int port, boolean secure, String name) {
        try {
            HttpService service = HttpService.httpService(host, port, secure);
            HttpRequest request = HttpRequest.httpRequest(service,
                    ByteArray.byteArray(new String(HttpNormalizer.normalize(rawRequest), StandardCharsets.ISO_8859_1)));
            api.repeater().sendToRepeater(request, name);
        } catch (RuntimeException e) {
            api.logging().logToError("[Cloak] send to Repeater failed: " + e.getClass().getSimpleName());
        }
    }

    /** Registers a vulnerable finding as a Burp audit issue (shows in Target -> Issues / Dashboard). */
    public void reportIssue(String title, String detail, boolean high,
                            byte[] rawRequest, byte[] rawResponse, String host, int port, boolean secure) {
        try {
            HttpRequestResponse rr = requestResponse(rawRequest, rawResponse, host, port, secure);
            String baseUrl = (secure ? "https" : "http") + "://" + host + ":" + port + "/";
            AuditIssueSeverity severity = high ? AuditIssueSeverity.HIGH : AuditIssueSeverity.INFORMATION;
            AuditIssue issue = AuditIssue.auditIssue(
                    "Cloak (AI): " + title,
                    detail,
                    null,
                    baseUrl,
                    severity,
                    AuditIssueConfidence.TENTATIVE,
                    "Reported by the Cloak AI agent. Confirm manually before acting.",
                    null,
                    severity,
                    List.of(rr));
            api.siteMap().add(issue);
        } catch (RuntimeException e) {
            api.logging().logToError("[Cloak] issue report failed: " + e.getClass().getSimpleName());
        }
    }

    private static HttpRequestResponse requestResponse(byte[] rawRequest, byte[] rawResponse,
                                                       String host, int port, boolean secure) {
        HttpService service = HttpService.httpService(host, port, secure);
        HttpRequest request = HttpRequest.httpRequest(service,
                ByteArray.byteArray(new String(rawRequest, StandardCharsets.ISO_8859_1)));
        if (rawResponse == null || rawResponse.length == 0) {
            return HttpRequestResponse.httpRequestResponse(request, null);
        }
        HttpResponse response = HttpResponse.httpResponse(
                ByteArray.byteArray(new String(rawResponse, StandardCharsets.ISO_8859_1)));
        return HttpRequestResponse.httpRequestResponse(request, response);
    }
}
