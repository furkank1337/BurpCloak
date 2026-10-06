package aimasker.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.function.BooleanSupplier;

/**
 * Sends an (already unmasked) raw request to the session's locked target through Burp and
 * captures the response with timing. The target host/port/TLS are fixed by the orchestrator,
 * not taken from the AI, so the AI cannot redirect traffic off-scope.
 *
 * <p>Requests go through Burp's HTTP stack, so they appear in Logger. When enabled, each replay
 * is also added to the site map so discovered/tested endpoints show up in Target.
 */
public final class BurpReplayer implements Replayer {

    private final MontoyaApi api;
    private final BurpSink sink;
    private final BooleanSupplier addToSiteMap;

    public BurpReplayer(MontoyaApi api, BurpSink sink, BooleanSupplier addToSiteMap) {
        this.api = api;
        this.sink = sink;
        this.addToSiteMap = addToSiteMap;
    }

    @Override
    public ReplayResult replay(byte[] rawRequest, String host, int port, boolean secure) {
        HttpService service = HttpService.httpService(host, port, secure);
        HttpRequest request = HttpRequest.httpRequest(service,
                ByteArray.byteArray(new String(rawRequest, StandardCharsets.ISO_8859_1)));
        long start = System.currentTimeMillis();
        HttpRequestResponse result = api.http().sendRequest(request);
        long end = System.currentTimeMillis();
        byte[] response = result.response() == null ? new byte[0] : result.response().toByteArray().getBytes();
        if (addToSiteMap.getAsBoolean()) {
            sink.addToSiteMap(rawRequest, response, host, port, secure);
        }
        return new ReplayResult(response, start, end, end - start);
    }
}
