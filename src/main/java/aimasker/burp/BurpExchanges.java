package aimasker.burp;

import aimasker.core.gateway.HttpExchange;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;

/** Converts Burp message objects into the Burp-independent {@link HttpExchange}. */
final class BurpExchanges {

    private BurpExchanges() {
    }

    static HttpExchange of(HttpRequestResponse requestResponse) {
        HttpService service = requestResponse.httpService();
        if (service == null && requestResponse.request() != null) {
            service = requestResponse.request().httpService();
        }
        String host = service == null || service.host() == null ? "unknown-host" : service.host();
        int port = service == null ? 0 : service.port();
        boolean secure = service != null && service.secure();
        byte[] request = requestResponse.request().toByteArray().getBytes();
        byte[] response = requestResponse.response() == null ? null : requestResponse.response().toByteArray().getBytes();
        return new HttpExchange(host, port, secure, request, response);
    }
}
