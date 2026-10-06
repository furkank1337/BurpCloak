package aimasker.core.gateway;

/**
 * Burp-independent view of a request/response pair.
 *
 * @param host     target host (from Burp's HttpService)
 * @param port     target port
 * @param secure   whether TLS is used
 * @param request  raw request bytes
 * @param response raw response bytes, or {@code null} when there is no response
 */
public record HttpExchange(String host, int port, boolean secure, byte[] request, byte[] response) {

    public HttpExchange {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
    }

    public String serviceUrl() {
        return (secure ? "https" : "http") + "://" + host + ":" + port;
    }
}
