package aimasker.burp;

/**
 * Sends an already-unmasked raw request to the session's locked target and returns the response
 * with timing. Abstracted from {@link BurpReplayer} so the agent loop can be driven in tests
 * without a running Burp.
 */
public interface Replayer {

    /**
     * @param rawRequest request bytes (ISO-8859-1), already unmasked
     * @param host       locked target host
     * @param port       locked target port
     * @param secure     whether the locked target uses TLS
     */
    ReplayResult replay(byte[] rawRequest, String host, int port, boolean secure);

    /** Raw response bytes plus wall-clock timing around the exchange. */
    record ReplayResult(byte[] response, long requestStartMillis, long responseEndMillis, long elapsedMillis) {
        public boolean hasResponse() {
            return response != null && response.length > 0;
        }
    }
}
