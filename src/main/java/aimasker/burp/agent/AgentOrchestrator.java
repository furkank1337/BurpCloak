package aimasker.burp.agent;

import aimasker.burp.Replayer;
import aimasker.burp.opencode.OpenCodeClient;
import aimasker.core.config.AgentSettings;
import aimasker.core.gateway.AiSafeGateway;
import aimasker.core.gateway.AiSafePayload;
import aimasker.core.gateway.GatewayDecision;
import aimasker.core.gateway.HttpExchange;
import aimasker.core.http.MessageKind;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Runs one AI-driven analysis session as a closed loop:
 *
 * <pre>
 * mask exchange -> OpenCode -> parse -> (replay? unmask, send to target, re-mask response) -> OpenCode -> ...
 *                                     -> (verdict? done)
 * </pre>
 *
 * <p>Every message handed to OpenCode goes through {@link AiSafeGateway} (reversible mode) and
 * its leakage validator, so raw customer data never leaves Burp. Replays always go to the
 * session's locked host/port/TLS, so the AI cannot steer traffic off-scope. The loop stops on a
 * verdict, on the iteration cap, on the kill switch, or on any error (fail-closed).
 */
public final class AgentOrchestrator {

    /** Receives progress for the UI transcript. All strings are masked / customer-data-free. */
    public interface Listener {
        void onStatus(String status);

        void onMaskedToAi(String text);

        void onAiReply(String text);

        /**
         * A replay happened. {@code unmaskedRequest} is the real request sent to the target (local
         * display only); {@code responseSummary} says what the target returned (status + size, or
         * that nothing came back).
         */
        void onReplay(int iteration, String unmaskedRequest, long elapsedMillis, String responseSummary);

        /**
         * Final conclusion. {@code pocRequest}/{@code pocResponse} are the last replayed exchange
         * (the proof-of-concept) in real/unmasked bytes, or {@code null} if nothing was replayed.
         */
        void onVerdict(String status, String title, String summary, String evidence,
                       byte[] pocRequest, byte[] pocResponse);

        void onError(String message);

        void onFinished();
    }

    private final AiSafeGateway gateway;
    private final Replayer replayer;
    private volatile boolean stopped;

    public AgentOrchestrator(AiSafeGateway gateway, Replayer replayer) {
        this.gateway = gateway;
        this.replayer = replayer;
    }

    /** Requests the running session to stop as soon as it reaches a safe point. */
    public void stop() {
        stopped = true;
    }

    /** Blocking; run on a worker thread, never on the Swing event thread. */
    public void run(HttpExchange start, String userPrompt, AgentSettings settings, Listener listener) {
        stopped = false;
        try {
            runLoop(start, userPrompt, settings, listener);
        } catch (OpenCodeClient.OpenCodeException e) {
            listener.onError(e.getMessage());
        } catch (RuntimeException e) {
            listener.onError("Session failed (" + e.getClass().getSimpleName() + ").");
        } finally {
            listener.onFinished();
        }
    }

    private void runLoop(HttpExchange start, String userPrompt, AgentSettings settings, Listener listener) {
        listener.onStatus("Masking the initial exchange…");
        GatewayDecision promptDecision = gateway.prepareText("TASK: " + userPrompt, true);
        if (!promptDecision.allowed()) {
            listener.onError("Prompt blocked: " + promptDecision.reasons());
            return;
        }
        GatewayDecision exchangeDecision = gateway.prepareExchange(start, true);
        if (!exchangeDecision.allowed()) {
            listener.onError("Initial exchange blocked, nothing sent: " + exchangeDecision.reasons());
            return;
        }
        GatewayDecision first = gateway.compose("\n\n--- MASKED HTTP EXCHANGE ---\n\n",
                promptDecision.payload().orElseThrow(), exchangeDecision.payload().orElseThrow());
        if (!first.allowed()) {
            listener.onError("Combined message blocked, nothing sent: " + first.reasons());
            return;
        }
        if (stopped) {
            listener.onStatus("Stopped before sending.");
            return;
        }

        OpenCodeClient client = new OpenCodeClient(settings);
        listener.onStatus("Creating OpenCode session…");
        String sessionId = client.createSession("cloak-" + UUID.randomUUID());

        String systemPrompt = settings.rules().isBlank() ? AgentProtocol.SYSTEM : settings.rules();
        String userText = first.payload().orElseThrow().text();
        listener.onMaskedToAi(userText);
        String reply = client.sendMessage(sessionId, systemPrompt, userText);
        listener.onAiReply(reply);

        int iteration = 0;
        int reminders = 0;
        byte[] pocRequest = null;
        byte[] pocResponse = null;
        while (!stopped && iteration < settings.maxIterations()) {
            AgentProtocol.Parsed parsed = AgentProtocol.parse(reply);
            if (parsed.kind() == AgentProtocol.Kind.VERDICT) {
                listener.onVerdict(parsed.verdictStatus(), parsed.verdictTitle(), parsed.verdictSummary(),
                        parsed.verdictEvidence(), pocRequest, pocResponse);
                return;
            }
            if (parsed.kind() == AgentProtocol.Kind.NONE) {
                if (++reminders > 2) {
                    listener.onStatus("No actionable reply after reminders; stopping.");
                    return;
                }
                reply = client.sendMessage(sessionId, null, AgentProtocol.REMINDER);
                listener.onAiReply(reply);
                continue;
            }

            iteration++;
            listener.onStatus("Iteration " + iteration + "/" + settings.maxIterations());
            if (iteration > 1 && settings.rateLimitMs() > 0) {
                sleep(settings.rateLimitMs());
            }
            if (stopped) {
                break;
            }

            String nextUserText;
            try {
                byte[] realRequest = aimasker.burp.HttpNormalizer.normalize(gateway.unmask(parsed.replayRequest()));
                Replayer.ReplayResult result =
                        replayer.replay(realRequest, start.host(), start.port(), start.secure());
                pocRequest = realRequest;
                pocResponse = result.hasResponse() ? result.response() : null;
                String responseSummary = result.hasResponse()
                        ? "target responded: " + statusLine(result.response()) + " (" + result.response().length + " bytes)"
                        : "NO RESPONSE from target after " + result.elapsedMillis() + " ms (timeout/unreachable/"
                                + "wrong scheme). Sent to " + start.serviceUrl();
                listener.onReplay(iteration, new String(realRequest, StandardCharsets.ISO_8859_1),
                        result.elapsedMillis(), responseSummary);
                nextUserText = buildResponseMessage(result);
            } catch (RuntimeException e) {
                nextUserText = "The replay could not be completed (" + e.getClass().getSimpleName()
                        + "). Decide based on what you have, or propose a different request.";
            }
            if (stopped) {
                break;
            }
            listener.onMaskedToAi(nextUserText);
            reply = client.sendMessage(sessionId, null, nextUserText);
            listener.onAiReply(reply);
        }

        if (stopped) {
            listener.onStatus("Stopped by user.");
        } else {
            listener.onStatus("Reached the iteration limit (" + settings.maxIterations() + ").");
        }
    }

    /** First line (status line) of a raw response, for the local transcript summary. */
    private static String statusLine(byte[] response) {
        String s = new String(response, StandardCharsets.ISO_8859_1);
        int end = s.indexOf('\r');
        if (end < 0) {
            end = s.indexOf('\n');
        }
        return (end < 0 ? s : s.substring(0, end)).strip();
    }

    /**
     * Masks the replayed response and appends plain timing numbers. The full masked body is sent
     * (truncated only by maxPartChars); the final outgoing text is re-validated (fail-closed).
     */
    private String buildResponseMessage(Replayer.ReplayResult result) {
        String timing = "Timing (local clock, not sensitive): request_start_ms=" + result.requestStartMillis()
                + " response_end_ms=" + result.responseEndMillis() + " elapsed_ms=" + result.elapsedMillis();
        if (!result.hasResponse()) {
            return "The target returned no response.\n\n" + timing;
        }
        GatewayDecision responseDecision = gateway.prepareMessage(result.response(), MessageKind.RESPONSE, true);
        if (!responseDecision.allowed()) {
            // Fail-closed: never forward a response that could not be fully masked.
            return "The target's response could not be shared safely (blocked: " + responseDecision.reasons()
                    + "). Provide your verdict based on the information so far, or propose another request.";
        }
        // Send the full masked response (already truncated to maxPartChars). No digesting - the AI
        // needs the real body to spot reflections, errors and other signals.
        String responseText = responseDecision.payload().orElseThrow().text();
        String combined = responseText + "\n\n" + timing;
        GatewayDecision finalDecision = gateway.prepareText(combined, true);
        return finalDecision.allowed() ? finalDecision.payload().orElseThrow().text() : responseText;
    }

    private void sleep(int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            stopped = true;
        }
    }
}
