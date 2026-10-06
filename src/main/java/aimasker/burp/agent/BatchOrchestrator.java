package aimasker.burp.agent;

import aimasker.burp.Replayer;
import aimasker.burp.opencode.OpenCodeClient;
import aimasker.core.config.AgentSettings;
import aimasker.core.gateway.AiSafeGateway;
import aimasker.core.gateway.GatewayDecision;
import aimasker.core.gateway.HttpExchange;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Whole-target ("batch") analysis in two phases:
 *
 * <ol>
 *   <li><b>Triage</b> - the AI is shown a masked, numbered inventory of all selected endpoints and
 *       the task, and picks which are most worth deep-testing.</li>
 *   <li><b>Deep test</b> - each chosen endpoint is run through the normal {@link AgentOrchestrator}
 *       loop with a lower per-endpoint iteration cap; every vulnerable verdict becomes a finding.</li>
 * </ol>
 *
 * <p>Endpoints are de-duplicated by host + method + path and capped by
 * {@link AgentSettings#maxEndpoints()} so a large site map cannot explode into unbounded traffic.
 * The same masking guarantees and scope-lock as the single-endpoint loop apply throughout.
 */
public final class BatchOrchestrator {

    public interface BatchListener {
        void onStatus(String status);

        void onPhase(String phase);

        void onTranscript(String role, String text);

        void onLocal(String text);

        void onFinding(String endpoint, String status, String title, String summary, HttpExchange exchange,
                       byte[] pocRequest, byte[] pocResponse);

        void onError(String message);

        void onFinished(int endpointsTested, int findings);
    }

    private final AiSafeGateway gateway;
    private final Replayer replayer;
    private volatile boolean stopped;
    private final Set<AgentOrchestrator> running = ConcurrentHashMap.newKeySet();

    public BatchOrchestrator(AiSafeGateway gateway, Replayer replayer) {
        this.gateway = gateway;
        this.replayer = replayer;
    }

    public void stop() {
        stopped = true;
        for (AgentOrchestrator inner : running) {
            inner.stop();
        }
    }

    /**
     * Blocking; run on a worker thread.
     *
     * @param dryRun when true, triage runs and reports the chosen endpoints but no deep testing or
     *               live requests happen
     */
    public void run(List<HttpExchange> exchanges, String prompt, AgentSettings settings, boolean dryRun,
                    BatchListener listener) {
        stopped = false;
        AtomicInteger tested = new AtomicInteger();
        AtomicInteger findings = new AtomicInteger();
        try {
            List<HttpExchange> unique = dedupeAndCap(exchanges, settings.maxEndpoints());
            listener.onStatus("Batch: " + unique.size() + " distinct endpoint(s) after de-duplication.");

            List<HttpExchange> selected = triage(unique, prompt, settings, listener);
            if (dryRun) {
                listener.onStatus("Dry run: triage picked " + selected.size() + " endpoint(s); not testing.");
                for (HttpExchange e : selected) {
                    listener.onTranscript("TRIAGE PICK", endpointLabel(e));
                }
                return;
            }
            listener.onStatus("Deep-testing " + selected.size() + " endpoint(s), parallelism "
                    + settings.parallelism() + ".");

            AgentSettings perEndpoint = settings.withMaxIterations(settings.endpointIterations());
            ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, settings.parallelism()), r -> {
                Thread t = new Thread(r, "cloak-batch");
                t.setDaemon(true);
                return t;
            });
            CountDownLatch latch = new CountDownLatch(selected.size());
            AtomicInteger progress = new AtomicInteger();
            try {
                for (HttpExchange exchange : selected) {
                    pool.submit(() -> {
                        try {
                            if (stopped) {
                                return;
                            }
                            String label = endpointLabel(exchange);
                            listener.onPhase("Testing " + progress.incrementAndGet() + "/" + selected.size()
                                    + ": " + label);
                            tested.incrementAndGet();
                            AgentOrchestrator inner = new AgentOrchestrator(gateway, replayer);
                            running.add(inner);
                            try {
                                Capture capture = new Capture(listener, label);
                                inner.run(exchange, prompt, perEndpoint, capture);
                                if (capture.report) {
                                    findings.incrementAndGet();
                                    listener.onFinding(exchange.serviceUrl() + "  " + label, capture.status,
                                            capture.title, capture.summary, exchange,
                                            capture.pocRequest, capture.pocResponse);
                                }
                            } finally {
                                running.remove(inner);
                            }
                        } catch (RuntimeException e) {
                            listener.onError(endpointLabel(exchange) + ": " + e.getClass().getSimpleName());
                        } finally {
                            latch.countDown();
                        }
                    });
                }
                pool.shutdown();
                latch.await();
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } finally {
                pool.shutdownNow();
            }
        } catch (OpenCodeClient.OpenCodeException e) {
            listener.onError(e.getMessage());
        } catch (RuntimeException e) {
            listener.onError("Batch failed (" + e.getClass().getSimpleName() + ").");
        } finally {
            listener.onFinished(tested.get(), findings.get());
        }
    }

    /** Phase 1: ask the AI which endpoints to test; fall back to all (capped) on any problem. */
    private List<HttpExchange> triage(List<HttpExchange> endpoints, String prompt, AgentSettings settings,
                                      BatchListener listener) {
        listener.onPhase("Triage: prioritising endpoints");
        if (endpoints.size() <= 1) {
            return endpoints;
        }
        StringBuilder inventory = new StringBuilder("TASK: ").append(prompt).append("\n\nENDPOINTS:\n");
        for (int i = 0; i < endpoints.size(); i++) {
            inventory.append(i + 1).append(": ").append(endpointLabel(endpoints.get(i))).append('\n');
        }
        GatewayDecision masked = gateway.prepareText(inventory.toString(), true);
        if (!masked.allowed()) {
            listener.onStatus("Triage input blocked by masking; testing all endpoints (capped).");
            return endpoints;
        }
        try {
            OpenCodeClient client = new OpenCodeClient(settings);
            String sessionId = client.createSession("cloak-triage-" + UUID.randomUUID());
            String text = masked.payload().orElseThrow().text();
            listener.onTranscript("TO AI (triage, masked)", text);
            String reply = client.sendMessage(sessionId, AgentProtocol.TRIAGE_SYSTEM, text);
            listener.onTranscript("AI (triage)", reply);
            List<Integer> picks = AgentProtocol.parseSelect(reply);
            List<HttpExchange> selected = new ArrayList<>();
            for (int index : picks) {
                if (index >= 1 && index <= endpoints.size()) {
                    HttpExchange e = endpoints.get(index - 1);
                    if (!selected.contains(e)) {
                        selected.add(e);
                    }
                }
            }
            if (selected.isEmpty()) {
                listener.onStatus("Triage returned no usable selection; testing all endpoints (capped).");
                return endpoints;
            }
            return selected;
        } catch (RuntimeException e) {
            listener.onStatus("Triage failed (" + e.getClass().getSimpleName() + "); testing all endpoints (capped).");
            return endpoints;
        }
    }

    private static List<HttpExchange> dedupeAndCap(List<HttpExchange> exchanges, int cap) {
        Map<String, HttpExchange> unique = new LinkedHashMap<>();
        for (HttpExchange exchange : exchanges) {
            unique.putIfAbsent(exchange.host() + " " + endpointLabel(exchange), exchange);
            if (unique.size() >= cap) {
                break;
            }
        }
        return new ArrayList<>(unique.values());
    }

    private static String endpointLabel(HttpExchange exchange) {
        String raw = new String(exchange.request(), StandardCharsets.ISO_8859_1);
        int end = raw.indexOf('\r');
        if (end < 0) {
            end = raw.indexOf('\n');
        }
        String first = (end < 0 ? raw : raw.substring(0, end)).strip();
        // "METHOD path HTTP/1.1" -> "METHOD path"
        int lastSpace = first.lastIndexOf(" HTTP/");
        return lastSpace > 0 ? first.substring(0, lastSpace) : first;
    }

    /** Forwards an inner single-endpoint session to the batch listener and captures its verdict. */
    private static final class Capture implements AgentOrchestrator.Listener {
        private final BatchListener listener;
        private final String label;
        private boolean report;
        private String status = "";
        private String title = "";
        private String summary = "";
        private byte[] pocRequest;
        private byte[] pocResponse;

        Capture(BatchListener listener, String label) {
            this.listener = listener;
            this.label = label;
        }

        @Override
        public void onStatus(String s) {
            listener.onStatus(label + ": " + s);
        }

        @Override
        public void onMaskedToAi(String text) {
            listener.onTranscript("TO AI [" + label + "] (masked)", text);
        }

        @Override
        public void onAiReply(String text) {
            listener.onTranscript("AI [" + label + "]", text);
        }

        @Override
        public void onReplay(int iteration, String unmaskedRequest, long elapsedMillis, String responseSummary) {
            listener.onTranscript("REPLAY [" + label + "] #" + iteration, responseSummary + " (" + elapsedMillis + " ms)");
            listener.onLocal("[" + label + "] #" + iteration + " (real request sent to target)\n" + unmaskedRequest
                    + "\n\n<-- " + responseSummary);
        }

        @Override
        public void onVerdict(String s, String t, String sum, String evidence, byte[] poc, byte[] pocResp) {
            this.status = s == null ? "" : s;
            this.title = t == null ? "" : t;
            this.summary = sum == null ? "" : sum;
            this.pocRequest = poc;
            this.pocResponse = pocResp;
            String low = this.status.toLowerCase();
            this.report = low.startsWith("vuln") || low.contains("inconclus");
            listener.onTranscript("VERDICT [" + label + "]", status + " - " + title);
        }

        @Override
        public void onError(String message) {
            listener.onError(label + ": " + message);
        }

        @Override
        public void onFinished() {
            // batch loop advances to the next endpoint
        }
    }
}
