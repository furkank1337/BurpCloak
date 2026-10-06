package aimasker.burp.opencode;

import aimasker.core.MiniJson;
import aimasker.core.config.AgentSettings;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Client for the OpenCode v2 HTTP API ({@code opencode serve}). Burp is the orchestrator: it
 * creates a session, sends a prompt, and polls for the assistant's reply.
 *
 * <p>Endpoints (all under {@code /api}): {@code POST /api/session} to create,
 * {@code POST /api/session/{id}/prompt} to send text (asynchronous), and
 * {@code GET /api/session/{id}/message} to read the assistant reply once it completes.
 * Authentication is HTTP basic ({@code opencode:<password>}). No third-party HTTP/JSON library.
 */
public final class OpenCodeClient {

    /** Process-wide usage counters so the UI can show call volume and rough size. */
    public static final class Usage {
        public static final AtomicLong sessions = new AtomicLong();
        public static final AtomicLong messages = new AtomicLong();
        public static final AtomicLong charsSent = new AtomicLong();
        public static final AtomicLong charsReceived = new AtomicLong();

        private Usage() {
        }

        public static void reset() {
            sessions.set(0);
            messages.set(0);
            charsSent.set(0);
            charsReceived.set(0);
        }

        public static long estimatedTokens() {
            return (charsSent.get() + charsReceived.get()) / 4;
        }
    }

    /** How long to wait for an assistant reply before giving up. */
    private static final long REPLY_TIMEOUT_MS = 300_000;
    private static final long POLL_INTERVAL_MS = 800;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private final AgentSettings settings;

    public OpenCodeClient(AgentSettings settings) {
        this.settings = settings;
    }

    public static final class OpenCodeException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public OpenCodeException(String message) {
            super(message);
        }
    }

    /** Lightweight connection test: {@code GET /api/info}. Throws on any problem. */
    public void ping() {
        get("/api/info");
    }

    /**
     * Lists the models available on this server as {@code provider/modelID} strings (what the
     * "Model" setting expects), from {@code GET /api/model}. Sorted and de-duplicated.
     */
    public List<String> listModels() {
        Object parsed = parse(get("/api/model"), "model");
        java.util.TreeSet<String> models = new java.util.TreeSet<>();
        collectModels(unwrap(parsed), models);
        return List.copyOf(models);
    }

    private static void collectModels(Object node, Set<String> out) {
        if (node instanceof Map<?, ?> map) {
            Object provider = map.get("providerID");
            Object model = map.get("modelID");
            if (provider instanceof String p && model instanceof String m && !p.isBlank() && !m.isBlank()) {
                out.add(p + "/" + m);
            }
            for (Object child : map.values()) {
                if (child instanceof Map || child instanceof List) {
                    collectModels(child, out);
                }
            }
        } else if (node instanceof List<?> list) {
            for (Object child : list) {
                collectModels(child, out);
            }
        }
    }

    /** Creates a session (pinned to the configured model) and returns its id. */
    public String createSession(String title) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("title", title);
        // Pin the model, so the selection in the UI actually takes effect instead of the server
        // default. The v2 model ref is {providerID, id}; our setting is "providerID/modelID".
        String model = settings.opencodeModel();
        int slash = model.indexOf('/');
        if (slash > 0 && slash < model.length() - 1) {
            Map<String, Object> ref = new LinkedHashMap<>();
            ref.put("providerID", model.substring(0, slash));
            ref.put("id", model.substring(slash + 1));
            body.put("model", ref);
        }
        Object parsed = parse(post("/api/session", MiniJson.write(body)), "session");
        Usage.sessions.incrementAndGet();
        return findString(unwrap(parsed), "id")
                .orElseThrow(() -> new OpenCodeException("OpenCode session response had no id."));
    }

    /**
     * Sends one prompt and returns the assistant's reply text. OpenCode generates asynchronously,
     * so this posts the prompt then polls the message list until a new assistant message completes.
     *
     * @param systemText optional contract prepended to the prompt (v2 has no separate system field)
     */
    public String sendMessage(String sessionId, String systemText, String userText) {
        String text = systemText == null || systemText.isBlank()
                ? userText
                : systemText + "\n\n----- TASK -----\n\n" + userText;

        Set<String> before = assistantMessageIds(sessionId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("text", text);
        Usage.messages.incrementAndGet();
        Usage.charsSent.addAndGet(text.length());
        post("/api/session/" + encode(sessionId) + "/prompt", MiniJson.write(body));

        long deadline = System.currentTimeMillis() + REPLY_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            Optional<Object> reply = newCompletedAssistant(sessionId, before);
            if (reply.isPresent()) {
                String out = collectText(reply.get()).strip();
                Usage.charsReceived.addAndGet(out.length());
                if (out.isEmpty()) {
                    throw new OpenCodeException("OpenCode returned an empty reply.");
                }
                return out;
            }
            sleep(POLL_INTERVAL_MS);
        }
        throw new OpenCodeException("Timed out waiting for the OpenCode reply.");
    }

    /** Best-effort SSE partials from {@code GET /api/event}; degrades silently on any difference. */
    public AutoCloseable streamPartials(Consumer<String> onPartial) {
        Thread reader = new Thread(() -> {
            try {
                HttpRequest.Builder b = HttpRequest.newBuilder()
                        .uri(URI.create(settings.opencodeUrl() + "/api/event"))
                        .timeout(Duration.ofSeconds(300))
                        .header("Accept", "text/event-stream").GET();
                auth(b);
                HttpResponse<java.io.InputStream> response =
                        http.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
                try (var br = new java.io.BufferedReader(
                        new java.io.InputStreamReader(response.body(), StandardCharsets.UTF_8))) {
                    String line;
                    while (!Thread.currentThread().isInterrupted() && (line = br.readLine()) != null) {
                        if (line.startsWith("data:")) {
                            MiniJson.parse(line.substring(5).trim()).ifPresent(obj -> {
                                String t = collectText(obj).strip();
                                if (!t.isEmpty()) {
                                    onPartial.accept(t);
                                }
                            });
                        }
                    }
                }
            } catch (Exception ignored) {
                // best-effort
            }
        }, "cloak-opencode-events");
        reader.setDaemon(true);
        reader.start();
        return reader::interrupt;
    }

    // --- message polling --------------------------------------------------------------------

    private Set<String> assistantMessageIds(String sessionId) {
        Set<String> ids = new HashSet<>();
        for (Object m : messages(sessionId)) {
            if (m instanceof Map<?, ?> map && "assistant".equals(map.get("type"))) {
                Object id = map.get("id");
                if (id != null) {
                    ids.add(id.toString());
                }
            }
        }
        return ids;
    }

    /** The newest completed assistant message whose id is not in {@code exclude}. */
    private Optional<Object> newCompletedAssistant(String sessionId, Set<String> exclude) {
        Object latest = null;
        for (Object m : messages(sessionId)) {
            if (m instanceof Map<?, ?> map && "assistant".equals(map.get("type"))) {
                Object id = map.get("id");
                if (id != null && !exclude.contains(id.toString()) && completed(map)) {
                    latest = m;
                }
            }
        }
        return Optional.ofNullable(latest);
    }

    private static boolean completed(Map<?, ?> message) {
        if (message.get("finish") != null) {
            return true;
        }
        Object time = message.get("time");
        return time instanceof Map<?, ?> t && t.get("completed") != null;
    }

    private List<Object> messages(String sessionId) {
        Object parsed = parse(get("/api/session/" + encode(sessionId) + "/message"), "messages");
        Object data = unwrap(parsed);
        return data instanceof List<?> list ? List.copyOf(list) : List.of();
    }

    // --- HTTP -------------------------------------------------------------------------------

    private String post(String path, String jsonBody) {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(settings.opencodeUrl() + path))
                .timeout(Duration.ofSeconds(120))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));
        auth(b);
        return send(b.build());
    }

    private String get(String path) {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(settings.opencodeUrl() + path))
                .timeout(Duration.ofSeconds(30))
                .header("Accept", "application/json").GET();
        auth(b);
        return send(b.build());
    }

    private void auth(HttpRequest.Builder b) {
        if (settings.hasPassword()) {
            String token = Base64.getEncoder().encodeToString(
                    ("opencode:" + settings.opencodePassword()).getBytes(StandardCharsets.UTF_8));
            b.header("Authorization", "Basic " + token);
        }
    }

    private String send(HttpRequest request) {
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (java.io.IOException e) {
            throw new OpenCodeException("Cannot reach OpenCode at " + settings.opencodeUrl()
                    + " (" + e.getClass().getSimpleName() + "). Is 'opencode serve' running and the URL correct?");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OpenCodeException("OpenCode request was interrupted.");
        }
        int code = response.statusCode();
        if (code == 401) {
            throw new OpenCodeException("OpenCode rejected the credentials (401). Check the server password.");
        }
        if (code / 100 != 2) {
            throw new OpenCodeException("OpenCode returned HTTP " + code + " for " + request.uri().getPath()
                    + ". Is this an OpenCode v2 server URL (not the Burp proxy)?");
        }
        return response.body();
    }

    private static Object parse(String json, String what) {
        return MiniJson.parse(json)
                .orElseThrow(() -> new OpenCodeException("OpenCode returned an unreadable " + what + " response."));
    }

    /** OpenCode v2 wraps payloads in {@code {"data": ...}}; return the inner value when present. */
    private static Object unwrap(Object parsed) {
        if (parsed instanceof Map<?, ?> map && map.containsKey("data")) {
            return map.get("data");
        }
        return parsed;
    }

    private static String encode(String segment) {
        return java.net.URLEncoder.encode(segment, StandardCharsets.UTF_8);
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OpenCodeException("Interrupted while waiting for the OpenCode reply.");
        }
    }

    private static Optional<String> findString(Object node, String key) {
        if (node instanceof Map<?, ?> map) {
            Object direct = map.get(key);
            if (direct instanceof String s) {
                return Optional.of(s);
            }
            for (Object child : map.values()) {
                Optional<String> found = findString(child, key);
                if (found.isPresent()) {
                    return found;
                }
            }
        } else if (node instanceof List<?> list) {
            for (Object child : list) {
                Optional<String> found = findString(child, key);
                if (found.isPresent()) {
                    return found;
                }
            }
        }
        return Optional.empty();
    }

    /** Concatenates every {@code {"type":"text","text":...}} part found in the structure. */
    private static String collectText(Object node) {
        StringBuilder out = new StringBuilder();
        collectText(node, out);
        return out.toString();
    }

    private static void collectText(Object node, StringBuilder out) {
        if (node instanceof Map<?, ?> map) {
            if ("text".equals(map.get("type")) && map.get("text") instanceof String s) {
                if (out.length() > 0) {
                    out.append('\n');
                }
                out.append(s);
            }
            for (Object child : map.values()) {
                if (child instanceof Map || child instanceof List) {
                    collectText(child, out);
                }
            }
        } else if (node instanceof List<?> list) {
            for (Object child : list) {
                collectText(child, out);
            }
        }
    }
}
