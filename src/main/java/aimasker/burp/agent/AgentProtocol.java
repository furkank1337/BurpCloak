package aimasker.burp.agent;

import aimasker.core.MiniJson;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The strict contract the AI must follow, and a tolerant parser for its replies.
 *
 * <p>Each reply must contain exactly one fenced block: a {@code replay} block with a raw HTTP
 * request to send, or a {@code verdict} block with a JSON conclusion. Everything the AI sees is
 * masked; it must preserve pseudonyms verbatim.
 */
public final class AgentProtocol {

    public static final String SYSTEM = String.join("\n",
            "You are assisting an authorized penetration tester through a local masking gateway.",
            "All customer identifiers in the material have been replaced locally before you see them:",
            "hostnames such as *.redacted.com, and tokens such as [COOKIE:...], [AUTH:...] or",
            "[REDACTED_DOMAIN], are pseudonyms. Keep every pseudonym EXACTLY as-is; never try to",
            "resolve, guess, decode or de-anonymize them, and do not invent new ones.",
            "",
            "You are analyzing a single HTTP request/response pair. Your task is stated in the first",
            "user message. Work iteratively.",
            "",
            "To TEST something, reply with EXACTLY ONE fenced block containing a complete raw HTTP",
            "request to send, modifying only the parts you intend to test (for example injecting a",
            "payload into a parameter value) and keeping all pseudonyms unchanged:",
            "```replay",
            "<raw HTTP request>",
            "```",
            "The gateway sends it to the real target and returns the masked response as the next",
            "message. Some bodies may be truncated or omitted; say so if it limits your analysis.",
            "",
            "When you reach a conclusion, reply with EXACTLY ONE fenced block:",
            "```verdict",
            "{\"status\":\"vulnerable|not_vulnerable|inconclusive\",\"title\":\"short name, e.g. Reflected XSS\","
                    + "\"summary\":\"one or two sentences, concise\",\"evidence\":\"...\"}",
            "```",
            "",
            "Rules: exactly one block per message; keep 'title' to a few words and 'summary' short; "
                    + "no commentary is needed outside the block.");

    static final String REMINDER = "Your previous message did not contain exactly one valid ```replay``` "
            + "or ```verdict``` block. Reply with exactly one such block, keeping all pseudonyms unchanged.";

    /** Batch triage: the AI prioritises which endpoints to deep-test, by index. */
    public static final String TRIAGE_SYSTEM = String.join("\n",
            "You are triaging a web target for an authorized penetration tester through a masking gateway.",
            "All identifiers are masked pseudonyms; keep them as-is and do not try to de-anonymize them.",
            "You are given a numbered inventory of endpoints and a task. Pick the endpoints most worth",
            "deep-testing for that task, highest priority first.",
            "Reply with EXACTLY ONE fenced block containing their numbers, comma-separated:",
            "```select",
            "3, 7, 12",
            "```",
            "Select only plausible candidates; it is fine to choose few.");

    private static final Pattern REPLAY = Pattern.compile("(?s)```replay\\s*\\R(.*?)```");
    private static final Pattern VERDICT = Pattern.compile("(?s)```verdict\\s*\\R(.*?)```");
    private static final Pattern SELECT = Pattern.compile("(?s)```select\\s*\\R(.*?)```");

    private AgentProtocol() {
    }

    enum Kind { REPLAY, VERDICT, NONE }

    record Parsed(Kind kind, String replayRequest, String verdictStatus, String verdictTitle,
                  String verdictSummary, String verdictEvidence) {
        static Parsed none() {
            return new Parsed(Kind.NONE, null, null, null, null, null);
        }
    }

    static Parsed parse(String reply) {
        Matcher verdict = VERDICT.matcher(reply);
        if (verdict.find()) {
            String json = verdict.group(1).strip();
            String status = "inconclusive";
            String title = "";
            String summary = json;
            String evidence = "";
            Optional<Object> parsed = MiniJson.parse(json);
            if (parsed.isPresent() && parsed.get() instanceof Map<?, ?> map) {
                status = string(map, "status", status);
                title = string(map, "title", "");
                summary = string(map, "summary", "");
                evidence = string(map, "evidence", "");
            }
            if (title.isBlank()) {
                title = shortTitle(summary, status);
            }
            return new Parsed(Kind.VERDICT, null, status, title, summary, evidence);
        }
        Matcher replay = REPLAY.matcher(reply);
        if (replay.find()) {
            return new Parsed(Kind.REPLAY, replay.group(1).strip(), null, null, null, null);
        }
        return Parsed.none();
    }

    /** Falls back to a short label when the model omitted a title. */
    private static String shortTitle(String summary, String status) {
        String s = summary == null ? "" : summary.strip();
        if (s.isEmpty()) {
            return status == null ? "Finding" : status;
        }
        int cut = s.indexOf('.');
        String first = cut > 0 ? s.substring(0, cut) : s;
        return first.length() > 60 ? first.substring(0, 60) + "…" : first;
    }

    private static String string(Map<?, ?> map, String key, String fallback) {
        Object value = map.get(key);
        return value instanceof String s ? s : fallback;
    }

    /** Parses the 1-based endpoint numbers from a triage {@code ```select``` } block. */
    static List<Integer> parseSelect(String reply) {
        List<Integer> result = new ArrayList<>();
        Matcher m = SELECT.matcher(reply);
        if (!m.find()) {
            return result;
        }
        Matcher num = Pattern.compile("\\d+").matcher(m.group(1));
        while (num.find()) {
            try {
                result.add(Integer.parseInt(num.group()));
            } catch (NumberFormatException ignored) {
                // skip overly long numbers
            }
        }
        return result;
    }
}
