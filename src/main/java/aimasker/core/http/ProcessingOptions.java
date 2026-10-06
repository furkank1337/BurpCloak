package aimasker.core.http;

/**
 * Which parts of a message the redactor rewrites. Turning a part off does NOT let sensitive
 * data through: the leakage validator always scans the whole message, so a message whose
 * skipped part contains a target is blocked.
 *
 * @param processRequests  redact request messages
 * @param processResponses redact response messages
 * @param processHeaders   redact the start line and header lines
 * @param processBodies    redact message bodies
 * @param omitBinaryBodies replace non-text bodies (images, fonts, archives) with a placeholder
 * @param maxPartChars     AI-safe text per message part is truncated to this many characters
 */
public record ProcessingOptions(
        boolean processRequests,
        boolean processResponses,
        boolean processHeaders,
        boolean processBodies,
        boolean omitBinaryBodies,
        int maxPartChars) {

    public static final int DEFAULT_MAX_PART_CHARS = 200_000;

    public static ProcessingOptions defaults() {
        return new ProcessingOptions(true, true, true, true, true, DEFAULT_MAX_PART_CHARS);
    }

    public ProcessingOptions {
        if (maxPartChars < 1_000) {
            throw new IllegalArgumentException("maxPartChars must be at least 1000");
        }
    }

    public boolean processes(MessageKind kind) {
        return kind == MessageKind.REQUEST ? processRequests : processResponses;
    }
}
