package aimasker.core.audit;

/**
 * Destination for audit log lines (Burp's extension output in production). Callers must only
 * pass sanitised text: fingerprints, locations, counts and verdicts, never original values.
 */
public interface AuditSink {

    void info(String message);

    void warn(String message);

    AuditSink NONE = new AuditSink() {
        @Override
        public void info(String message) {
        }

        @Override
        public void warn(String message) {
        }
    };
}
