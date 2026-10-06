package aimasker.burp;

import aimasker.core.audit.AuditSink;
import burp.api.montoya.logging.Logging;

/** Writes sanitised audit lines to the extension's Output / Errors tabs. */
final class BurpAuditSink implements AuditSink {

    private static final String PREFIX = "[Cloak] ";

    private final Logging logging;

    BurpAuditSink(Logging logging) {
        this.logging = logging;
    }

    @Override
    public void info(String message) {
        logging.logToOutput(PREFIX + message);
    }

    @Override
    public void warn(String message) {
        logging.logToError(PREFIX + message);
    }
}
