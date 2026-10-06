package aimasker.core.audit;

import java.util.concurrent.atomic.AtomicLong;

/** Thread-safe counters for AI-bound traffic handled by the gateway. */
public final class Statistics {

    private final AtomicLong requestsScanned = new AtomicLong();
    private final AtomicLong responsesScanned = new AtomicLong();
    private final AtomicLong valuesRedacted = new AtomicLong();
    private final AtomicLong leakageBlocked = new AtomicLong();
    private final AtomicLong unknownBlocked = new AtomicLong();
    private final AtomicLong allowed = new AtomicLong();

    public void requestScanned() {
        requestsScanned.incrementAndGet();
    }

    public void responseScanned() {
        responsesScanned.incrementAndGet();
    }

    public void valuesRedacted(int count) {
        valuesRedacted.addAndGet(count);
    }

    public void leakageBlocked() {
        leakageBlocked.incrementAndGet();
    }

    public void unknownBlocked() {
        unknownBlocked.incrementAndGet();
    }

    public void allowed() {
        allowed.incrementAndGet();
    }

    public Snapshot snapshot() {
        return new Snapshot(requestsScanned.get(), responsesScanned.get(), valuesRedacted.get(),
                leakageBlocked.get(), unknownBlocked.get(), allowed.get());
    }

    public void reset() {
        requestsScanned.set(0);
        responsesScanned.set(0);
        valuesRedacted.set(0);
        leakageBlocked.set(0);
        unknownBlocked.set(0);
        allowed.set(0);
    }

    public record Snapshot(long requestsScanned, long responsesScanned, long valuesRedacted,
                           long leakageBlocked, long unknownBlocked, long allowed) {
    }
}
