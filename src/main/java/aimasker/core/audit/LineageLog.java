package aimasker.core.audit;

import aimasker.core.EntityType;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * In-memory, bounded history of redactions. Kept only for the lifetime of the extension and
 * never written to disk or sent anywhere.
 */
public final class LineageLog {

    public static final int DEFAULT_CAPACITY = 5_000;

    private final int capacity;
    private final Clock clock;
    private final Deque<LineageRecord> records = new ArrayDeque<>();
    private final Map<String, String> entityIds = new HashMap<>();
    private final Map<EntityType, Integer> counters = new HashMap<>();
    private final List<Consumer<LineageRecord>> listeners = new CopyOnWriteArrayList<>();

    public LineageLog() {
        this(DEFAULT_CAPACITY, Clock.systemUTC());
    }

    public LineageLog(int capacity, Clock clock) {
        this.capacity = capacity;
        this.clock = clock;
    }

    public LineageRecord record(EntityType type, String fingerprint, String replacement, String source, String location) {
        LineageRecord record;
        synchronized (this) {
            String entityId = entityIds.computeIfAbsent(fingerprint, fp -> {
                int next = counters.merge(type, 1, Integer::sum);
                return String.format("%s_%03d", type.name(), next);
            });
            record = new LineageRecord(entityId, type, fingerprint, replacement, source, location, clock.instant());
            records.addLast(record);
            while (records.size() > capacity) {
                records.removeFirst();
            }
        }
        for (Consumer<LineageRecord> listener : listeners) {
            listener.accept(record);
        }
        return record;
    }

    public synchronized List<LineageRecord> snapshot() {
        return new ArrayList<>(records);
    }

    public synchronized void clear() {
        records.clear();
    }

    public void addListener(Consumer<LineageRecord> listener) {
        listeners.add(listener);
    }
}
