package aimasker.burp;

import aimasker.core.MiniJson;
import burp.api.montoya.persistence.PersistedObject;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Persists AI findings in the Burp project so they survive a reload. Stored as one JSON string;
 * the request/response bytes are real local traffic, kept alongside the project's own history.
 */
public final class FindingsStore {

    private static final String KEY = "cloak.findings";

    private final PersistedObject data;

    public FindingsStore(PersistedObject data) {
        this.data = data;
    }

    public synchronized List<Finding> load() {
        List<Finding> findings = new ArrayList<>();
        String json = data.getString(KEY);
        if (json == null || json.isBlank()) {
            return findings;
        }
        Optional<Object> parsed = MiniJson.parse(json);
        if (parsed.isPresent() && parsed.get() instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof java.util.Map<?, ?> map) {
                    try {
                        findings.add(Finding.fromMap(map));
                    } catch (RuntimeException ignored) {
                        // skip a corrupt record rather than losing them all
                    }
                }
            }
        }
        return findings;
    }

    public synchronized void save(List<Finding> findings) {
        List<Object> list = new ArrayList<>();
        for (Finding f : findings) {
            list.add(f.toMap());
        }
        data.setString(KEY, MiniJson.write(list));
    }
}
