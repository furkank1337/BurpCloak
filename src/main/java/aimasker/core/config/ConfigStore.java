package aimasker.core.config;

import java.util.Optional;

/** Persistence for the serialised configuration (Burp project data in production). */
public interface ConfigStore {

    Optional<String> load();

    void save(String serializedConfig);

    /** Non-persistent store for tests and previews. */
    final class InMemory implements ConfigStore {
        private volatile String value;

        @Override
        public Optional<String> load() {
            return Optional.ofNullable(value);
        }

        @Override
        public void save(String serializedConfig) {
            value = serializedConfig;
        }
    }
}
