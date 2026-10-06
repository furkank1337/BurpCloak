package aimasker.burp;

import aimasker.core.audit.Fingerprinter;
import aimasker.core.config.ConfigStore;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;
import java.util.Base64;
import java.util.Optional;

/**
 * Stores the configuration in the Burp project file, so target domains stay with the
 * engagement they belong to. (With a temporary project they are lost when Burp closes.)
 */
final class BurpConfigStore implements ConfigStore {

    private static final String CONFIG_KEY = "aimasker.config";
    private static final String FINGERPRINT_KEY = "aimasker.fingerprintKey";
    /** Keys written by pre-release builds (published as "AI Redactor"); read once and migrated. */
    private static final String LEGACY_CONFIG_KEY = "airedactor.config";
    private static final String LEGACY_FINGERPRINT_KEY = "airedactor.fingerprintKey";

    private final PersistedObject projectData;

    BurpConfigStore(PersistedObject projectData) {
        this.projectData = projectData;
    }

    @Override
    public Optional<String> load() {
        String value = projectData.getString(CONFIG_KEY);
        if (value == null) {
            value = projectData.getString(LEGACY_CONFIG_KEY);
            if (value != null) {
                projectData.setString(CONFIG_KEY, value);
                projectData.deleteString(LEGACY_CONFIG_KEY);
            }
        }
        return Optional.ofNullable(value);
    }

    @Override
    public void save(String serializedConfig) {
        projectData.setString(CONFIG_KEY, serializedConfig);
    }

    /**
     * The fingerprint key lives in user-level preferences so the same domain has the same
     * fingerprint across projects on this machine, and is never part of a shared project file.
     */
    static byte[] loadOrCreateFingerprintKey(Preferences preferences) {
        String stored = preferences.getString(FINGERPRINT_KEY);
        if (stored == null) {
            stored = preferences.getString(LEGACY_FINGERPRINT_KEY);
            if (stored != null) {
                preferences.setString(FINGERPRINT_KEY, stored);
                preferences.deleteString(LEGACY_FINGERPRINT_KEY);
            }
        }
        if (stored != null) {
            try {
                byte[] key = Base64.getDecoder().decode(stored);
                if (key.length == Fingerprinter.KEY_BYTES) {
                    return key;
                }
            } catch (IllegalArgumentException e) {
                // fall through and replace the corrupt key
            }
        }
        byte[] key = Fingerprinter.newKey();
        preferences.setString(FINGERPRINT_KEY, Base64.getEncoder().encodeToString(key));
        return key;
    }
}
