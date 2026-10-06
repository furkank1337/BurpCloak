package aimasker.core;

/**
 * Categories of sensitive data. Each constant is used as the prefix of lineage entity IDs, e.g. {@code DOMAIN_001}.
 */
public enum EntityType {
    DOMAIN,
    /** Brand / organisation name tied to a customer domain, e.g. "N-Day" for nday.blog. */
    BRAND,
    IP,
    EMAIL,
    JWT,
    API_KEY,
    SECRET,
    COOKIE,
    /** Usernames, phone numbers, card numbers, IBANs, national IDs. */
    PERSONAL,
    CUSTOM
}
