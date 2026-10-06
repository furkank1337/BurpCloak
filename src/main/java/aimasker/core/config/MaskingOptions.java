package aimasker.core.config;

/**
 * Which categories of sensitive data are masked in addition to customer domains.
 *
 * @param secrets      credentials and tokens: JWTs, API keys, private keys, Authorization and
 *                     Cookie values, and fields named password, token, secret, session, ...
 * @param personalData e-mail addresses, username/phone/address fields, payment cards, IBANs
 *                     and national ID numbers
 * @param ipAddresses  IPv4 and IPv6 addresses
 */
public record MaskingOptions(boolean secrets, boolean personalData, boolean ipAddresses) {

    /** Secure default: everything on. */
    public static MaskingOptions all() {
        return new MaskingOptions(true, true, true);
    }
}
