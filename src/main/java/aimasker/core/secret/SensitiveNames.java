package aimasker.core.secret;

import java.util.Locale;
import java.util.Set;

/**
 * Decides whether a header, parameter, JSON key or form field name holds a secret or personal
 * data, and which placeholder kind to use. Names are compared after lower-casing and dropping
 * everything but letters and digits, so {@code X-Api-Key}, {@code api_key} and {@code apiKey}
 * are treated alike.
 */
final class SensitiveNames {

    /** Substrings that mark a secret wherever they appear in a name. */
    private static final String[] SECRET_PARTS = {
        "password", "passwd", "passphrase", "secret", "apikey", "accesskey", "privatekey", "accountkey",
        "sharedaccesskey", "token", "sessionid", "sessid", "sessionkey", "csrf", "xsrf", "credential",
        "authorization", "bearer", "jwt", "cvv", "cvc", "pincode", "otpcode", "mfacode", "totp",
        "signingkey", "encryptionkey", "masterkey", "connectionstring", "cookie",
    };
    /** Names that are secrets only as a whole word (as substrings they are too common). */
    private static final Set<String> SECRET_EXACT = Set.of(
            "pwd", "pass", "pw", "pin", "otp", "sid", "auth", "apikey", "session", "sig", "signature",
            "salt", "ticket", "assertion", "samlresponse", "samlrequest", "authcode");
    /** Substrings that mark personal data. */
    private static final String[] PERSONAL_PARTS = {
        "username", "userid", "email", "phone", "mobile", "msisdn", "firstname", "lastname", "fullname",
        "surname", "birthdate", "dateofbirth", "tckn", "tckimlik", "nationalid", "ssn", "iban",
        "cardnumber", "ccnumber", "creditcard", "accountnumber", "address", "postcode", "zipcode",
    };
    private static final Set<String> PERSONAL_EXACT = Set.of(
            "user", "uid", "login", "mail", "tel", "dob");

    private SensitiveNames() {
    }

    enum Category {
        SECRET,
        PERSONAL
    }

    /** Returns the category of a field name, or {@code null} if it is not sensitive. */
    static Category classify(String name) {
        String normalized = normalize(name);
        if (normalized.isEmpty() || normalized.length() > 64) {
            return null;
        }
        // Names such as user[password] or data.token are judged by their last segment first.
        String last = normalize(lastSegment(name));
        for (String candidate : new String[] {last, normalized}) {
            if (SECRET_EXACT.contains(candidate) || containsAny(candidate, SECRET_PARTS)) {
                return Category.SECRET;
            }
            if (PERSONAL_EXACT.contains(candidate) || containsAny(candidate, PERSONAL_PARTS)) {
                return Category.PERSONAL;
            }
        }
        return null;
    }

    static boolean isSecretHeader(String headerName) {
        String lower = headerName.toLowerCase(Locale.ROOT);
        if (lower.startsWith("access-control-") || lower.equals("www-authenticate")
                || lower.equals("proxy-authenticate") || lower.startsWith("sec-ch-")) {
            return false;
        }
        return classify(headerName) == Category.SECRET;
    }

    private static String lastSegment(String name) {
        int cut = Math.max(Math.max(name.lastIndexOf('['), name.lastIndexOf('.')), name.lastIndexOf("%5B"));
        return cut >= 0 ? name.substring(cut + 1) : name;
    }

    static String normalize(String name) {
        StringBuilder out = new StringBuilder(name.length());
        String decoded = name.replace("%5B", "[").replace("%5D", "]").replace("%5b", "[").replace("%5d", "]");
        for (int i = 0; i < decoded.length(); i++) {
            char c = Character.toLowerCase(decoded.charAt(i));
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static boolean containsAny(String value, String[] parts) {
        for (String part : parts) {
            if (value.contains(part)) {
                return true;
            }
        }
        return false;
    }
}
