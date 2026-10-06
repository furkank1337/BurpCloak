package aimasker.core.secret;

import aimasker.core.EntityType;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Numbers that identify a person or an account, each confirmed by its checksum so random
 * digit runs are not masked: payment card numbers (Luhn), IBANs (ISO 13616 mod 97) and
 * Turkish national ID numbers (T.C. Kimlik No).
 */
public final class PersonalIdDetector extends SpanDetector {

    public static final String ID = "personal-id";

    private static final Pattern CARD = Pattern.compile("(?<![\\d.-])(?:\\d[ -]?){12,18}\\d(?![\\d.-])");
    private static final Pattern IBAN = Pattern.compile(
            "(?<![A-Za-z0-9])[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])");
    private static final Pattern TCKN = Pattern.compile("(?<![\\d.])[1-9]\\d{10}(?![\\d.])");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public EntityType entityType() {
        return EntityType.PERSONAL;
    }

    @Override
    List<Span> spans(String text) {
        List<Span> spans = new ArrayList<>();
        int longestDigitRun = longestDigitRun(text);
        if (longestDigitRun < 11 && !hasIbanStart(text)) {
            return spans;
        }
        Matcher card = CARD.matcher(text);
        while (card.find()) {
            String digits = card.group().replaceAll("[ -]", "");
            if (isCardNumber(digits)) {
                spans.add(new Span(card.start(), card.end(), EntityType.PERSONAL, "CARD"));
            }
        }
        Matcher iban = IBAN.matcher(text);
        while (iban.find()) {
            if (isIban(iban.group().replace(" ", ""))) {
                spans.add(new Span(iban.start(), iban.end(), EntityType.PERSONAL, "IBAN"));
            }
        }
        Matcher tckn = TCKN.matcher(text);
        while (tckn.find()) {
            if (isTckn(tckn.group())) {
                spans.add(new Span(tckn.start(), tckn.end(), EntityType.PERSONAL, "NATIONAL_ID"));
            }
        }
        return spans;
    }

    /** Longest run of digits, allowing single spaces or dashes between them (as in card numbers). */
    private static int longestDigitRun(String text) {
        int best = 0;
        int run = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= '0' && c <= '9') {
                run++;
                best = Math.max(best, run);
            } else if ((c == ' ' || c == '-') && run > 0 && i + 1 < text.length() && Character.isDigit(text.charAt(i + 1))) {
                continue;
            } else {
                run = 0;
            }
        }
        return best;
    }

    private static boolean hasIbanStart(String text) {
        for (int i = 0; i + 3 < text.length(); i++) {
            if (isUpper(text.charAt(i)) && isUpper(text.charAt(i + 1))
                    && Character.isDigit(text.charAt(i + 2)) && Character.isDigit(text.charAt(i + 3))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isUpper(char c) {
        return c >= 'A' && c <= 'Z';
    }

    static boolean isCardNumber(String digits) {
        if (digits.length() < 13 || digits.length() > 19 || digits.chars().distinct().count() < 2) {
            return false;
        }
        char first = digits.charAt(0);
        String two = digits.substring(0, 2);
        boolean knownPrefix = first == '4' // Visa
                || (two.compareTo("51") >= 0 && two.compareTo("55") <= 0) // Mastercard
                || (digits.substring(0, 4).compareTo("2221") >= 0 && digits.substring(0, 4).compareTo("2720") <= 0)
                || two.equals("34") || two.equals("37") // Amex
                || first == '6' // Discover, UnionPay, Troy (65, 9792 is covered below)
                || digits.startsWith("9792") // Troy
                || two.equals("35") || two.equals("36") || two.equals("30"); // JCB, Diners
        return knownPrefix && luhn(digits);
    }

    private static boolean luhn(String digits) {
        int sum = 0;
        boolean doubleIt = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (doubleIt) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }

    static boolean isIban(String iban) {
        if (iban.length() < 15 || iban.length() > 34) {
            return false;
        }
        String rearranged = iban.substring(4) + iban.substring(0, 4);
        StringBuilder numeric = new StringBuilder();
        for (char c : rearranged.toCharArray()) {
            numeric.append(Character.isDigit(c) ? String.valueOf(c) : String.valueOf(c - 'A' + 10));
        }
        return new BigInteger(numeric.toString()).mod(BigInteger.valueOf(97)).intValue() == 1;
    }

    static boolean isTckn(String id) {
        int[] d = id.chars().map(c -> c - '0').toArray();
        int odd = d[0] + d[2] + d[4] + d[6] + d[8];
        int even = d[1] + d[3] + d[5] + d[7];
        int tenth = Math.floorMod(odd * 7 - even, 10);
        int eleventh = (odd + even + d[9]) % 10;
        return d[9] == tenth && d[10] == eleventh;
    }
}
