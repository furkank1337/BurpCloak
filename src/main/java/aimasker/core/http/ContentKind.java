package aimasker.core.http;

import java.util.Locale;

/** Coarse body type, used for lineage locations and binary detection. */
enum ContentKind {
    JSON("json"),
    XML("xml"),
    HTML("html"),
    JAVASCRIPT("javascript"),
    CSS("css"),
    FORM("form"),
    MULTIPART("multipart"),
    TEXT("text"),
    BINARY("binary");

    private final String label;

    ContentKind(String label) {
        this.label = label;
    }

    String label() {
        return label;
    }

    static ContentKind of(String contentType, String body) {
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (type.contains("json")) {
            return JSON;
        }
        if (type.contains("html")) {
            return HTML;
        }
        if (type.contains("svg") || type.contains("xml")) {
            return XML;
        }
        if (type.contains("javascript") || type.contains("ecmascript")) {
            return JAVASCRIPT;
        }
        if (type.contains("css")) {
            return CSS;
        }
        if (type.contains("x-www-form-urlencoded")) {
            return FORM;
        }
        if (type.startsWith("multipart/")) {
            return MULTIPART;
        }
        if (type.startsWith("image/") || type.startsWith("audio/") || type.startsWith("video/")
                || type.startsWith("font/") || type.contains("octet-stream") || type.contains("pdf")
                || type.contains("zip") || type.contains("protobuf") || type.contains("grpc")
                || type.contains("wasm")) {
            return BINARY;
        }
        return sniff(body);
    }

    private static ContentKind sniff(String body) {
        int limit = Math.min(body.length(), 4096);
        int control = 0;
        for (int i = 0; i < limit; i++) {
            char c = body.charAt(i);
            if (c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f) {
                control++;
            }
        }
        if (limit > 0 && control * 10 > limit) {
            return BINARY;
        }
        String start = body.stripLeading();
        if (start.startsWith("{") || start.startsWith("[")) {
            return JSON;
        }
        if (start.regionMatches(true, 0, "<!doctype html", 0, 14) || start.regionMatches(true, 0, "<html", 0, 5)) {
            return HTML;
        }
        if (start.startsWith("<")) {
            return XML;
        }
        return TEXT;
    }
}
