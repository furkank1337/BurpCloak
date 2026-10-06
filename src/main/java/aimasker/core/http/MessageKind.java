package aimasker.core.http;

public enum MessageKind {
    REQUEST("HTTP Request"),
    RESPONSE("HTTP Response");

    private final String label;

    MessageKind(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
