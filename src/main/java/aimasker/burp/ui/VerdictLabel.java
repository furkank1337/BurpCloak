package aimasker.burp.ui;

import aimasker.core.gateway.GatewayDecision;
import java.awt.Color;
import java.awt.Font;
import javax.swing.BorderFactory;
import javax.swing.JLabel;

/** One-line verdict banner: green when the content may be sent, red when it is blocked. */
public final class VerdictLabel extends JLabel {

    private static final long serialVersionUID = 1L;
    private static final Color ALLOW = new Color(0x2E7D32);
    private static final Color BLOCK = new Color(0xC62828);

    public VerdictLabel() {
        setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        setFont(getFont().deriveFont(Font.BOLD));
    }

    public void show(GatewayDecision decision) {
        if (decision.allowed()) {
            setForeground(ALLOW);
            setText("AI SAFE: " + decision.verdict() + " - " + decision.events().size() + " value(s) replaced");
            setToolTipText(null);
        } else {
            setForeground(BLOCK);
            String reason = decision.reasons().isEmpty() ? "" : " - " + decision.reasons().get(0);
            setText("BLOCKED: " + decision.verdict() + reason);
            setToolTipText("<html>" + String.join("<br>", decision.reasons().stream().map(VerdictLabel::escape).toList()) + "</html>");
        }
    }

    public void showPending() {
        setForeground(null);
        setText("Redacting...");
        setToolTipText(null);
    }

    public void showMessage(String message) {
        setForeground(null);
        setText(message);
        setToolTipText(null);
    }

    static String escape(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
