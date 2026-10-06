package aimasker.burp.ui;

import aimasker.core.config.RedactorConfig;
import aimasker.core.domain.DomainRule;
import aimasker.core.gateway.GatewayDecision;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.HashSet;
import java.util.Set;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/** Small modal dialogs used by the tab and the context menu. */
public final class Dialogs {

    private Dialogs() {
    }

    public static void showDecision(Component parent, String title, GatewayDecision decision) {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        VerdictLabel verdict = new VerdictLabel();
        verdict.show(decision);
        panel.add(verdict, BorderLayout.NORTH);
        StringBuilder details = new StringBuilder();
        for (String reason : decision.reasons()) {
            details.append("Reason: ").append(reason).append('\n');
        }
        for (String note : decision.notes()) {
            details.append("Note: ").append(note).append('\n');
        }
        if (!decision.allowed()) {
            details.append("\nNothing was sent or copied. The text below is shown locally only.\n");
        }
        if (!decision.localPreview().isEmpty()) {
            details.append("\n").append(decision.localPreview());
        }
        panel.add(scroll(details.toString()), BorderLayout.CENTER);
        JOptionPane.showMessageDialog(parent, panel, title,
                decision.allowed() ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE);
    }

    public static void showText(Component parent, String title, String text) {
        JOptionPane.showMessageDialog(parent, scroll(text), title, JOptionPane.PLAIN_MESSAGE);
    }

    public static void info(Component parent, String message) {
        JOptionPane.showMessageDialog(parent, message, "Cloak", JOptionPane.INFORMATION_MESSAGE);
    }

    public static void error(Component parent, String message) {
        JOptionPane.showMessageDialog(parent, message, "Cloak", JOptionPane.ERROR_MESSAGE);
    }

    /** Single-line prompt; returns the entered text, or {@code null} if cancelled. */
    public static String ask(Component parent, String title, String message) {
        return (String) JOptionPane.showInputDialog(parent, message, title, JOptionPane.PLAIN_MESSAGE, null, null, "");
    }

    /** Returns the question, or {@code null} if cancelled. */
    public static String askQuestion(Component parent) {
        JTextArea question = new JTextArea("Analyse this exchange for security issues and suggest next tests.", 5, 60);
        question.setLineWrap(true);
        question.setWrapStyleWord(true);
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.add(new JLabel("Question (it is redacted and validated too before sending):"), BorderLayout.NORTH);
        panel.add(new JScrollPane(question), BorderLayout.CENTER);
        int choice = JOptionPane.showConfirmDialog(parent, panel, "Ask Burp AI (masked)",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        return choice == JOptionPane.OK_OPTION ? question.getText() : null;
    }

    public static String askTarget(Component parent, String initial) {
        return (String) JOptionPane.showInputDialog(parent,
                "Target domain to redact (edit to the registrable domain, e.g. example.com):",
                "Add target domain", JOptionPane.PLAIN_MESSAGE, null, null, initial);
    }

    /** Returns {@code {target, replacement, keywords}}, or {@code null} if cancelled. */
    public static String[] askRule(Component parent, String suggestedReplacement) {
        JTextField target = new JTextField(30);
        JTextField replacement = new JTextField(suggestedReplacement, 30);
        JTextField keywords = new JTextField(30);
        JPanel panel = new JPanel(new GridLayout(0, 1, 0, 4));
        panel.add(new JLabel("Target domain (subdomains are always included):"));
        panel.add(target);
        panel.add(new JLabel("Replacement (hostname such as redacted.com, or a token such as [REDACTED_DOMAIN]):"));
        panel.add(replacement);
        panel.add(new JLabel("Extra brand keywords, comma-separated (optional, e.g. company or product names):"));
        panel.add(keywords);
        int choice = JOptionPane.showConfirmDialog(parent, panel, "Add target domain",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        return choice == JOptionPane.OK_OPTION ? new String[] {target.getText(), replacement.getText(), keywords.getText()} : null;
    }

    /** {@code redacted.com}, then {@code redacted2.com}, ... so every target gets a distinct pseudonym. */
    public static String suggestReplacement(RedactorConfig config) {
        Set<String> used = new HashSet<>();
        for (DomainRule rule : config.domainRules()) {
            used.add(rule.replacement());
        }
        if (!used.contains(DomainRule.DEFAULT_REPLACEMENT)) {
            return DomainRule.DEFAULT_REPLACEMENT;
        }
        for (int i = 2; ; i++) {
            String candidate = "redacted" + i + ".com";
            if (!used.contains(candidate)) {
                return candidate;
            }
        }
    }

    static JScrollPane scroll(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, area.getFont().getSize()));
        area.setCaretPosition(0);
        JScrollPane pane = new JScrollPane(area);
        pane.setPreferredSize(new Dimension(900, 550));
        return pane;
    }
}
