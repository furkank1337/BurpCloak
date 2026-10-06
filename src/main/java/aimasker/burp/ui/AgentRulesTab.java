package aimasker.burp.ui;

import aimasker.burp.agent.AgentProtocol;
import aimasker.core.control.RedactorService;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * The "Agent Rules" tab: edit the system prompt sent to the AI on every agent session.
 *
 * <p>Blank means the built-in default ({@link AgentProtocol#SYSTEM}) is used. The default
 * carries the reply contract (one {@code ```replay``` } or {@code ```verdict``` } block, keep
 * pseudonyms verbatim) that the loop depends on, so editing it freely can stop the loop from
 * working - the note on the panel warns about this.
 */
public final class AgentRulesTab {

    private static final Color OK_GREEN = new Color(0x2E7D32);
    private static final Color WARN_AMBER = new Color(0xF9A825);

    private final RedactorService service;
    private final JPanel root = new JPanel(new BorderLayout());
    private final JTextArea rules = new JTextArea();
    private final JLabel contractStatus = new JLabel();

    public AgentRulesTab(RedactorService service) {
        this.service = service;

        rules.setFont(new Font(Font.MONOSPACED, Font.PLAIN, rules.getFont().getSize()));
        rules.setLineWrap(true);
        rules.setWrapStyleWord(true);

        JTextArea note = new JTextArea(
                "This is the system prompt sent to the AI on every agent session. Leave it blank to use "
                + "the built-in default. Keep the reply contract (one ```replay``` or ```verdict``` block, "
                + "and \"keep pseudonyms exactly as-is\") or the agent loop may stop working.");
        note.setEditable(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        note.setOpaque(false);
        note.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JButton save = new JButton("Save rules");
        save.addActionListener(e -> save());
        JButton reset = new JButton("Reset to default");
        reset.addActionListener(e -> resetToDefault());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(save);
        buttons.add(reset);
        buttons.add(contractStatus);

        rules.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { updateContract(); }
            @Override public void removeUpdate(DocumentEvent e) { updateContract(); }
            @Override public void changedUpdate(DocumentEvent e) { updateContract(); }
        });

        JScrollPane scroll = new JScrollPane(rules);
        scroll.setBorder(BorderFactory.createTitledBorder("System prompt (agent rules)"));

        root.add(note, BorderLayout.NORTH);
        root.add(scroll, BorderLayout.CENTER);
        root.add(buttons, BorderLayout.SOUTH);

        loadFromConfig();
        service.addChangeListener(() -> SwingUtilities.invokeLater(this::loadFromConfig));
    }

    public Component component() {
        return root;
    }

    private void loadFromConfig() {
        String current = service.config().agent().rules();
        rules.setText(current.isBlank() ? AgentProtocol.SYSTEM : current);
        rules.setCaretPosition(0);
        updateContract();
    }

    /** Live check that the required reply contract is still present in the prompt. */
    private void updateContract() {
        String text = rules.getText();
        boolean hasReplay = text.contains("```replay");
        boolean hasVerdict = text.contains("```verdict");
        if (hasReplay && hasVerdict) {
            contractStatus.setForeground(OK_GREEN);
            contractStatus.setText("Contract OK (```replay``` and ```verdict``` present)");
        } else {
            contractStatus.setForeground(WARN_AMBER);
            contractStatus.setText("Warning: missing "
                    + (!hasReplay ? "```replay``` " : "") + (!hasVerdict ? "```verdict``` " : "")
                    + "- the loop may not work.");
        }
    }

    private void save() {
        String text = rules.getText();
        // If it equals the default, store blank so the effective prompt tracks future default changes.
        String toStore = text.strip().equals(AgentProtocol.SYSTEM.strip()) ? "" : text;
        try {
            service.update(config -> config.withAgent(config.agent().withRules(toStore)));
            Dialogs.info(root, "Succeeded: agent rules saved.");
        } catch (IllegalArgumentException e) {
            Dialogs.error(root, e.getMessage());
        }
    }

    private void resetToDefault() {
        service.update(config -> config.withAgent(config.agent().withRules("")));
        loadFromConfig();
        Dialogs.info(root, "Succeeded: reset to the built-in default rules.");
    }
}
