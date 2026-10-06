package aimasker.burp.ui;

import aimasker.burp.agent.AgentOrchestrator;
import aimasker.burp.agent.BatchOrchestrator;
import aimasker.burp.agent.PromptLibrary;
import aimasker.burp.opencode.OpenCodeClient;
import aimasker.core.config.AgentSettings;
import aimasker.core.config.SavedPrompt;
import aimasker.core.control.RedactorService;
import aimasker.core.gateway.HttpExchange;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

/**
 * The "Agent" chat panel: pick a target exchange (via the context menu), choose or write a
 * prompt, and run the AI-driven analysis loop (single endpoint or whole-target batch).
 *
 * <p>Views are kept strictly apart: <b>Transcript</b> is only the masked text sent to the AI;
 * <b>Local traffic</b> and <b>Unmasked</b> show real data that never leaves the machine.
 * Vulnerable findings collect in the table, optionally mirror into Burp's site map / issues, and
 * can be reproduced in Repeater or exported as a report.
 */
public final class AgentTab {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final Color OK_GREEN = new Color(0x2E7D32);
    private static final Color BLOCK_RED = new Color(0xC62828);
    private static final Color WARN_AMBER = new Color(0xF9A825);

    private final RedactorService service;
    private final ExecutorService worker;
    private final AgentOrchestrator orchestrator;
    private final BatchOrchestrator batchOrchestrator;
    private final FindingsTab findingsTab;

    private final JPanel root = new JPanel(new BorderLayout());
    private final JLabel readiness = new JLabel();
    private final JLabel target = new JLabel("No target selected.");
    private final JLabel verdict = new JLabel(" ");
    private final JComboBox<String> promptBox = new JComboBox<>();
    private final JTextArea promptText = new JTextArea(3, 60);
    private final JTextArea transcript = new JTextArea();
    private final JTextArea localTraffic = new JTextArea();
    private final JTextArea unmaskedView = new JTextArea();
    private final JTextArea endpoints = new JTextArea();
    private final JProgressBar progress = new JProgressBar();
    private final JLabel iterationLabel = new JLabel("");
    private final JButton start = new JButton("Start session");
    private final JButton stop = new JButton("Stop");
    private final JButton testConn = new JButton("Test OpenCode connection");
    private final JButton savePrompt = new JButton("Save prompt");
    private final JCheckBox dryRun = new JCheckBox("Dry run (triage only)");
    private final AtomicBoolean running = new AtomicBoolean(false);
    private List<SavedPrompt> promptItems = List.of();

    private HttpExchange exchange;
    private List<HttpExchange> batch;

    public AgentTab(RedactorService service, ExecutorService worker, AgentOrchestrator orchestrator,
                    BatchOrchestrator batchOrchestrator, FindingsTab findingsTab) {
        this.service = service;
        this.worker = worker;
        this.orchestrator = orchestrator;
        this.batchOrchestrator = batchOrchestrator;
        this.findingsTab = findingsTab;

        promptText.setLineWrap(true);
        promptText.setWrapStyleWord(true);
        for (JTextArea area : new JTextArea[] {transcript, localTraffic, unmaskedView, endpoints}) {
            area.setEditable(false);
            area.setFont(mono(area));
        }

        verdict.setOpaque(true);
        verdict.setVisible(false);
        verdict.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
        verdict.setFont(verdict.getFont().deriveFont(Font.BOLD));

        root.add(topPanel(), BorderLayout.NORTH);
        root.add(centerPanel(), BorderLayout.CENTER);
        root.add(statusBar(), BorderLayout.SOUTH);

        reloadPrompts();
        stop.setEnabled(false);
        service.addChangeListener(() -> SwingUtilities.invokeLater(() -> {
            reloadPrompts();
            updateReadiness();
        }));
        promptBox.addActionListener(e -> {
            int i = promptBox.getSelectedIndex();
            if (i >= 0 && i < promptItems.size()) {
                promptText.setText(promptItems.get(i).text());
                promptText.setCaretPosition(0);
            }
        });
        start.addActionListener(e -> startSession());
        stop.addActionListener(e -> {
            orchestrator.stop();
            batchOrchestrator.stop();
        });
        testConn.addActionListener(e -> testConnection());
        savePrompt.addActionListener(e -> savePrompt());
        updateReadiness();
    }

    public Component component() {
        return root;
    }

    /** Called from the context menu. One item -> single-endpoint session; several -> batch. */
    public void setExchanges(List<HttpExchange> exchanges, String targetLabel) {
        if (exchanges == null || exchanges.isEmpty()) {
            return;
        }
        if (exchanges.size() == 1) {
            this.exchange = exchanges.get(0);
            this.batch = null;
            SwingUtilities.invokeLater(() -> {
                target.setText("Target: " + targetLabel + "    " + requestSummary(exchange));
                endpoints.setText("1 request will be analysed:\n\n  " + endpointLine(exchange));
                endpoints.setCaretPosition(0);
                updateReadiness();
            });
        } else {
            this.batch = List.copyOf(exchanges);
            this.exchange = null;
            SwingUtilities.invokeLater(() -> {
                target.setText("Batch target: " + targetLabel + "    [" + batch.size()
                        + " requests → dedup + triage]");
                endpoints.setText(listEndpoints(batch));
                endpoints.setCaretPosition(0);
                updateReadiness();
            });
        }
    }

    private static String listEndpoints(List<HttpExchange> exchanges) {
        java.util.LinkedHashMap<String, Integer> unique = new java.util.LinkedHashMap<>();
        for (HttpExchange e : exchanges) {
            unique.merge(e.host() + "  " + endpointLine(e), 1, Integer::sum);
        }
        StringBuilder out = new StringBuilder();
        out.append(exchanges.size()).append(" request(s) selected, ").append(unique.size())
                .append(" distinct after de-dup. Triage will then pick which to deep-test.\n\n");
        int i = 1;
        for (java.util.Map.Entry<String, Integer> entry : unique.entrySet()) {
            out.append(String.format("%3d. %s", i++, entry.getKey()));
            if (entry.getValue() > 1) {
                out.append("   (x").append(entry.getValue()).append(')');
            }
            out.append('\n');
        }
        return out.toString();
    }

    private static String endpointLine(HttpExchange exchange) {
        if (exchange == null || exchange.request() == null) {
            return "(no request)";
        }
        String raw = new String(exchange.request(), StandardCharsets.ISO_8859_1);
        int end = raw.indexOf('\r');
        if (end < 0) {
            end = raw.indexOf('\n');
        }
        String first = (end < 0 ? raw : raw.substring(0, end)).strip();
        int http = first.lastIndexOf(" HTTP/");
        return http > 0 ? first.substring(0, http) : first;
    }

    private JComponent topPanel() {
        readiness.setBorder(BorderFactory.createEmptyBorder(6, 8, 0, 8));
        target.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));

        // Dropdown holds plain prompt NAMES (never the text); selecting one fills the text area.
        promptBox.setEditable(false);
        JPanel promptRow = leftRow();
        promptRow.add(new JLabel("Prompt:"));
        promptRow.add(promptBox);
        promptRow.add(savePrompt);

        // Action buttons on their own row so they are never clipped by wrapping.
        JPanel actionRow = leftRow();
        actionRow.add(dryRun);
        actionRow.add(testConn);
        actionRow.add(start);
        actionRow.add(stop);

        // Header rows only; the prompt text box moves into the resizable split below.
        JPanel stack = new JPanel();
        stack.setLayout(new javax.swing.BoxLayout(stack, javax.swing.BoxLayout.Y_AXIS));
        for (JComponent c : new JComponent[] {leftAlign(readiness), leftAlign(target), leftAlign(verdict),
                leftAlign(promptRow), leftAlign(actionRow)}) {
            stack.add(c);
        }
        return stack;
    }

    private static JPanel leftRow() {
        return new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
    }

    private static JComponent leftAlign(JComponent c) {
        c.setAlignmentX(Component.LEFT_ALIGNMENT);
        return c;
    }

    private JComponent centerPanel() {
        // Findings now live in their own top-level "Vulnerabilities" suite tab (FindingsTab).
        JTabbedPane views = new JTabbedPane();
        views.addTab("Transcript (masked → AI)", new JScrollPane(transcript));
        views.addTab("Endpoints", new JScrollPane(endpoints));
        views.addTab("Local traffic (real)", localWarned(localTraffic));
        views.addTab("Unmasked (local)", localWarned(unmaskedView));

        JScrollPane promptScroll = new JScrollPane(promptText);
        promptScroll.setBorder(BorderFactory.createTitledBorder("Prompt (sent masked)"));
        // Keep the prompt box from ever collapsing to nothing; the views below absorb resizing.
        promptScroll.setMinimumSize(new Dimension(0, 70));
        promptScroll.setPreferredSize(new Dimension(100, 100));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, promptScroll, views);
        split.setResizeWeight(0.0);          // prompt keeps its height; views take the extra space
        split.setContinuousLayout(true);
        views.setMinimumSize(new Dimension(0, 120));
        return split;
    }

    private JComponent localWarned(JTextArea area) {
        JPanel wrap = new JPanel(new BorderLayout());
        JLabel warn = new JLabel("LOCAL ONLY - real data, never sent to the AI.");
        warn.setForeground(WARN_AMBER);
        warn.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        wrap.add(warn, BorderLayout.NORTH);
        wrap.add(new JScrollPane(area), BorderLayout.CENTER);
        return wrap;
    }

    private JComponent statusBar() {
        progress.setStringPainted(true);
        progress.setString("idle");
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT));
        left.add(progress);
        left.add(iterationLabel);

        JButton usage = new JButton("Usage");
        usage.addActionListener(e -> Dialogs.info(root,
                "OpenCode usage this session:\n"
                + "  sessions: " + OpenCodeClient.Usage.sessions.get() + "\n"
                + "  messages: " + OpenCodeClient.Usage.messages.get() + "\n"
                + "  chars sent: " + OpenCodeClient.Usage.charsSent.get() + "\n"
                + "  chars received: " + OpenCodeClient.Usage.charsReceived.get() + "\n"
                + "  ~tokens (rough): " + OpenCodeClient.Usage.estimatedTokens()));
        JButton copy = new JButton("Copy transcript");
        copy.addActionListener(e -> copyToClipboard(transcript.getText()));
        JButton clear = new JButton("Clear log");
        clear.addActionListener(e -> {
            transcript.setText("");
            localTraffic.setText("");
            unmaskedView.setText("");
            verdict.setVisible(false);
        });
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        right.add(usage);
        right.add(copy);
        right.add(clear);

        JPanel bar = new JPanel(new BorderLayout());
        bar.add(left, BorderLayout.WEST);
        bar.add(right, BorderLayout.EAST);
        return bar;
    }

    // --- readiness / pre-flight -------------------------------------------------------------

    private void updateReadiness() {
        String text;
        Color color;
        boolean ready = false;
        if (!service.config().enabled()) {
            text = "Blocked: extension is disabled (Configuration → Enable).";
            color = BLOCK_RED;
        } else if (service.config().domainRules().isEmpty()) {
            text = "Blocked: no target domains configured - everything is blocked (fail-closed).";
            color = BLOCK_RED;
        } else if (exchange == null && batch == null) {
            text = "Select request(s): right-click → Cloak → Send to Agent (one = single, many = batch).";
            color = WARN_AMBER;
        } else {
            String mode = batch != null ? "batch (" + batch.size() + " requests)" : "single endpoint";
            text = "Ready [" + mode + "]. OpenCode: " + service.config().agent().opencodeUrl();
            color = OK_GREEN;
            ready = true;
        }
        readiness.setText(text);
        readiness.setForeground(color);
        start.setEnabled(ready && !running.get());
    }

    private static String requestSummary(HttpExchange exchange) {
        String line = endpointLine(exchange);
        return "[" + (line.length() > 80 ? line.substring(0, 80) + "..." : line) + "]";
    }

    // --- actions ----------------------------------------------------------------------------

    private void testConnection() {
        AgentSettings settings = service.config().agent();
        setStatus("Testing OpenCode connection...");
        try {
            worker.submit(() -> {
                try {
                    new OpenCodeClient(settings).ping();
                    SwingUtilities.invokeLater(() -> Dialogs.info(root,
                            "Succeeded: reached OpenCode at " + settings.opencodeUrl() + "."));
                    setStatus("OpenCode reachable.");
                } catch (RuntimeException ex) {
                    SwingUtilities.invokeLater(() -> Dialogs.error(root,
                            "Could not reach OpenCode: " + ex.getMessage()));
                    setStatus("OpenCode unreachable.");
                }
            });
        } catch (RejectedExecutionException e) {
            Dialogs.error(root, "Extension is unloading.");
        }
    }

    private void reloadPrompts() {
        promptItems = PromptLibrary.merged(service.config().prompts());
        String[] names = promptItems.stream().map(SavedPrompt::name).toArray(String[]::new);
        promptBox.setModel(new DefaultComboBoxModel<>(names));
        if (!promptItems.isEmpty() && promptText.getText().isBlank()) {
            promptText.setText(promptItems.get(0).text());
            promptText.setCaretPosition(0);
        }
    }

    private void savePrompt() {
        String text = promptText.getText().strip();
        if (text.isEmpty()) {
            Dialogs.error(root, "Enter a prompt first.");
            return;
        }
        String name = Dialogs.ask(root, "Save prompt", "Name for this prompt:");
        if (name == null || name.isBlank()) {
            return;
        }
        try {
            SavedPrompt prompt = new SavedPrompt(name, text);
            service.update(config -> {
                List<SavedPrompt> prompts = new ArrayList<>(config.prompts());
                prompts.removeIf(p -> p.name().equalsIgnoreCase(prompt.name()));
                prompts.add(prompt);
                return config.withPrompts(prompts);
            });
            Dialogs.info(root, "Succeeded: prompt saved.");
        } catch (IllegalArgumentException e) {
            Dialogs.error(root, e.getMessage());
        }
    }

    private void startSession() {
        if (exchange == null && batch == null) {
            Dialogs.error(root, "No target selected. Right-click request(s) → Cloak → Send to Agent.");
            return;
        }
        String prompt = promptText.getText().strip();
        if (prompt.isEmpty()) {
            Dialogs.error(root, "Enter or choose a prompt first.");
            return;
        }
        if (!running.compareAndSet(false, true)) {
            Dialogs.error(root, "A session is already running.");
            return;
        }
        transcript.setText("");
        localTraffic.setText("");
        unmaskedView.setText("");
        verdict.setVisible(false);
        AgentSettings settings = service.config().agent();
        boolean dry = dryRun.isSelected();
        setRunning(true);
        try {
            if (batch != null) {
                List<HttpExchange> items = batch;
                progress.setIndeterminate(true);
                progress.setString(dry ? "triage (dry run)" : "batch starting");
                iterationLabel.setText("");
                worker.submit(() -> batchOrchestrator.run(items, prompt, settings, dry, new UiBatchListener()));
            } else {
                HttpExchange target = exchange;
                progress.setIndeterminate(false);
                progress.setMinimum(0);
                progress.setMaximum(settings.maxIterations());
                progress.setValue(0);
                progress.setString("running");
                iterationLabel.setText("0/" + settings.maxIterations());
                worker.submit(() -> orchestrator.run(target, prompt, settings, new UiListener()));
            }
        } catch (RejectedExecutionException e) {
            running.set(false);
            setRunning(false);
            Dialogs.error(root, "Extension is unloading.");
        }
    }

    private void setRunning(boolean busy) {
        SwingUtilities.invokeLater(() -> {
            stop.setEnabled(busy);
            testConn.setEnabled(!busy);
            promptBox.setEnabled(!busy);
            savePrompt.setEnabled(!busy);
            dryRun.setEnabled(!busy);
            if (!busy) {
                progress.setIndeterminate(false);
                progress.setString("done");
            }
            updateReadiness();
        });
    }


    /** Local-only: restore real values in AI-produced (masked) text, for display/report. */
    private String unmask(String maskedText) {
        try {
            return new String(service.gateway().unmask(maskedText), StandardCharsets.ISO_8859_1);
        } catch (RuntimeException e) {
            return maskedText;
        }
    }

    // --- transcript helpers -----------------------------------------------------------------

    private void append(JTextArea area, String role, String text) {
        SwingUtilities.invokeLater(() -> {
            area.append("[" + LocalTime.now().format(TIME) + "] " + role + "\n" + text + "\n\n");
            area.setCaretPosition(area.getDocument().getLength());
        });
    }

    private void setStatus(String text) {
        SwingUtilities.invokeLater(() -> progress.setString(text));
    }

    private void showVerdict(String status, String title) {
        SwingUtilities.invokeLater(() -> {
            Color color = status != null && status.toLowerCase().startsWith("vuln") ? BLOCK_RED
                    : status != null && status.toLowerCase().contains("not") ? OK_GREEN : WARN_AMBER;
            verdict.setBackground(color);
            verdict.setForeground(Color.WHITE);
            String s = status == null ? "?" : status.toUpperCase();
            verdict.setText("VERDICT: " + s + (title == null || title.isBlank() ? "" : "  —  " + title));
            verdict.setVisible(true);
        });
    }

    private void copyToClipboard(String text) {
        try {
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new java.awt.datatransfer.StringSelection(text), null);
        } catch (RuntimeException e) {
            Dialogs.error(root, "Could not copy to clipboard.");
        }
    }

    private static Font mono(JTextArea area) {
        return new Font(Font.MONOSPACED, Font.PLAIN, area.getFont().getSize());
    }

    private final class UiListener implements AgentOrchestrator.Listener {
        @Override
        public void onStatus(String s) {
            SwingUtilities.invokeLater(() -> {
                progress.setString(s);
                int slash = s.indexOf('/');
                int space = s.lastIndexOf(' ', slash);
                if (slash > 0 && space >= 0) {
                    try {
                        progress.setValue(Integer.parseInt(s.substring(space + 1, slash).trim()));
                        iterationLabel.setText(s.substring(space + 1));
                    } catch (NumberFormatException ignored) {
                        // not an "Iteration x/y" status
                    }
                }
            });
        }

        @Override
        public void onMaskedToAi(String text) {
            append(transcript, "TO AI (masked)", text);
        }

        @Override
        public void onAiReply(String text) {
            append(transcript, "AI", text);
            append(unmaskedView, "AI (unmasked)", unmask(text));
        }

        @Override
        public void onReplay(int iteration, String unmaskedRequest, long elapsedMillis, String responseSummary) {
            append(transcript, "REPLAY #" + iteration, responseSummary + "  (" + elapsedMillis + " ms)");
            append(localTraffic, "REPLAY #" + iteration + " (real request sent to target)",
                    unmaskedRequest + "\n\n<-- " + responseSummary);
            SwingUtilities.invokeLater(() -> {
                progress.setValue(iteration);
                iterationLabel.setText(iteration + "/" + progress.getMaximum());
            });
        }

        @Override
        public void onVerdict(String status, String title, String summary, String evidence,
                              byte[] pocRequest, byte[] pocResponse) {
            append(transcript, "VERDICT", status + (title == null || title.isBlank() ? "" : " — " + title)
                    + "\n" + summary + (evidence == null || evidence.isBlank() ? "" : "\nEvidence: " + evidence));
            showVerdict(status, title);
            findingsTab.record(status, title, summary, exchange, pocRequest, pocResponse);
        }

        @Override
        public void onError(String message) {
            append(transcript, "ERROR", message);
            setStatus("error");
        }

        @Override
        public void onFinished() {
            running.set(false);
            setRunning(false);
        }
    }

    private final class UiBatchListener implements BatchOrchestrator.BatchListener {
        @Override
        public void onStatus(String s) {
            setStatus(s);
        }

        @Override
        public void onPhase(String phase) {
            SwingUtilities.invokeLater(() -> {
                progress.setString(phase);
                iterationLabel.setText(phase);
            });
        }

        @Override
        public void onTranscript(String role, String text) {
            append(transcript, role, text);
            if (role.startsWith("AI")) {
                append(unmaskedView, role + " (unmasked)", unmask(text));
            }
        }

        @Override
        public void onLocal(String text) {
            append(localTraffic, "LOCAL", text);
        }

        @Override
        public void onFinding(String endpoint, String status, String title, String summary, HttpExchange exchange,
                              byte[] pocRequest, byte[] pocResponse) {
            findingsTab.record(status, title, summary, exchange, pocRequest, pocResponse);
        }

        @Override
        public void onError(String message) {
            append(transcript, "ERROR", message);
        }

        @Override
        public void onFinished(int tested, int found) {
            append(transcript, "BATCH DONE", "Tested " + tested + " endpoint(s); " + found + " finding(s).");
            SwingUtilities.invokeLater(() -> {
                verdict.setBackground(found > 0 ? BLOCK_RED : OK_GREEN);
                verdict.setForeground(Color.WHITE);
                verdict.setText("BATCH: " + found + " finding(s) across " + tested + " endpoint(s)");
                verdict.setVisible(true);
            });
            running.set(false);
            setRunning(false);
        }
    }

}
