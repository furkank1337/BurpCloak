package aimasker.burp.ui;

import aimasker.burp.opencode.OpenCodeClient;
import aimasker.core.audit.Statistics;
import aimasker.core.config.AgentSettings;
import aimasker.core.config.MaskingOptions;
import aimasker.core.config.RedactorConfig;
import aimasker.core.control.RedactorService;
import aimasker.core.domain.DomainRule;
import aimasker.core.gateway.GatewayDecision;
import aimasker.core.http.LocatedEvent;
import aimasker.core.http.ProcessingOptions;
import java.util.ArrayList;
import java.util.List;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

/** The "Cloak" suite tab: configuration, preview and audit. */
public final class AiMaskerTab {

    private static final Color ENABLED = new Color(0x2E7D32);
    private static final Color DISABLED = new Color(0xC62828);
    private static final String SAMPLE = String.join("\n",
            "GET /api HTTP/1.1",
            "Host: api.example.com",
            "Referer: https://example.com/login",
            "",
            "");

    private final RedactorService service;
    private final ExecutorService worker;
    private final BooleanSupplier burpAiAvailable;
    private final JPanel root = new JPanel(new BorderLayout());
    private final JLabel status = new JLabel();
    private final RulesTableModel rulesModel;
    private final JTable rulesTable;
    private final LineageTableModel lineageModel = new LineageTableModel();
    private final AtomicBoolean lineageDirty = new AtomicBoolean(true);
    private final JLabel[] statLabels = new JLabel[6];
    private final JCheckBox keepSubdomains = checkBox("Keep subdomain labels",
            "api.example.com -> api.redacted.com (unticked: -> redacted.com)");
    private final JCheckBox autoBrand = checkBox("Redact brand names from domains",
            "Derive a keyword from each domain: example.com -> Example, EXAMPLE, Ex-ample");
    private final JCheckBox maskSecrets = checkBox("Mask credentials & tokens",
            "JWTs, API keys, private keys, Authorization/Cookie values, password/token/secret/session fields");
    private final JCheckBox maskPersonal = checkBox("Mask personal data",
            "E-mail addresses, username/phone/address fields, card numbers, IBANs, national ID numbers");
    private final JCheckBox maskIps = checkBox("Mask IP addresses", "IPv4 (private/public kept apart) and IPv6");
    private final JCheckBox processRequests = checkBox("Process Requests", null);
    private final JCheckBox processResponses = checkBox("Process Responses", null);
    private final JCheckBox processHeaders = checkBox("Process Headers", null);
    private final JCheckBox processBodies = checkBox("Process Bodies", null);
    private final JCheckBox omitBinary = checkBox("Omit binary bodies", "Replace images, fonts and archives with a placeholder");
    private final JCheckBox verboseAudit = checkBox("Verbose audit log", "One log line per value (fingerprints only)");
    private final JTextArea customFields = new JTextArea(4, 20);
    private final JTextField agentUrl = new JTextField(22);
    private final JComboBox<String> agentModel = new JComboBox<>();
    private final JPasswordField agentPassword = new JPasswordField(22);
    private final JTextField agentMaxIterations = new JTextField(6);
    private final JTextField agentRateLimit = new JTextField(6);
    private final JTextField agentMaxEndpoints = new JTextField(6);
    private final JTextField agentEndpointIterations = new JTextField(6);
    private final JTextField agentParallelism = new JTextField(6);
    private final JTextField maxPartChars = new JTextField(8);
    private final JCheckBox addToSiteMap = checkBox("Add replayed traffic to Burp site map",
            "Discovered/tested endpoints (real traffic) appear in Target");
    private final JCheckBox createIssues = checkBox("Report findings as Burp issues",
            "Vulnerable verdicts become audit issues in Target -> Issues");
    private final Timer refreshTimer;
    private boolean updatingControls;

    public AiMaskerTab(RedactorService service, ExecutorService worker, BooleanSupplier burpAiAvailable,
                       Component agentPanel, Component agentRulesPanel, Component findingsPanel) {
        this.service = service;
        this.worker = worker;
        this.burpAiAvailable = burpAiAvailable;
        this.rulesModel = new RulesTableModel((rule, column, value) -> apply(config -> config.withRuleAdded(
                column == RulesTableModel.REPLACEMENT
                        ? rule.withReplacement(value)
                        : rule.withKeywords(RulesTableModel.manualKeywords(value)))));
        this.rulesTable = new JTable(rulesModel);

        root.add(header(), BorderLayout.NORTH);
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Configuration", configurationPanel());
        if (agentPanel != null) {
            tabs.addTab("Agent", agentPanel);
        }
        if (agentRulesPanel != null) {
            tabs.addTab("Agent Rules", agentRulesPanel);
        }
        if (findingsPanel != null) {
            tabs.addTab("Vulnerabilities", findingsPanel);
        }
        tabs.addTab("Preview", previewPanel());
        tabs.addTab("Audit", auditPanel());
        root.add(tabs, BorderLayout.CENTER);

        service.addChangeListener(() -> SwingUtilities.invokeLater(this::refreshFromConfig));
        service.lineage().addListener(record -> lineageDirty.set(true));
        refreshFromConfig();
        refreshTimer = new Timer(1000, e -> refreshCounters());
        refreshTimer.start();
    }

    public Component component() {
        return root;
    }

    public void dispose() {
        refreshTimer.stop();
    }

    private JComponent header() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        JLabel title = new JLabel("Cloak");
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize2D() + 4f));
        JLabel slogan = new JLabel("Keep the context. Remove the customer data.");
        JPanel titles = new JPanel(new GridLayout(0, 1));
        titles.add(title);
        titles.add(slogan);
        panel.add(titles, BorderLayout.WEST);

        status.setFont(status.getFont().deriveFont(Font.BOLD));
        JButton enable = new JButton("Enable");
        enable.addActionListener(e -> runSafely(service::enableRedaction));
        JButton disable = new JButton("Disable");
        disable.addActionListener(e -> runSafely(service::disableRedaction));
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        controls.add(status);
        controls.add(enable);
        controls.add(disable);
        panel.add(controls, BorderLayout.EAST);
        return panel;
    }

    private JComponent configurationPanel() {
        rulesTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        rulesTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        JButton add = new JButton("+ Add Domain");
        add.addActionListener(e -> addRule());
        JButton remove = new JButton("- Remove Domain");
        remove.addActionListener(e -> removeSelectedRules());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(add);
        buttons.add(remove);
        JPanel rules = new JPanel(new BorderLayout());
        rules.setBorder(BorderFactory.createTitledBorder("Target Domains"));
        rules.add(buttons, BorderLayout.NORTH);
        rules.add(new JScrollPane(rulesTable), BorderLayout.CENTER);
        rules.add(note("Subdomains are always covered: every subdomain contains the target domain, so leaving "
                + "it out would leak it. Brand keywords catch names without a TLD (page titles, copyright lines, "
                + "JS identifiers) with or without separators and in any case. Double-click a cell to edit it."),
                BorderLayout.SOUTH);

        JPanel options = column("Options");
        for (JCheckBox box : new JCheckBox[] {maskSecrets, maskPersonal, maskIps, keepSubdomains, autoBrand, processRequests, processResponses, processHeaders,
                processBodies, omitBinary, verboseAudit}) {
            box.addActionListener(e -> applyOptions());
            options.add(box);
        }
        options.add(note("Unticked parts are not rewritten. The leakage validator still scans the whole message, "
                + "so a message whose skipped part contains a target is blocked."));

        JPanel stats = column("Statistics (AI-bound traffic)");
        String[] names = {"Requests Scanned", "Responses Scanned", "Values Redacted", "Leakage Blocked",
            "Unknown Blocked", "Allowed"};
        JPanel grid = new JPanel(new GridLayout(0, 2, 12, 2));
        for (int i = 0; i < names.length; i++) {
            grid.add(new JLabel(names[i] + ":"));
            statLabels[i] = new JLabel("0");
            grid.add(statLabels[i]);
        }
        JPanel gridHolder = new JPanel(new BorderLayout());
        gridHolder.add(grid, BorderLayout.WEST);
        stats.add(gridHolder);
        JButton reset = new JButton("Reset counters");
        reset.addActionListener(e -> service.statistics().reset());
        stats.add(reset);

        // Sections stack at their natural height and follow the pane's width; the filler takes spare height.
        ScrollablePanel side = new ScrollablePanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.NORTH;
        c.insets = new Insets(0, 0, 6, 0);
        for (JComponent section : new JComponent[] {options, customFieldsPanel(), agentSettingsPanel(), stats}) {
            side.add(section, c);
        }
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        side.add(new JPanel(), c);

        JScrollPane sideScroll = new JScrollPane(side);
        sideScroll.setBorder(BorderFactory.createEmptyBorder());
        sideScroll.getVerticalScrollBar().setUnitIncrement(16);
        rules.setMinimumSize(new Dimension(150, 0));
        sideScroll.setMinimumSize(new Dimension(150, 0));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, rules, sideScroll);
        split.setResizeWeight(0.6);
        split.setContinuousLayout(true);
        split.setOneTouchExpandable(true);
        return split;
    }

    private JComponent customFieldsPanel() {
        JPanel panel = column("Custom field names (extra params)");
        customFields.setLineWrap(false);
        JScrollPane scroll = new JScrollPane(customFields);
        scroll.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        panel.add(scroll);
        JButton apply = new JButton("Apply custom fields");
        apply.addActionListener(e -> applyCustomFields());
        panel.add(apply);
        panel.add(note("One field name per line (e.g. internalRef). Wherever such a name appears as a key "
                + "in a request or response, its value is masked. Masked reversibly in the agent loop."));
        return panel;
    }

    private void applyCustomFields() {
        List<String> names = new ArrayList<>();
        for (String line : customFields.getText().split("\n")) {
            if (!line.isBlank()) {
                names.add(line.strip());
            }
        }
        apply(config -> config.withCustomFieldNames(names));
    }

    private JComponent agentSettingsPanel() {
        JPanel panel = column("Agent (OpenCode)");
        panel.add(labeled("OpenCode URL", agentUrl));
        agentModel.setEditable(true);
        JButton loadModels = new JButton("Load");
        loadModels.setToolTipText("Fetch models from the OpenCode server (uses the URL/password above)");
        loadModels.addActionListener(e -> loadModels());
        JPanel modelRow = new JPanel(new BorderLayout(6, 0));
        modelRow.add(agentModel, BorderLayout.CENTER);
        modelRow.add(loadModels, BorderLayout.EAST);
        panel.add(labeled("Model", modelRow));
        panel.add(labeled("Server password", agentPassword));
        panel.add(labeled("Max iterations", agentMaxIterations));
        panel.add(labeled("Rate limit (ms)", agentRateLimit));
        panel.add(labeled("Batch: max endpoints", agentMaxEndpoints));
        panel.add(labeled("Batch: iters/endpoint", agentEndpointIterations));
        panel.add(labeled("Batch: parallelism", agentParallelism));
        panel.add(labeled("Max chars/part", maxPartChars));
        panel.add(addToSiteMap);
        panel.add(createIssues);
        JButton apply = new JButton("Apply agent settings");
        apply.addActionListener(e -> applyAgentSettings());
        panel.add(apply);
        panel.add(note("Burp drives a local 'opencode serve'; only masked data is sent and replays go to the "
                + "session's locked host. The model, provider and API key are configured inside OpenCode."));
        return panel;
    }

    private void applyAgentSettings() {
        AgentSettings settings;
        int mpc;
        try {
            mpc = Integer.parseInt(maxPartChars.getText().trim());
            settings = new AgentSettings(
                    agentUrl.getText().trim(),
                    currentModelText(),
                    new String(agentPassword.getPassword()),
                    Integer.parseInt(agentMaxIterations.getText().trim()),
                    Integer.parseInt(agentRateLimit.getText().trim()),
                    service.config().agent().rules(),  // keep the edited rules from the Agent Rules tab
                    Integer.parseInt(agentMaxEndpoints.getText().trim()),
                    Integer.parseInt(agentEndpointIterations.getText().trim()),
                    Integer.parseInt(agentParallelism.getText().trim()),
                    addToSiteMap.isSelected(),
                    createIssues.isSelected());
        } catch (NumberFormatException e) {
            Dialogs.error(root, "Max iterations and rate limit must be whole numbers.");
            refreshFromConfig();
            return;
        } catch (IllegalArgumentException e) {
            Dialogs.error(root, e.getMessage());
            refreshFromConfig();
            return;
        }
        try {
            int partChars = mpc;
            service.update(config -> {
                ProcessingOptions p = config.processing();
                return config.withAgent(settings).withProcessing(new ProcessingOptions(
                        p.processRequests(), p.processResponses(), p.processHeaders(), p.processBodies(),
                        p.omitBinaryBodies(), partChars));
            });
            Dialogs.info(root, "Succeeded: agent settings saved.");
        } catch (IllegalArgumentException e) {
            Dialogs.error(root, e.getMessage());
            refreshFromConfig();
        }
    }

    private String currentModelText() {
        Object v = agentModel.getSelectedItem();
        return v == null ? "" : v.toString().trim();
    }

    /** Fetches the server's model list and fills the dropdown; keeps the current selection. */
    private void loadModels() {
        AgentSettings current = service.config().agent();
        AgentSettings probe;
        try {
            probe = new AgentSettings(agentUrl.getText().trim(), currentModelText(),
                    new String(agentPassword.getPassword()),
                    current.maxIterations(), current.rateLimitMs(), current.rules(),
                    current.maxEndpoints(), current.endpointIterations(), current.parallelism(),
                    current.addToSiteMap(), current.createIssues());
        } catch (IllegalArgumentException e) {
            Dialogs.error(root, e.getMessage());
            return;
        }
        try {
            worker.submit(() -> {
                try {
                    List<String> models = new OpenCodeClient(probe).listModels();
                    SwingUtilities.invokeLater(() -> {
                        String keep = currentModelText();
                        agentModel.setModel(new DefaultComboBoxModel<>(models.toArray(new String[0])));
                        if (!keep.isBlank()) {
                            agentModel.setSelectedItem(keep);
                        }
                        Dialogs.info(root, "Loaded " + models.size() + " model(s). Pick one and Apply.");
                    });
                } catch (RuntimeException ex) {
                    SwingUtilities.invokeLater(() -> Dialogs.error(root, "Could not load models: " + ex.getMessage()));
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException e) {
            Dialogs.error(root, "Extension is unloading.");
        }
    }

    private static JComponent labeled(String label, JComponent field) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        JLabel caption = new JLabel(label + ":");
        caption.setPreferredSize(new Dimension(110, caption.getPreferredSize().height));
        row.add(caption, BorderLayout.WEST);
        row.add(field, BorderLayout.CENTER);
        return row;
    }

    private JComponent previewPanel() {
        JTextArea original = monospace(SAMPLE, true);
        JTextArea safe = monospace("", false);
        VerdictLabel verdict = new VerdictLabel();
        verdict.showMessage("Paste a raw HTTP request or response on the left and press Run Preview.");
        JTextArea details = monospace("", false);
        details.setRows(6);

        JButton run = new JButton("Run Preview");
        run.addActionListener(e -> {
            String input = original.getText();
            verdict.showPending();
            submit(() -> {
                GatewayDecision decision = service.gateway().previewRawMessage(input);
                SwingUtilities.invokeLater(() -> {
                    verdict.show(decision);
                    safe.setText(decision.localPreview());
                    safe.setCaretPosition(0);
                    details.setText(describe(decision));
                    details.setCaretPosition(0);
                });
            });
        });

        JSplitPane texts = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                titled("ORIGINAL (stays local)", new JScrollPane(original)),
                titled("AI SAFE", new JScrollPane(safe)));
        texts.setResizeWeight(0.5);
        JPanel bottom = new JPanel(new BorderLayout());
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.add(run);
        bar.add(verdict);
        bottom.add(bar, BorderLayout.NORTH);
        bottom.add(new JScrollPane(details), BorderLayout.CENTER);
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(texts, BorderLayout.CENTER);
        panel.add(bottom, BorderLayout.SOUTH);
        return panel;
    }

    private static String describe(GatewayDecision decision) {
        StringBuilder out = new StringBuilder();
        out.append("Validator: ").append(decision.allowed() ? "PASS" : "BLOCKED").append('\n');
        for (String reason : decision.reasons()) {
            out.append("Reason: ").append(reason).append('\n');
        }
        for (String note : decision.notes()) {
            out.append("Note: ").append(note).append('\n');
        }
        for (LocatedEvent event : decision.events()) {
            out.append(event.event().type()).append(" -> ").append(event.event().replacement())
                    .append("  at ").append(event.location())
                    .append("  fingerprint ").append(event.event().fingerprint()).append('\n');
        }
        return out.toString();
    }

    private JComponent auditPanel() {
        JTable table = new JTable(lineageModel);
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> {
            service.lineage().clear();
            lineageDirty.set(true);
        });
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.add(clear);
        bar.add(new JLabel("In-memory only. Fingerprints are HMAC-SHA256 with a per-user key; originals are never stored."));
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(bar, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private void addRule() {
        String[] input = Dialogs.askRule(root, Dialogs.suggestReplacement(service.config()));
        if (input != null && !input[0].isBlank()) {
            apply(config -> config.withRuleAdded(
                    DomainRule.of(input[0], input[1], DomainRule.parseKeywords(input[2]))));
        }
    }

    private void removeSelectedRules() {
        int[] rows = rulesTable.getSelectedRows();
        String[] targets = new String[rows.length];
        for (int i = 0; i < rows.length; i++) {
            targets[i] = rulesModel.ruleAt(rulesTable.convertRowIndexToModel(rows[i])).target();
        }
        for (String target : targets) {
            runSafely(() -> service.removeDomain(target));
        }
    }

    private void applyOptions() {
        if (updatingControls) {
            return;
        }
        apply(config -> config
                .withKeepSubdomainLabels(keepSubdomains.isSelected())
                .withAutoBrandKeywords(autoBrand.isSelected())
                .withMasking(new MaskingOptions(maskSecrets.isSelected(), maskPersonal.isSelected(), maskIps.isSelected()))
                .withVerboseAudit(verboseAudit.isSelected())
                .withProcessing(new ProcessingOptions(processRequests.isSelected(), processResponses.isSelected(),
                        processHeaders.isSelected(), processBodies.isSelected(), omitBinary.isSelected(),
                        config.processing().maxPartChars())));
    }

    private void apply(java.util.function.UnaryOperator<RedactorConfig> change) {
        runSafely(() -> service.update(change));
    }

    /** Invalid input leaves the configuration unchanged and is reported; the UI is then re-synced. */
    private void runSafely(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException e) {
            Dialogs.error(root, e.getMessage());
            refreshFromConfig();
        }
    }

    private void refreshFromConfig() {
        RedactorConfig config = service.config();
        updatingControls = true;
        try {
            rulesModel.setRules(config.domainRules(), config.autoBrandKeywords());
            ProcessingOptions p = config.processing();
            keepSubdomains.setSelected(config.keepSubdomainLabels());
            autoBrand.setSelected(config.autoBrandKeywords());
            maskSecrets.setSelected(config.masking().secrets());
            maskPersonal.setSelected(config.masking().personalData());
            maskIps.setSelected(config.masking().ipAddresses());
            processRequests.setSelected(p.processRequests());
            processResponses.setSelected(p.processResponses());
            processHeaders.setSelected(p.processHeaders());
            processBodies.setSelected(p.processBodies());
            omitBinary.setSelected(p.omitBinaryBodies());
            verboseAudit.setSelected(config.verboseAudit());
            customFields.setText(String.join("\n", config.customFieldNames()));
            AgentSettings agent = config.agent();
            agentUrl.setText(agent.opencodeUrl());
            agentModel.setSelectedItem(agent.opencodeModel());
            agentPassword.setText(agent.opencodePassword());
            agentMaxIterations.setText(String.valueOf(agent.maxIterations()));
            agentRateLimit.setText(String.valueOf(agent.rateLimitMs()));
            agentMaxEndpoints.setText(String.valueOf(agent.maxEndpoints()));
            agentEndpointIterations.setText(String.valueOf(agent.endpointIterations()));
            agentParallelism.setText(String.valueOf(agent.parallelism()));
            addToSiteMap.setSelected(agent.addToSiteMap());
            createIssues.setSelected(agent.createIssues());
            maxPartChars.setText(String.valueOf(p.maxPartChars()));
        } finally {
            updatingControls = false;
        }
        if (!config.enabled()) {
            status.setForeground(DISABLED);
            status.setText("Status: DISABLED (AI transmission blocked)");
        } else if (config.domainRules().isEmpty()) {
            status.setForeground(DISABLED);
            status.setText("Status: ENABLED - no targets, everything is blocked");
        } else {
            status.setForeground(ENABLED);
            status.setText("Status: ENABLED");
        }
    }

    private void refreshCounters() {
        Statistics.Snapshot s = service.statistics().snapshot();
        long[] values = {s.requestsScanned(), s.responsesScanned(), s.valuesRedacted(), s.leakageBlocked(),
            s.unknownBlocked(), s.allowed()};
        for (int i = 0; i < values.length; i++) {
            statLabels[i].setText(String.valueOf(values[i]));
        }
        if (lineageDirty.getAndSet(false)) {
            lineageModel.setRecords(service.lineage().snapshot());
        }
    }

    private void submit(Runnable task) {
        try {
            worker.submit(task);
        } catch (RejectedExecutionException e) {
            Dialogs.error(root, "Cloak is unloading.");
        }
    }

    /** A titled section whose children are stacked vertically and stretched to its width. */
    private static JPanel column(String title) {
        JPanel panel = new JPanel(new VerticalStack());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        return panel;
    }

    private static JCheckBox checkBox(String label, String tooltip) {
        JCheckBox box = new JCheckBox(label);
        box.setToolTipText(tooltip);
        return box;
    }

    private static JComponent titled(String title, JComponent content) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(content, BorderLayout.CENTER);
        return panel;
    }

    private static JTextArea note(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        // No fixed column count: the text wraps to whatever width the section gets.
        area.setMinimumSize(new Dimension(50, 0));
        return area;
    }

    private static JTextArea monospace(String text, boolean editable) {
        JTextArea area = new JTextArea(text);
        area.setEditable(editable);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, area.getFont().getSize()));
        return area;
    }
}
