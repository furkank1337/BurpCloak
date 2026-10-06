package aimasker.burp.ui;

import aimasker.burp.BurpSink;
import aimasker.burp.Finding;
import aimasker.burp.FindingsStore;
import aimasker.burp.PdfExporter;
import aimasker.burp.ReportRenderer;
import aimasker.core.control.RedactorService;
import aimasker.core.gateway.HttpExchange;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

/**
 * The "Vulnerabilities" suite tab: the running list of AI-reported findings, with reproduce,
 * export and clear. Fed by the agent session via {@link #record}. Confirmed findings and
 * inconclusive ("potential") ones are kept; not-vulnerable verdicts are ignored.
 */
public final class FindingsTab {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final RedactorService service;
    private final ExecutorService worker;
    private final BurpSink burpSink;
    private final FindingsStore findingsStore;

    private final JPanel root = new JPanel(new BorderLayout());
    private final DefaultTableModel model =
            new DefaultTableModel(new Object[] {"Time", "Source", "Target", "Finding"}, 0) {
                private static final long serialVersionUID = 1L;
                @Override public boolean isCellEditable(int r, int c) { return false; }
            };
    private final JTable table = new JTable(model);
    private final List<Finding> findingList = new ArrayList<>();

    public FindingsTab(RedactorService service, ExecutorService worker, BurpSink burpSink, FindingsStore findingsStore) {
        this.service = service;
        this.worker = worker;
        this.burpSink = burpSink;
        this.findingsStore = findingsStore;

        JButton repeater = new JButton("Send to Repeater");
        repeater.addActionListener(e -> sendSelectedToRepeater());
        JButton exportMd = new JButton("Export (Markdown)");
        exportMd.addActionListener(e -> exportReport());
        JButton exportPdf = new JButton("Export (PDF)");
        exportPdf.addActionListener(e -> exportPdf());
        JButton clear = new JButton("Clear findings");
        clear.addActionListener(e -> clearFindings());
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.add(repeater);
        bar.add(exportMd);
        bar.add(exportPdf);
        bar.add(clear);

        JPanel hint = new JPanel(new BorderLayout());
        JLabel note = new JLabel("Vulnerabilities reported by the AI agent. Confirm each one manually.");
        note.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        hint.add(note, BorderLayout.WEST);

        JPanel top = new JPanel(new BorderLayout());
        top.add(bar, BorderLayout.NORTH);
        top.add(hint, BorderLayout.SOUTH);

        root.add(top, BorderLayout.NORTH);
        root.add(new JScrollPane(table), BorderLayout.CENTER);

        loadPersistedFindings();
    }

    public Component component() {
        return root;
    }

    /** Records a vulnerable/inconclusive verdict as a finding; ignores not-vulnerable ones. */
    public void record(String status, String title, String summary, HttpExchange source,
                       byte[] pocRequest, byte[] pocResponse) {
        if (source == null || !reportable(status)) {
            return;
        }
        byte[] request = pocRequest != null && pocRequest.length > 0 ? pocRequest : source.request();
        byte[] response = pocResponse != null && pocResponse.length > 0 ? pocResponse : source.response();
        String titleOnly = title == null || title.isBlank() ? status : title;
        Finding finding = new Finding(LocalTime.now().format(TIME), endpointLine(source), titleOnly, status, summary,
                source.host(), source.port(), source.secure(), request, response);
        SwingUtilities.invokeLater(() -> {
            findingList.add(finding);
            model.addRow(new Object[] {finding.time(), "AI", source.serviceUrl() + "  " + finding.endpoint(),
                    displayLabel(finding)});
            findingsStore.save(findingList);
        });
        if (service.config().agent().createIssues()) {
            burpSink.reportIssue(displayLabel(finding), unmask(summary), finding.vulnerable(),
                    request, response, source.host(), source.port(), source.secure());
        }
    }

    private static boolean reportable(String status) {
        if (status == null) {
            return false;
        }
        String s = status.toLowerCase();
        return s.startsWith("vuln") || s.contains("inconclus");
    }

    private static String displayLabel(Finding f) {
        String title = f.title() == null || f.title().isBlank() ? f.status() : f.title();
        return f.potential() ? "[POTENTIAL] " + title : title;
    }

    private void sendSelectedToRepeater() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= findingList.size()) {
            Dialogs.error(root, "Select a finding row first.");
            return;
        }
        Finding f = findingList.get(row);
        burpSink.sendToRepeater(f.request(), f.host(), f.port(), f.secure(), "Cloak: " + f.endpoint());
        Dialogs.info(root, "Sent to Repeater (unmasked).");
    }

    private void clearFindings() {
        findingList.clear();
        model.setRowCount(0);
        findingsStore.save(findingList);
    }

    private void loadPersistedFindings() {
        for (Finding f : findingsStore.load()) {
            findingList.add(f);
            model.addRow(new Object[] {f.time(), "AI",
                    (f.secure() ? "https" : "http") + "://" + f.host() + ":" + f.port() + "  " + f.endpoint(),
                    displayLabel(f)});
        }
    }

    private void exportReport() {
        if (findingList.isEmpty()) {
            Dialogs.error(root, "No findings to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("cloak-findings.md"));
        if (chooser.showSaveDialog(root) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        StringBuilder md = new StringBuilder("# Cloak findings (AI-reported)\n\n");
        md.append("_").append(findingList.size()).append(" finding(s). Confirm manually before acting._\n\n");
        int i = 1;
        for (Finding f : findingList) {
            md.append("## ").append(i++).append(". ").append(f.potential() ? "[POTENTIAL] " : "")
                    .append(f.title()).append("\n\n")
                    .append("- Target: `").append(f.secure() ? "https" : "http").append("://")
                    .append(f.host()).append(':').append(f.port()).append("`\n")
                    .append("- Endpoint: `").append(f.endpoint()).append("`\n")
                    .append("- Status: **").append(f.status()).append("**\n")
                    .append("- Time: ").append(f.time()).append("\n\n")
                    .append(unmask(f.summary())).append("\n\n");
            if (f.request() != null && f.request().length > 0) {
                md.append("**Proof of concept (request):**\n\n```http\n")
                        .append(new String(f.request(), StandardCharsets.ISO_8859_1).stripTrailing())
                        .append("\n```\n\n");
            }
        }
        try {
            Files.writeString(chooser.getSelectedFile().toPath(), md.toString(), StandardCharsets.UTF_8);
            Dialogs.info(root, "Succeeded: report written to " + chooser.getSelectedFile().getName());
        } catch (java.io.IOException e) {
            Dialogs.error(root, "Could not write file: " + e.getMessage());
        }
    }

    private void exportPdf() {
        if (findingList.isEmpty()) {
            Dialogs.error(root, "No findings to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("cloak-findings.pdf"));
        if (chooser.showSaveDialog(root) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File target = chooser.getSelectedFile();
        String html = ReportRenderer.html(new ArrayList<>(findingList), this::unmask);
        try {
            worker.submit(() -> {
                try {
                    String browser = PdfExporter.toPdf(html, target);
                    SwingUtilities.invokeLater(() -> Dialogs.info(root,
                            "Succeeded: PDF written to " + target.getName() + " (via " + browser + ")."));
                } catch (PdfExporter.PdfUnavailableException ex) {
                    java.io.File htmlFile = new java.io.File(target.getAbsolutePath().replaceAll("\\.pdf$", "") + ".html");
                    try {
                        Files.writeString(htmlFile.toPath(), html, StandardCharsets.UTF_8);
                        SwingUtilities.invokeLater(() -> Dialogs.info(root,
                                "No headless browser found for direct PDF. Saved styled report as "
                                + htmlFile.getName() + " - open it and use Print → Save as PDF."));
                    } catch (java.io.IOException io) {
                        SwingUtilities.invokeLater(() -> Dialogs.error(root, "Could not write report: " + io.getMessage()));
                    }
                } catch (java.io.IOException ex) {
                    SwingUtilities.invokeLater(() -> Dialogs.error(root, "PDF export failed: " + ex.getMessage()));
                }
            });
        } catch (RejectedExecutionException e) {
            Dialogs.error(root, "Extension is unloading.");
        }
    }

    /** Local-only: restore real values in the AI's masked summary for the report/issue. */
    private String unmask(String maskedText) {
        try {
            return new String(service.gateway().unmask(maskedText), StandardCharsets.ISO_8859_1);
        } catch (RuntimeException e) {
            return maskedText;
        }
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
}
