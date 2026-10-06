package aimasker.burp;

import aimasker.burp.ui.AgentTab;
import aimasker.burp.ui.Dialogs;
import aimasker.core.control.RedactorService;
import aimasker.core.gateway.AiSafePayload;
import aimasker.core.gateway.GatewayDecision;
import aimasker.core.gateway.HttpExchange;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

/**
 * Right-click actions. Every path that lets data leave Burp (clipboard, Burp AI) goes through
 * {@link aimasker.core.gateway.AiSafeGateway#prepareExchange} and only proceeds with an
 * {@link AiSafePayload}.
 */
final class AiMaskerContextMenu implements ContextMenuItemsProvider {

    private static final String SEPARATOR = "\n\n----------------------------------------\n\n";

    private final MontoyaApi api;
    private final RedactorService service;
    private final BurpAiClient ai;
    private final ExecutorService worker;
    private final AgentTab agentTab;

    AiMaskerContextMenu(MontoyaApi api, RedactorService service, BurpAiClient ai, ExecutorService worker,
                        AgentTab agentTab) {
        this.api = api;
        this.service = service;
        this.ai = ai;
        this.worker = worker;
        this.agentTab = agentTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = selection(event);
        if (selected.isEmpty()) {
            return List.of();
        }
        JMenu menu = new JMenu("Cloak");
        JMenuItem preview = new JMenuItem("Preview AI-safe version");
        preview.addActionListener(e -> runInBackground(() -> preview(selected.get(0))));
        JMenuItem copy = new JMenuItem(selected.size() == 1
                ? "Copy AI-safe version" : "Copy AI-safe version of " + selected.size() + " items");
        copy.addActionListener(e -> runInBackground(() -> copy(selected)));
        JMenuItem ask = new JMenuItem("Ask Burp AI (masked)...");
        ask.setEnabled(selected.size() == 1 && ai.isAvailable());
        if (!ai.isAvailable()) {
            ask.setToolTipText("Burp AI is not enabled for this extension.");
        }
        ask.addActionListener(e -> askAi(selected.get(0)));
        JMenuItem sendToAgent = new JMenuItem(selected.size() == 1
                ? "Send to Agent (OpenCode)..."
                : "Send " + selected.size() + " requests to Agent (batch)...");
        sendToAgent.addActionListener(e -> sendToAgent(selected));
        JMenuItem addTarget = new JMenuItem("Add this host as a target domain...");
        addTarget.addActionListener(e -> addHostAsTarget(selected.get(0)));
        menu.add(preview);
        menu.add(copy);
        menu.add(ask);
        menu.add(sendToAgent);
        menu.addSeparator();
        menu.add(addTarget);
        return List.of(menu);
    }

    private static List<HttpRequestResponse> selection(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return List.of(event.messageEditorRequestResponse().get().requestResponse());
        }
        return event.selectedRequestResponses();
    }

    private void preview(HttpRequestResponse item) {
        GatewayDecision decision = service.gateway().previewExchange(BurpExchanges.of(item));
        SwingUtilities.invokeLater(() -> Dialogs.showDecision(parent(), "AI-safe preview", decision));
    }

    /** All-or-nothing: if any selected item is blocked, nothing is copied. */
    private void copy(List<HttpRequestResponse> items) {
        List<AiSafePayload> payloads = new ArrayList<>();
        for (int i = 0; i < items.size(); i++) {
            GatewayDecision decision = service.gateway().prepareExchange(BurpExchanges.of(items.get(i)));
            if (!decision.allowed()) {
                String title = items.size() == 1 ? "Blocked" : "Blocked (item " + (i + 1) + " of " + items.size() + ")";
                SwingUtilities.invokeLater(() -> Dialogs.showDecision(parent(), title + " - nothing copied", decision));
                return;
            }
            payloads.add(decision.payload().orElseThrow());
        }
        GatewayDecision combined = service.gateway().compose(SEPARATOR, payloads.toArray(AiSafePayload[]::new));
        if (!combined.allowed()) {
            SwingUtilities.invokeLater(() -> Dialogs.showDecision(parent(), "Blocked - nothing copied", combined));
            return;
        }
        String text = combined.payload().orElseThrow().text();
        SwingUtilities.invokeLater(() -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
            Dialogs.info(parent(), "Copied AI-safe text for " + items.size() + " item(s) ("
                    + combined.verdict() + ").");
        });
    }

    private void askAi(HttpRequestResponse item) {
        String question = Dialogs.askQuestion(parent());
        if (question == null || question.isBlank()) {
            return;
        }
        runInBackground(() -> {
            GatewayDecision exchange = service.gateway().prepareExchange(BurpExchanges.of(item));
            if (!exchange.allowed()) {
                SwingUtilities.invokeLater(() -> Dialogs.showDecision(parent(), "Blocked - not sent to AI", exchange));
                return;
            }
            GatewayDecision prompt = service.gateway().prepareText(question);
            if (!prompt.allowed()) {
                SwingUtilities.invokeLater(() -> Dialogs.showDecision(parent(), "Question blocked - not sent to AI", prompt));
                return;
            }
            GatewayDecision combined = service.gateway().compose("\n\n",
                    prompt.payload().orElseThrow(), exchange.payload().orElseThrow());
            if (!combined.allowed()) {
                SwingUtilities.invokeLater(() -> Dialogs.showDecision(parent(), "Blocked - not sent to AI", combined));
                return;
            }
            String answer;
            try {
                answer = ai.ask(combined.payload().orElseThrow());
            } catch (RuntimeException e) {
                api.logging().logToError("[Cloak] Burp AI request failed: " + e.getClass().getSimpleName());
                SwingUtilities.invokeLater(() -> Dialogs.error(parent(), "Burp AI request failed: " + e.getMessage()));
                return;
            }
            SwingUtilities.invokeLater(() -> Dialogs.showText(parent(), "Burp AI (masked input)", answer));
        });
    }

    private void sendToAgent(List<HttpRequestResponse> items) {
        List<HttpExchange> exchanges = new ArrayList<>();
        for (HttpRequestResponse item : items) {
            exchanges.add(BurpExchanges.of(item));
        }
        String label = exchanges.size() == 1
                ? exchanges.get(0).serviceUrl()
                : exchanges.get(0).host() + " + " + exchanges.size() + " requests";
        agentTab.setExchanges(exchanges, label);
        Dialogs.info(parent(), (exchanges.size() == 1 ? "Exchange" : exchanges.size() + " requests")
                + " sent to the Agent tab. Open Cloak → Agent, choose a prompt and press Start. "
                + "(Make sure 'opencode serve' is running and at least one target domain is set.)");
    }

    private void addHostAsTarget(HttpRequestResponse item) {
        HttpService httpService = item.httpService();
        String host = httpService == null ? "" : httpService.host();
        String target = Dialogs.askTarget(parent(), host);
        if (target == null || target.isBlank()) {
            return;
        }
        try {
            service.addDomain(target, Dialogs.suggestReplacement(service.config()));
        } catch (IllegalArgumentException e) {
            Dialogs.error(parent(), e.getMessage());
        }
    }

    private void runInBackground(Runnable task) {
        try {
            worker.submit(() -> {
                try {
                    task.run();
                } catch (RuntimeException e) {
                    api.logging().logToError("[Cloak] action failed: " + e.getClass().getSimpleName());
                    SwingUtilities.invokeLater(() -> Dialogs.error(parent(),
                            "Action failed (" + e.getClass().getSimpleName() + "). Nothing was sent."));
                }
            });
        } catch (RejectedExecutionException e) {
            Dialogs.error(parent(), "Cloak is unloading.");
        }
    }

    private Component parent() {
        return api.userInterface().swingUtils().suiteFrame();
    }
}
