package aimasker.burp;

import aimasker.burp.agent.AgentOrchestrator;
import aimasker.burp.agent.BatchOrchestrator;
import aimasker.burp.ui.AgentRulesTab;
import aimasker.burp.ui.AgentTab;
import aimasker.burp.ui.AiMaskerTab;
import aimasker.burp.ui.FindingsTab;
import aimasker.core.audit.Fingerprinter;
import aimasker.core.control.RedactorService;
import aimasker.core.crypto.Encryptor;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Entry point loaded by Burp Suite (Montoya API).
 *
 * <p>Registers:
 * <ul>
 *   <li>the "Cloak" suite tab (configuration, preview, audit),</li>
 *   <li>a "Cloak" context menu (preview, copy AI-safe, ask Burp AI, add target),</li>
 *   <li>an "AI Safe" tab in every HTTP request/response viewer.</li>
 * </ul>
 *
 * <p>Live proxy traffic is never modified: redaction only applies to data on its way to an AI.
 */
public final class AiMaskerExtension implements BurpExtension {

    static final String NAME = "Cloak";

    /** Required for {@code api.ai()}; the user must also tick "Use AI" for this extension. */
    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return EnumSet.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        BurpAuditSink audit = new BurpAuditSink(api.logging());
        byte[] key = BurpConfigStore.loadOrCreateFingerprintKey(api.persistence().preferences());
        Fingerprinter fingerprinter = new Fingerprinter(key);
        Encryptor encryptor = new Encryptor(key);
        RedactorService service = new RedactorService(
                new BurpConfigStore(api.persistence().extensionData()), fingerprinter, encryptor, audit);

        ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "ai-masker-worker");
            thread.setDaemon(true);
            return thread;
        });
        BurpAiClient ai = new BurpAiClient(api.ai());

        BurpSink burpSink = new BurpSink(api);
        FindingsStore findingsStore = new FindingsStore(api.persistence().extensionData());
        BurpReplayer replayer = new BurpReplayer(api, burpSink, () -> service.config().agent().addToSiteMap());
        AgentOrchestrator orchestrator = new AgentOrchestrator(service.gateway(), replayer);
        BatchOrchestrator batchOrchestrator = new BatchOrchestrator(service.gateway(), replayer);
        FindingsTab findingsTab = new FindingsTab(service, worker, burpSink, findingsStore);
        AgentTab agentTab = new AgentTab(service, worker, orchestrator, batchOrchestrator, findingsTab);
        AgentRulesTab agentRulesTab = new AgentRulesTab(service);

        AiMaskerTab tab = new AiMaskerTab(service, worker, ai::isAvailable,
                agentTab.component(), agentRulesTab.component(), findingsTab.component());
        api.userInterface().applyThemeToComponent(tab.component());
        api.userInterface().registerSuiteTab(NAME, tab.component());
        api.userInterface().registerContextMenuItemsProvider(new AiMaskerContextMenu(api, service, ai, worker, agentTab));
        AiSafeEditorProvider editors = new AiSafeEditorProvider(api, service, worker);
        api.userInterface().registerHttpRequestEditorProvider(editors);
        api.userInterface().registerHttpResponseEditorProvider(editors);

        api.extension().registerUnloadingHandler(() -> {
            worker.shutdownNow();
            tab.dispose();
        });

        audit.info("Loaded. Status: " + (service.config().enabled() ? "ENABLED" : "DISABLED")
                + ", " + service.config().domainRules().size() + " target domain(s). "
                + "Live proxy traffic is not modified; only AI-bound data is redacted.");
    }
}
