package aimasker.burp;

import aimasker.burp.ui.VerdictLabel;
import aimasker.core.control.RedactorService;
import aimasker.core.gateway.GatewayDecision;
import aimasker.core.http.MessageKind;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import java.awt.BorderLayout;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

/**
 * Adds a read-only "AI Safe" tab next to Raw/Pretty/Hex in every HTTP message viewer, showing
 * exactly what the redactor would produce and whether it would be allowed to leave Burp.
 */
final class AiSafeEditorProvider implements HttpRequestEditorProvider, HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final RedactorService service;
    private final ExecutorService worker;

    AiSafeEditorProvider(MontoyaApi api, RedactorService service, ExecutorService worker) {
        this.api = api;
        this.service = service;
        this.worker = worker;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new RequestEditor();
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new ResponseEditor();
    }

    private abstract class AiSafeEditor {
        private final RawEditor editor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        private final VerdictLabel status = new VerdictLabel();
        private final JPanel panel = new JPanel(new BorderLayout());
        /** Discards results of superseded background renders when the user clicks quickly. */
        private final AtomicLong generation = new AtomicLong();
        protected HttpRequestResponse current;

        AiSafeEditor() {
            panel.add(status, BorderLayout.NORTH);
            panel.add(editor.uiComponent(), BorderLayout.CENTER);
        }

        void show(HttpRequestResponse requestResponse, MessageKind kind) {
            current = requestResponse;
            long ticket = generation.incrementAndGet();
            status.showPending();
            editor.setContents(ByteArray.byteArray(""));
            byte[] raw = kind == MessageKind.REQUEST
                    ? requestResponse.request().toByteArray().getBytes()
                    : requestResponse.response().toByteArray().getBytes();
            try {
                worker.submit(() -> {
                    GatewayDecision decision = service.gateway().previewMessage(raw, kind);
                    SwingUtilities.invokeLater(() -> {
                        if (generation.get() == ticket) {
                            status.show(decision);
                            editor.setContents(ByteArray.byteArray(decision.localPreview().getBytes(StandardCharsets.UTF_8)));
                        }
                    });
                });
            } catch (RejectedExecutionException e) {
                status.showMessage("Extension is unloading.");
            }
        }

        public String caption() {
            return "AI Safe";
        }

        public Component uiComponent() {
            return panel;
        }

        public Selection selectedData() {
            return editor.selection().orElse(null);
        }

        public boolean isModified() {
            return false;
        }
    }

    private final class RequestEditor extends AiSafeEditor implements ExtensionProvidedHttpRequestEditor {
        @Override
        public HttpRequest getRequest() {
            return current.request();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            show(requestResponse, MessageKind.REQUEST);
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return requestResponse.request() != null;
        }
    }

    private final class ResponseEditor extends AiSafeEditor implements ExtensionProvidedHttpResponseEditor {
        @Override
        public HttpResponse getResponse() {
            return current.response();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            show(requestResponse, MessageKind.RESPONSE);
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return requestResponse.response() != null;
        }
    }
}
