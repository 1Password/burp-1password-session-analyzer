package burp;

import com.onepassword.burpanalyzer.ui.OnePasswordSessionTab;
import com.onepassword.burpanalyzer.util.OnePasswordHeaders;
import com.onepassword.burpanalyzer.util.SessionStateCache;

@SuppressWarnings("unused")
public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IProxyListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("1Password Session Analyzer");

        callbacks.registerMessageEditorTabFactory(this);
        callbacks.registerProxyListener(this);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new OnePasswordSessionTab(this.helpers, controller, editable, callbacks);
    }

    // We implement this to observe the latest request ids from the HTTP history, so we can automatically set these
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if(messageIsRequest) {
            final var info = message.getMessageInfo();
            final var headers = helpers.analyzeRequest(info.getHttpService(), info.getRequest()).getHeaders();

            if(OnePasswordHeaders.isOnePasswordRequest(headers)) {
                final var sessionId = OnePasswordHeaders.parseSessionIdFromHeaders(headers);
                final var requestId = OnePasswordHeaders.parseRequestIdFromHeaders(headers);

                if(sessionId.isPresent() && requestId.isPresent()) {
                    SessionStateCache.getInstance().setLatestRequestId(sessionId.get(), requestId.get());
                }
            }
        }
    }
}
