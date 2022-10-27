package com.onepassword.burpanalyzer.ui;

import burp.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.onepassword.burpanalyzer.model.DecryptedPayload;
import com.onepassword.burpanalyzer.model.EncryptedMessage;
import com.onepassword.burpanalyzer.model.RequestMAC;
import com.onepassword.burpanalyzer.processing.EncryptedMessageProcessingError;
import com.onepassword.burpanalyzer.processing.Result;
import com.onepassword.burpanalyzer.processing.SessionKeyParsingError;
import com.onepassword.burpanalyzer.util.OnePasswordHeaders;
import com.onepassword.burpanalyzer.util.RequestMACParser;
import com.onepassword.burpanalyzer.util.SessionStateCache;

import java.awt.*;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class OnePasswordSessionTab implements IMessageEditorTab {

    private final IExtensionHelpers helpers;
    private final IMessageEditorController controller;

    private final OnePasswordSessionTabUI ui;
    private final AtomicBoolean isModified;

    private IHttpService httpService;
    private final SessionStateCache sessionStateCache;

    private final ObjectMapper mapper = new ObjectMapper();

    private final boolean editable;
    private boolean isRequest;

    private final AtomicReference<byte[]> sessionKey = new AtomicReference<>();
    private final AtomicReference<String> keyId = new AtomicReference<>();
    private final AtomicLong requestId = new AtomicLong();
    private final AtomicReference<String> decryptedPayloadText = new AtomicReference<>();
    private final AtomicReference<String> httpMessageText = new AtomicReference<>();

    public OnePasswordSessionTab(IExtensionHelpers helpers, IMessageEditorController controller,
                                 boolean editable, IBurpExtenderCallbacks unused) {
        this.helpers = helpers;
        this.controller = controller;
        this.editable = editable;
        this.sessionStateCache = SessionStateCache.getInstance();

        this.isModified = new AtomicBoolean(false);

        ui = new OnePasswordSessionTabUI(this, editable);
    }

    @Override
    public String getTabCaption() {
        return "1Password session";
    }

    @Override
    public Component getUiComponent() {
        return ui;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        if(content.length == 0) { // Burp sends multiple empty requests on extension load
            return false;
        }

        if(isRequest) {
            final var request = helpers.analyzeRequest(getHttpService(content), content);
            return OnePasswordHeaders.isOnePasswordRequest(request.getHeaders());
        } else { // Responses don't have as clear markers, we're matching on the contents of the CSP
            final var response = helpers.analyzeResponse(content);
            return OnePasswordHeaders.isOnePasswordResponse(response.getHeaders());
        }
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.isRequest = isRequest;
        isModified.set(false);

        if(controller != null) {
            httpService = controller.getHttpService();
        }

        final var messageText = helpers.bytesToString(content);
        processHttpMessageUpdate(messageText);

        if(isRequest) {
            final var headers = helpers.analyzeRequest(content).getHeaders();

            // Requests send a session ID which is equal to the keyID. Grab from the header and fill.
            final var sessionId = OnePasswordHeaders.parseSessionIdFromHeaders(headers);

            if(sessionId.isPresent()) {
                this.keyId.set(sessionId.get());
                ui.setKeyIdInput(sessionId.get());
            }

            httpService = getHttpService(content);

            // Attempt to set the request id
            final Optional<Integer> requestId;

            if(editable && sessionId.isPresent()) {
                // If this is editable (intercept or repeater), set the request id to be the latest seen plus one
                requestId = sessionStateCache.findLatestRequestId(sessionId.get())
                                .map(reqId -> reqId + 1);
            } else {
                // If not editable or no session id is present, try to find the request id in the request itself
                requestId = OnePasswordHeaders.parseRequestIdFromHeaders(headers);
            }

            if(requestId.isPresent()) {
                this.requestId.set(requestId.get());
                ui.setRequestIdInput(requestId.get());
            }
        } else { // On responses, attempt to set the KeyId by fetching it from the payload
            ui.removeRequestIdInput(); // There is no request id on responses

            final var response = helpers.analyzeResponse(content);
            final var responseBody = Arrays.copyOfRange(content, response.getBodyOffset(), content.length);

            try {
                final var em = mapper.readValue(responseBody, EncryptedMessage.class);
                this.keyId.set(em.getKeyIdentifier());
                ui.setKeyIdInput(em.getKeyIdentifier());
            } catch(IOException ignored) {
                // If parsing fails, then the key id will simply be empty
            }
        }
    }

    private void updateDecryptedPayload(final byte[] sessionKey, final EncryptedMessage encrypted) {
        final var decrypted = encrypted.decrypt(sessionKey);

        final var text = decrypted.checkResult().map( dm -> {
            final var body = dm.getBody();
            if(body != null && body.length > 0) {
                return helpers.bytesToString(body);
            } else {
                return "";
            }
        }).orElseGet(() -> decrypted.getError().getReadableError());

        ui.showNoErrors();
        this.decryptedPayloadText.set(text);
        ui.setProcessedDecryptedPayloadText(text);
    }

    private void updateRequestMac(final byte[] sessionKey, final RequestMAC requestMac, final byte[] httpMessage) {
        final var requestMacStr = requestMac.generateRequestHeader(sessionKey);

        if(requestMacStr.isOk()) {
            final var requestMacNew = requestMacStr.getResult();
            final var requestStr = helpers.bytesToString(httpMessage);

            // Find request MAC positions in original text
            // The request MAC begins after the X-AgileBits-MAC: header, including the space between those.
            final int requestMacBegin = requestStr.toLowerCase().indexOf(OnePasswordHeaders.MAC_HEADER_NAME.toLowerCase()) +
                                            OnePasswordHeaders.MAC_HEADER_NAME.length() + 2; // header is followed by ": "
            // The request MAC ends when the carriage return character after that is encountered
            final int requestMacEnd = requestMacBegin + requestStr.substring(requestMacBegin).indexOf('\r');

            if(requestMacBegin < requestMacEnd) {
                // Put the the new string together and update
                final var updatedRequestStr = requestStr.substring(0, requestMacBegin)
                        + requestMacNew
                        + requestStr.substring(requestMacEnd);

                this.httpMessageText.set(updatedRequestStr);
                ui.setProcessedHttpMessageText(updatedRequestStr);
                ui.showNoErrors();
            } else {
                ui.showError("Failed to find replace MAC in original body.");
            }
        } else {
            ui.showError("Failed to generate request MAC: " + requestMacStr.getError().getReadableError());
        }
    }

    private void updateEncrypted(final String keyIdentifier, final byte[] iv, final byte[] sessionKey, final DecryptedPayload decryptedPayload) {
        final var origTextBytes = helpers.stringToBytes(this.httpMessageText.get());

        if(origTextBytes.length > 0) { // This can be empty in case this function is fired when before the message has been set. In that case, don't perform updates.
            final String newText;

            final int bodyOffset = isRequest ? helpers.analyzeRequest(origTextBytes).getBodyOffset() :
                    helpers.analyzeResponse(origTextBytes).getBodyOffset();

            byte[] headerBytes = Arrays.copyOfRange(origTextBytes, 0, bodyOffset);

            if(!helpers.bytesToString(decryptedPayload.getBody()).isBlank()) {
                final var result = decryptedPayload.encrypt(keyIdentifier, iv, sessionKey);
                final var text = result.checkResult().map(em -> {
                    try {
                        return mapper.writeValueAsString(em);
                    } catch (JsonProcessingException e) {
                        return "Error writing message to JSON.";
                    }
                }).orElseGet(() -> result.getError().getReadableError());

                newText = helpers.bytesToString(headerBytes) + text;
            } else {
                newText = helpers.bytesToString(headerBytes) + "\n";
            }

            isModified.set(true);

            this.httpMessageText.set(newText);
            ui.setProcessedHttpMessageText(newText);
            ui.showNoErrors();
        }
    }

    public void processKeyIdUpdate(final String input) {
        this.keyId.set(input);

        if(input.length() == 26) {
            final var sessionKey = Optional.ofNullable(this.sessionKey.get());
            if(sessionKey.isPresent()) {
                new Thread(() -> {
                    updateEncrypted(input, fetchIvOrGenerate(), sessionKey.get(), decryptedPayload());
                }).start();
            } else {
                final var skFromCache = sessionStateCache.findSessionKey(input);
                if(skFromCache.isPresent()) {
                    this.sessionKey.set(skFromCache.get());
                    ui.setSessionKey(skFromCache.get());
                } else {
                    ui.showError("No session key available.");
                }
            }
        }
    }

    private byte[] fetchIvOrGenerate() {
        final var em = fetchEncryptedMessage();

        if(em.isOk()) {
            return em.getResult().getIv();
        } else {
            var buf = new byte[12];
            var rand = new SecureRandom();
            rand.nextBytes(buf);
            return buf;
        }
    }

    private DecryptedPayload decryptedPayload() {
        return new DecryptedPayload(helpers.stringToBytes(this.decryptedPayloadText.get()));
    }

    private Result<EncryptedMessage, EncryptedMessageProcessingError> fetchEncryptedMessage() {
        final var bodyText = helpers.bytesToString(getBodyBytes());

        if(bodyText.isBlank()) {
            return new Result<>(EncryptedMessageProcessingError.EMPTY);
        }

        try {
            return new Result<>(mapper.readValue(bodyText, EncryptedMessage.class));
        } catch (IOException e) {
            return new Result<>(EncryptedMessageProcessingError.INVALID_BODY);
        }
    }

    private String fetchKeyId() {
        return this.keyId.get();
    }

    private byte[] getBodyBytes() {
        final var message = this.httpMessageText.get();

        if(message != null) {
            final var messageBytes = helpers.stringToBytes(message);
            final var bodyOffset = isRequest ? helpers.analyzeRequest(this.getHttpService(messageBytes), messageBytes).getBodyOffset() : helpers.analyzeResponse(messageBytes).getBodyOffset();
            return Arrays.copyOfRange(messageBytes, bodyOffset, messageBytes.length);
        } else {
            return new byte[]{};
        }
    }

    public void processHttpMessageUpdate(final String input) {
        final var sessionKey = Optional.ofNullable(this.sessionKey.get());

        new Thread(() -> {
            httpMessageText.set(input);
            ui.setProcessedHttpMessageText(input);

            final var messageBytes = helpers.stringToBytes(input);
            final byte[] body;

            if(isRequest) {
                final var request = helpers.analyzeRequest(this.getHttpService(messageBytes), messageBytes);
                final var requestMacParseRes = RequestMACParser.parseRequestMac(request);

                if(sessionKey.isPresent()) {
                    if(requestMacParseRes.didSucceed()) {
                        updateRequestMac(sessionKey.get(), requestMacParseRes.getRequestMAC(), messageBytes);
                    } else {
                        ui.showError(requestMacParseRes.getParseFailure().getReadableError());
                    }
                } else {
                    ui.showError("Can't update request MAC. No valid session key is available.");
                }

                final var bodyOffset = helpers.analyzeRequest(this.getHttpService(messageBytes), messageBytes).getBodyOffset();
                body = Arrays.copyOfRange(messageBytes, bodyOffset, messageBytes.length);
            } else {
                final var bodyOffset = helpers.analyzeResponse(messageBytes).getBodyOffset();
                body = Arrays.copyOfRange(messageBytes, bodyOffset, messageBytes.length);
            }

            if(sessionKey.isPresent()) {
                EncryptedMessage encryptedMessage;

                try {
                    encryptedMessage = mapper.readValue(body, EncryptedMessage.class);
                } catch (IOException e) {
                    encryptedMessage = EncryptedMessage.empty(); // Assume parsing fails because of empty body
                }

                updateDecryptedPayload(sessionKey.get(), encryptedMessage);
            } else if(!helpers.bytesToString(body).isBlank()) {
                ui.showError("Can't decrypt body");
            }

        }).start();
    }

    public void processSessionKeyUpdate(final String input) {
        final var parsedSessionKey = parseSessionKey(input);
        final var keyId = fetchKeyId();
        final var encryptedMessage = fetchEncryptedMessage();

        if(parsedSessionKey.isOk()) {
            final var sk = parsedSessionKey.getResult();

            if(keyId != null && !keyId.isBlank()) {
                sessionStateCache.setSessionKey(keyId, sk);
            } else if(encryptedMessage.isOk()) {
                sessionStateCache.setSessionKey(encryptedMessage.getResult().getKeyIdentifier(), sk);
            }

            this.sessionKey.set(sk);

            if(encryptedMessage.isOk()) {
                final var messageBytes = helpers.stringToBytes(this.httpMessageText.get());

                new Thread(() -> {
                    if(isRequest) {
                        final var request = helpers.analyzeRequest(getHttpService(messageBytes), messageBytes);
                        final var requestMacParseRes = RequestMACParser.parseRequestMac(request);
                        if(requestMacParseRes.didSucceed()) {
                            updateRequestMac(sk, requestMacParseRes.getRequestMAC(), messageBytes);
                        } else {
                            ui.showError(requestMacParseRes.getParseFailure().getReadableError());
                        }
                    }

                    updateDecryptedPayload(sk, encryptedMessage.getResult());
                }).start();
            } else if(encryptedMessage.getError().equals(EncryptedMessageProcessingError.EMPTY)) {
                ui.showNoErrors(); // Don't show errors when we can't decrypt an empty message
            } else {
                ui.showError(encryptedMessage.getError().getReadableError());
            }
        } else {
            ui.showError(parsedSessionKey.getError().getReadableError());
        }
    }

    private Result<byte[], SessionKeyParsingError> parseSessionKey(final String input) {
        switch(input.length()) {
            case 43:
                var decoded = Base64.getUrlDecoder().decode(input);
                if(decoded != null) {
                    return new Result<>(decoded);
                } else {
                    return new Result<>(SessionKeyParsingError.INVALID_BASE64_URL);
                }
            case 0: return new Result<>(SessionKeyParsingError.EMPTY);
            default: return new Result<>(SessionKeyParsingError.INVALID_LENGTH);
        }
    }

    public void processDecryptedMessageUpdate(final String input) {
        final var sessionKey = Optional.ofNullable(this.sessionKey.get());
        final var keyId = Optional.ofNullable(this.keyId.get());
        final var iv = fetchIvOrGenerate();

        if(sessionKey.isPresent() && keyId.isPresent()) {
            new Thread(() -> {
                final var decryptedMessage = new DecryptedPayload(helpers.stringToBytes(input));
                updateEncrypted(keyId.get(), iv, sessionKey.get(), decryptedMessage);
            }).start();
        } else {
            if(sessionKey.isEmpty()) { ui.showError("Can't create encrypted message. No session key available."); }
            if(keyId.isEmpty()) { ui.showError("Can't create encrypted message. No key id available."); }
        }
    }


    public void processRequestIdUpdate(final long newRequestId) {
        final var sessionKey = Optional.ofNullable(this.sessionKey.get());
        final var httpMessage = this.httpMessageText.get();

        if(isRequest && sessionKey.isPresent()) {
            this.requestId.set(newRequestId);

            new Thread(() -> {
                final var messageBytes = helpers.stringToBytes(httpMessage);
                final var currentRequest = helpers.analyzeRequest(getHttpService(messageBytes), messageBytes);

                final var currentRequestMacRes = RequestMACParser.parseRequestMac(currentRequest);

                if(currentRequestMacRes.didSucceed()) {
                    final var currentMac = currentRequestMacRes.getRequestMAC();
                    final var newMac = new RequestMAC(
                            currentMac.getVersionIndicator(),
                            currentMac.getRequestMethod(),
                            currentMac.getSessionId(),
                            newRequestId,
                            currentMac.getHost(),
                            currentMac.getUriPath(),
                            currentMac.getQueryString()
                    );

                    updateRequestMac(sessionKey.get(), newMac, messageBytes);
                }
            }).start();
        } else {
            ui.showError("Can't apply new request ID without session key.");
        }
    }

    @Override
    public byte[] getMessage() {
        return helpers.stringToBytes(this.httpMessageText.get());
    }

    @Override
    public boolean isModified() {
        final var result = isModified.get();
        isModified.set(false);
        return result;
    }

    @Override
    public byte[] getSelectedData() {
        return helpers.stringToBytes(ui.getSelectedData());
    }

    private IHttpService getHttpService(byte[] request) {
        // httpService is only set in HTTP Proxy view, but not in the repeater. For the repeater, we construct it manually here.
        if(httpService == null) {
            httpService = helpers.analyzeRequest(request).getHeaders().stream()
                .filter(header -> header.startsWith("Host:"))
                .findFirst()
                .map(header -> header.split(":", 2))
                .filter(split -> split.length == 2)
                .map(split -> split[1])
                .map(hostFromHeader -> hostFromHeader.split(":", 2))
                .map(hostPortPair -> {
                    final var host = hostPortPair[0].trim();
                    int port = 443;
                    if(hostPortPair.length == 2) {
                        try {
                            port = Integer.parseInt(hostPortPair[1].trim());
                        } catch (NumberFormatException ignored) { }
                    }

                    final int resultPort = port;

                    return new IHttpService() {
                        @Override public String getHost()       { return host; }
                        @Override public int    getPort()       { return resultPort; }
                        @Override public String getProtocol()   { return "https"; }
                    };
                }).orElseThrow();
        }
        return httpService;
    }
}
