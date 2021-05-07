package com.onepassword.burpanalyzer.ui;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import java.awt.*;
import java.util.*;

public class OnePasswordSessionTabUI extends JPanel {
    private final OnePasswordSessionTab main;

    private final DocumentListener decryptedBodyInputDocumentListener;
    private final DocumentListener httpMessageDocumentListener;

    private final RSyntaxTextArea decryptedPayloadText;
    private final RSyntaxTextArea httpMessageText;

    private final JTextField sessionKeyText;
    private final JTextField keyIdText;

    private final JPanel requestIdPanel;
    private final JSpinner requestIdSpinner;
    private final JLabel errorMessageLabel;

    public void setKeyIdInput(String keyIdText) {
        this.keyIdText.setText(keyIdText);
    }

    public void setRequestIdInput(int requestId) {
        requestIdSpinner.setValue(requestId);
    }

    public void removeRequestIdInput() {
        this.requestIdPanel.setVisible(false);
        this.requestIdPanel.setEnabled(false);
    }

    public void setSessionKey(byte[] sessionKey) {
        final var sessionKeyString = Base64.getUrlEncoder()
                                                .encodeToString(sessionKey)
                                                .replaceAll("=", "");

        sessionKeyText.setText(sessionKeyString);
    }

    public OnePasswordSessionTabUI(OnePasswordSessionTab main, boolean editable) {
        this.main = main;

        // Permit using RSyntaxArea in a Burp context
        RSyntaxTextAreaHacks();

        // > Define two main panels
        final var sessionParametersPanel = new JPanel();                // Panel for the session parameters (session key, key id, request id)

        // >> Define panels for all editable session parameters
        final var sessionKeyPanel = new JPanel();                       // Panel for components editing the session key
        final var keyIdPanel = new JPanel();                            // Panel for components editing the key id
        this.requestIdPanel = new JPanel();                        // Panel for components editing the request id
        final var errorPanel = new JPanel();                            // Panel for showing errors in current session parameters

        // >>> Set up session key panel
        final var sessionKeyLabel = new JLabel("Session key:");
        final var sessionKeyText = new JTextField();
        sessionKeyLabel.setLabelFor(sessionKeyText);

        sessionKeyPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        sessionKeyPanel.add(sessionKeyLabel);
        sessionKeyPanel.add(sessionKeyText);

        // >>> Set up key id panel
        final var keyIdLabel = new JLabel("Key ID:");
        final var keyIdText = new JTextField();
        keyIdLabel.setLabelFor(keyIdText);

        keyIdPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        keyIdPanel.add(keyIdLabel);
        keyIdPanel.add(keyIdText);

        // >>> Set up request id panel
        final var requestIdLabel = new JLabel("Request ID:");
        final var requestIdSpinner = new JSpinner(new SpinnerNumberModel(0, 0, Integer.MAX_VALUE, 1));

        requestIdLabel.setLabelFor(requestIdSpinner);
        requestIdPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        requestIdPanel.add(requestIdLabel);
        requestIdPanel.add(requestIdSpinner);

        // >>> Set up error message panel
        final var errorMessageLabel = new JLabel();

        errorPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        errorPanel.add(errorMessageLabel);

        // >> Add individual parameter panels to main session parameter panel
        sessionParametersPanel.setLayout(new BoxLayout(sessionParametersPanel, BoxLayout.Y_AXIS));
        sessionParametersPanel.add(sessionKeyPanel);
        sessionParametersPanel.add(keyIdPanel);
        sessionParametersPanel.add(requestIdPanel);
        sessionParametersPanel.add(errorPanel);

        // -- End of session parameters panel, now defining editors pane

        // >> Set up two main panels for the two editors
        final var decryptedPayloadPanel = new JPanel();
        final var httpMessagePanel = new JPanel();

        // >>> Set up decrypted payload panel
        final var decryptedPayloadLabelPanel = new JPanel();
        final var decryptedPayloadScrollPane = new RTextScrollPane();

        // >>>> Set up label for decrypted payload panel
        final var decryptedPayloadLabel = new JLabel("Decrypted payload:");

        decryptedPayloadLabelPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        decryptedPayloadLabelPanel.add(decryptedPayloadLabel);

        // >>>> Configure decrypted body text area
        final var decryptedPayloadText = new RSyntaxTextArea();
        decryptedPayloadScrollPane.setViewportView(decryptedPayloadText);
        decryptedPayloadScrollPane.setLineNumbersEnabled(true);

        decryptedPayloadText.setLineWrap(true);
        decryptedPayloadText.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);

        decryptedPayloadScrollPane.setFoldIndicatorEnabled(true);
        decryptedPayloadScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        decryptedPayloadScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);

        // >>>> Associate decrypted body label with decrypted body text input
        decryptedPayloadLabel.setLabelFor(decryptedPayloadText);

        // >>> Add label and editor to the decrypted payload panel
        decryptedPayloadPanel.setLayout(new BoxLayout(decryptedPayloadPanel, BoxLayout.Y_AXIS));
        decryptedPayloadPanel.add(decryptedPayloadLabelPanel);
        decryptedPayloadPanel.add(decryptedPayloadScrollPane);

        // --- End of decrypted payload panel, start of HTTP message panel

        // >>> Set up http message panel
        final var httpMessageLabelPanel = new JPanel();
        final var httpMessageScrollPane = new RTextScrollPane();

        // >>>> Set up label for http message panel
        final var httpMessageLabel = new JLabel("HTTP message:");

        httpMessageLabelPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        httpMessageLabelPanel.add(httpMessageLabel);

        // >>>> Configure http message text area
        final var httpMessageText = new RSyntaxTextArea();
        httpMessageScrollPane.setViewportView(httpMessageText);
        httpMessageScrollPane.setLineNumbersEnabled(true);

        httpMessageText.setLineWrap(true);
        httpMessageText.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);

        httpMessageScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        httpMessageScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);

        // >>>> Associate HTTP message label with http message text input
        httpMessageLabel.setLabelFor(httpMessageText);

        // >>> Add label and editor to the http message panel
        httpMessagePanel.setLayout(new BoxLayout(httpMessagePanel, BoxLayout.Y_AXIS));
        httpMessagePanel.add(httpMessageLabelPanel);
        httpMessagePanel.add(httpMessageScrollPane);

        // >> Add main panels to the split pane
        final var editorPanel = new JPanel();
        final var editorPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, decryptedPayloadPanel, httpMessagePanel);
        editorPanel.setLayout(new BoxLayout(editorPanel, BoxLayout.Y_AXIS));
        editorPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        editorPane.setAlignmentX(Component.CENTER_ALIGNMENT);
        editorPanel.add(editorPane);

        // > Add two main panels to this UI vertically
        sessionParametersPanel.add(sessionKeyPanel);
        sessionParametersPanel.add(keyIdPanel);
        sessionParametersPanel.add(requestIdPanel);
        sessionParametersPanel.add(errorPanel);

        this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        this.add(sessionParametersPanel);
        this.add(editorPanel);

        // Make sure we consistently use the same font
        final var editorFont = httpMessageText.getFont();
        for(final var component: Set.of(sessionKeyText, keyIdText, requestIdSpinner) ) {
            component.setFont(editorFont);
        }

        // Make sure that the minimum sizes of the session parameter labels line up nicely
        final var uiFont = sessionKeyLabel.getFont();
        final var uiFontMetrics = sessionKeyLabel.getFontMetrics(uiFont);
        final int labelMinWidth = uiFontMetrics.stringWidth("Session key:"); // This is the widest label we have
        final int labelHeight = uiFontMetrics.getHeight();
        final var labelDim = new Dimension(labelMinWidth, labelHeight);

        for(final var label: Set.of(sessionKeyLabel, keyIdLabel, requestIdLabel)) {
            label.setMinimumSize(labelDim);
            label.setPreferredSize(labelDim);
        }

        // Make sure editor labels remain a fixed height
        final var editorLabelDim = new Dimension(Integer.MAX_VALUE, labelHeight);
        decryptedPayloadLabelPanel.setMaximumSize(editorLabelDim);
        httpMessageLabelPanel.setMaximumSize(editorLabelDim);

        // Make sure that the text fields have a matching and appropriate size.
        final var editorFontMetrics = sessionKeyText.getFontMetrics(editorFont);
        final int textfieldMinWidth = editorFontMetrics.stringWidth("a".repeat(43)) + 15; // 43 is the size of a session key, add some room to grow
        final int textfieldHeight = (int) ((double) editorFontMetrics.getHeight() * Math.sqrt(2.0));
        final var textfieldDim = new Dimension(textfieldMinWidth, textfieldHeight);
        for(final var textfield: Set.of(sessionKeyText, keyIdText)) {
            textfield.setMinimumSize(textfieldDim);
            textfield.setPreferredSize(textfieldDim);
        }

        // Make modifications for non-editable items.
        // Session key and key id must be modifiable even when the message must not be edited
        requestIdSpinner.setEnabled(editable);
        decryptedPayloadText.setEditable(editable);
        httpMessageText.setEditable(editable);

        // Associate listeners with input fields
        sessionKeyText.getDocument().addDocumentListener(new SessionKeyInputDocumentListener());
        keyIdText.getDocument().addDocumentListener(new KeyIdInputDocumentListener());
        requestIdSpinner.addChangeListener(new RequestIdChangeListener());

        this.decryptedBodyInputDocumentListener = new DecryptedMessageDocumentListener();
        this.httpMessageDocumentListener = new HttpMessageDocumentListener();

        if(editable) {
            decryptedPayloadText.getDocument().addDocumentListener(this.decryptedBodyInputDocumentListener);
            httpMessageText.getDocument().addDocumentListener(this.httpMessageDocumentListener);
        }

        // Associate UI components needed by this class with member values
        this.sessionKeyText = sessionKeyText;
        this.keyIdText = keyIdText;
        this.requestIdSpinner = requestIdSpinner;
        this.errorMessageLabel = errorMessageLabel;

        this.decryptedPayloadText = decryptedPayloadText;
        this.httpMessageText = httpMessageText;
    }

    private static void RSyntaxTextAreaHacks() {
        // See https://github.com/bobbylight/RSyntaxTextArea/issues/269
        JTextArea.removeKeymap("RTextAreaKeymap");
        for(var setting: Set.of("RSyntaxTextAreaUI.actionMap", "RSyntaxTextAreaUI.inputMap", "RTextAreaUI.actionMap", "RTextAreaUI.inputMap")) {
            UIManager.put(setting, null);
        }
    }

    private class SessionKeyInputDocumentListener implements DocumentListener {

        private void update(DocumentEvent e) {
            final var source = e.getDocument();
            try {
                final var receivedSessionKeyInput = source.getText(0, source.getLength());
                main.processSessionKeyUpdate(receivedSessionKeyInput);
            } catch(BadLocationException ex) {
                showError("Failed to read session key.");
            }
        }

        @Override public void insertUpdate(DocumentEvent e) { update(e); }
        @Override public void removeUpdate(DocumentEvent e) { update(e); }
        @Override public void changedUpdate(DocumentEvent e) { update(e); }
    }

    private class KeyIdInputDocumentListener implements DocumentListener {
        private void update(DocumentEvent e) {
            final var source = e.getDocument();
            try {
                var keyIdInput = source.getText(0, source.getLength());

                main.processKeyIdUpdate(keyIdInput);
            } catch(BadLocationException ignored) {
                showError("Failed to process the key identifier.");
            }
        }

        @Override public void insertUpdate(DocumentEvent e) { update(e); }
        @Override public void removeUpdate(DocumentEvent e) { update(e); }
        @Override public void changedUpdate(DocumentEvent e) { update(e); }
    }

    // Listener for changes in the decrypted messages editor
    private class DecryptedMessageDocumentListener implements DocumentListener {

        private void update(DocumentEvent e) {
            var source = e.getDocument();
            try {
                main.processDecryptedMessageUpdate(source.getText(0, source.getLength()));
            } catch(BadLocationException l) {
                showError("Failed to read decrypted message.");
            }
        }

        @Override public void insertUpdate(DocumentEvent e) { update(e); }
        @Override public void removeUpdate(DocumentEvent e) { update(e); }
        @Override public void changedUpdate(DocumentEvent e) { update(e); }
    }

    // Listener for changes in the decrypted messages editor
    private class HttpMessageDocumentListener implements DocumentListener {

        private void update(DocumentEvent e) {
            var source = e.getDocument();

            try {
                main.processHttpMessageUpdate(source.getText(0, source.getLength()));
            } catch(BadLocationException l) {
                showError("Failed to read HTTP message.");
            }
        }

        @Override public void insertUpdate(DocumentEvent e) { update(e); }
        @Override public void removeUpdate(DocumentEvent e) { update(e); }
        @Override public void changedUpdate(DocumentEvent e) { update(e); }
    }

    private class RequestIdChangeListener implements ChangeListener {
        private Integer prevRequestId = null;

        @Override
        public void stateChanged(ChangeEvent e) {
            final var requestId = (Integer) ((JSpinner) e.getSource()).getValue();

            if(!requestId.equals(prevRequestId)) {
                main.processRequestIdUpdate(requestId);
                prevRequestId = requestId;
            }
        }
    }

    public void showError(final String error) {
        SwingUtilities.invokeLater(() -> {
            errorMessageLabel.setText("Error: " + error);
            errorMessageLabel.setVisible(true);
        });
    }

    public void showNoErrors() {
        SwingUtilities.invokeLater(() -> {
            errorMessageLabel.setText("");
            errorMessageLabel.setVisible(false);
        });
    }

    public void setProcessedDecryptedPayloadText(final String text) {
        Optional<String> prettyJson = Optional.empty();

        if(!text.isBlank()) {
            try {
                final var mapper = new ObjectMapper();
                final var obj = mapper.readTree(text);
                prettyJson = Optional.ofNullable(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(obj));
            } catch (JsonProcessingException ignored) { }
        }

        final var newText = prettyJson.orElse(text);

        SwingUtilities.invokeLater(() -> {
            final int prevCaretPosition = decryptedPayloadText.getCaretPosition();
            decryptedPayloadText.getDocument().removeDocumentListener(decryptedBodyInputDocumentListener);
            decryptedPayloadText.setText(newText);
            if(prevCaretPosition >= 0 && prevCaretPosition < newText.length()) {
                decryptedPayloadText.setCaretPosition(prevCaretPosition);
            }
            decryptedPayloadText.getDocument().addDocumentListener(decryptedBodyInputDocumentListener);
        });
    }

    public void setProcessedHttpMessageText(final String text) {
        SwingUtilities.invokeLater(() -> {
            final int prevCaretPosition = httpMessageText.getCaretPosition();
            httpMessageText.getDocument().removeDocumentListener(httpMessageDocumentListener);
            httpMessageText.setText(text);
            if(prevCaretPosition >= 0 && prevCaretPosition < text.length()) {
                httpMessageText.setCaretPosition(prevCaretPosition);
            }
            httpMessageText.getDocument().addDocumentListener(httpMessageDocumentListener);
        });
    }

    public String getSelectedData() {
        return httpMessageText.getSelectedText();
    }
}
