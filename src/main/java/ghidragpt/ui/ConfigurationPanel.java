package ghidragpt.ui;

import ghidragpt.service.APIClient;
import ghidragpt.config.ConfigurationManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * Configuration panel for API settings
 */
public class ConfigurationPanel extends JPanel {
    
    private final APIClient apiClient;
    private final ConfigurationManager configManager;
    private final JTextField apiKeyField;
    private final JComboBox<APIClient.GPTProvider> providerCombo;
    private final JComboBox<String> modelCombo;
    private final JButton fetchModelsButton;
    private final JTextField customApiUrlField;
    private final JLabel customApiUrlLabel;
    private final JSpinner maxTokensSpinner;
    private final JComboBox<Integer> contextSizeCombo;
    private final JSpinner temperatureSpinner;
    private final JSpinner timeoutSpinner;
    private final JSpinner processingTimeoutSpinner;
    private final JButton testButton;
    private final JButton saveButton;
    private final JLabel statusLabel;
    private boolean configDirty = false;
    private final JCheckBox applyFunctionRenameCheckbox;
    private final JCheckBox applyFunctionPrototypeCheckbox;
    private final JCheckBox printRewriteSummaryCheckbox;
    private final JCheckBox renameNamedLocalsCheckbox;
    private final JCheckBox renameNamedFieldsCheckbox;
    private final JCheckBox renameNamedFunctionsCheckbox;
    private final JCheckBox renameNamedClassesCheckbox;
    private final JRadioButton debugOffRadio;
    private final JRadioButton debugSaveRadio;
    private final JRadioButton debugLoadRadio;
    private final JTextField debugPathField;
    private final JTextField debugFileField;
    private final JTextArea customInstructionsArea;
    private final JCheckBox enableThinkingCheckbox;
    private final JSpinner thinkingThresholdSpinner;
    private final JLabel thinkingThresholdLabel;
    private final JLabel thinkingTimeoutLabel;
    private final JSpinner maxResponseSizeSpinner;
    private final JPanel toolbar;
    
    public ConfigurationPanel(APIClient apiClient) {
        this.apiClient = apiClient;
        this.configManager = new ConfigurationManager();
        
        setLayout(new BorderLayout());
        
        // Toolbar with Test, Save buttons and status
        toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        toolbar.setMinimumSize(new Dimension(200, 32));
        toolbar.setPreferredSize(new Dimension(400, 32));
        
        testButton = new JButton("Test Connection");
        testButton.setToolTipText("Test connectivity to the selected LLM provider");
        testButton.addActionListener(e -> testConnection());
        testButton.setPreferredSize(new Dimension(130, 28));
        toolbar.add(testButton);
        
        saveButton = new JButton("Save");
        saveButton.setToolTipText("Save configuration to disk");
        saveButton.addActionListener(e -> saveConfiguration());
        saveButton.setPreferredSize(new Dimension(80, 28));
        saveButton.setEnabled(false);
        toolbar.add(saveButton);
        
        toolbar.add(Box.createHorizontalStrut(10));
        statusLabel = new JLabel("Not configured");
        statusLabel.setForeground(Color.RED);
        toolbar.add(statusLabel);
        
        add(toolbar, BorderLayout.NORTH);
        
        // Form panel with GridBagLayout
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // API Provider
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("API Provider:"), gbc);
        
        providerCombo = new JComboBox<>(APIClient.GPTProvider.values());
        providerCombo.setToolTipText("LLM API provider (Ollama for local models)");
        providerCombo.addActionListener(e -> updateModelField());
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(providerCombo, gbc);
        
        // API Key
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("API Key:"), gbc);
        
        apiKeyField = new JPasswordField(30);
        apiKeyField.setToolTipText("API key for the selected provider (not needed for Ollama)");
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(apiKeyField, gbc);
        
        // Model
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Model:"), gbc);
        
        // Create a panel to hold model combo and fetch button
        JPanel modelPanel = new JPanel(new BorderLayout(5, 0));
        modelCombo = new JComboBox<>();
        modelCombo.setEditable(true);
        modelCombo.setToolTipText("Model name (type or select from fetched list)");
        modelCombo.setPreferredSize(new Dimension(200, 25));
        modelPanel.add(modelCombo, BorderLayout.CENTER);
        
        fetchModelsButton = new JButton("Fetch");
        fetchModelsButton.setToolTipText("Fetch available models from the provider");
        fetchModelsButton.setPreferredSize(new Dimension(70, 25));
        fetchModelsButton.addActionListener(e -> fetchModels());
        modelPanel.add(fetchModelsButton, BorderLayout.EAST);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(modelPanel, gbc);
        
        // Custom API URL (for OpenAI Compatible provider)
        gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE;
        customApiUrlLabel = new JLabel("Custom API URL:");
        formPanel.add(customApiUrlLabel, gbc);
        
        customApiUrlField = new JTextField("http://localhost:8000/v1", 30);
        customApiUrlField.setToolTipText("Base URL for OpenAI-compatible API endpoint");
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(customApiUrlField, gbc);
        
        // Hide by default (only show for OPENAI_COMPATIBLE provider)
        customApiUrlLabel.setVisible(false);
        customApiUrlField.setVisible(false);
        
        // Max Tokens
        gbc.gridx = 0; gbc.gridy = 4; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Max Tokens:"), gbc);
        
        maxTokensSpinner = new JSpinner(new SpinnerNumberModel(APIClient.DEFAULT_MAX_TOKENS, 100, 131072, 1024));
        maxTokensSpinner.setToolTipText("Maximum number of tokens in the model response");
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(maxTokensSpinner, gbc);
        
        // Context Size
        gbc.gridx = 0; gbc.gridy = 5; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Context Size:"), gbc);
        
        Integer[] contextSizes = new Integer[16];
        for (int i = 0; i < 16; i++) {
            contextSizes[i] = (i + 1) * 16384;
        }
        contextSizeCombo = new JComboBox<>(contextSizes);
        contextSizeCombo.setToolTipText("Context window size sent to the model");
        contextSizeCombo.setSelectedItem(APIClient.DEFAULT_CONTEXT_SIZE);
        contextSizeCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public java.awt.Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean sel, boolean focus) {
                super.getListCellRendererComponent(list, value, index, sel, focus);
                if (value instanceof Integer) {
                    setText(((Integer) value / 1024) + "k");
                }
                return this;
            }
        });
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(contextSizeCombo, gbc);
        
        // Temperature
        gbc.gridx = 0; gbc.gridy = 6; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Temperature:"), gbc);
        
        temperatureSpinner = new JSpinner(new SpinnerNumberModel(APIClient.DEFAULT_TEMPERATURE, 0.0, 2.0, 0.1));
        temperatureSpinner.setToolTipText("Sampling temperature (lower = more deterministic, higher = more creative)");
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(temperatureSpinner, gbc);
        
        // Connection Timeout
        gbc.gridx = 0; gbc.gridy = 7; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Connection timeout (s):"), gbc);
        
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(APIClient.DEFAULT_TIMEOUT_SECONDS, 5, 300, 5));
        timeoutSpinner.setToolTipText("HTTP connect/read/write timeout in seconds");
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(timeoutSpinner, gbc);

        // Max response size
        gbc.gridx = 0; gbc.gridy = 8; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(2, 5, 5, 5);
        formPanel.add(new JLabel("Max response size (KB):"), gbc);
        maxResponseSizeSpinner = new JSpinner(new SpinnerNumberModel(APIClient.DEFAULT_MAX_RESPONSE_SIZE_KB, 0, 10240, 64));
        maxResponseSizeSpinner.setToolTipText("Maximum content response size in KB (0 = no limit). Cancels stream if exceeded.");
        gbc.gridx = 1; gbc.gridy = 8;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(maxResponseSizeSpinner, gbc);

        // Rewrite Options separator
        gbc.gridx = 0; gbc.gridy = 10; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 5, 2, 5);
        JSeparator separator = new JSeparator();
        formPanel.add(separator, gbc);
        
        gbc.gridx = 0; gbc.gridy = 11; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 5, 5);
        formPanel.add(new JLabel("Rewrite Options:"), gbc);
        
        // Apply Function Rename checkbox
        applyFunctionRenameCheckbox = new JCheckBox("Apply function renames");
        applyFunctionRenameCheckbox.setToolTipText("Allow GhidraGPT to rename functions based on analysis");
        gbc.gridx = 0; gbc.gridy = 12; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 2, 5);
        formPanel.add(applyFunctionRenameCheckbox, gbc);
        
        // Apply Function Prototype checkbox
        applyFunctionPrototypeCheckbox = new JCheckBox("Apply function prototypes");
        applyFunctionPrototypeCheckbox.setToolTipText("Allow GhidraGPT to update function signatures (return type, parameters)");
        gbc.gridx = 0; gbc.gridy = 13; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 2, 5);
        formPanel.add(applyFunctionPrototypeCheckbox, gbc);

        // Print Suggestion Summary checkbox
        printRewriteSummaryCheckbox = new JCheckBox("Print rewrite summary");
        printRewriteSummaryCheckbox.setToolTipText("Print per-suggestion success/failure summary to console after rewrite");
        gbc.gridx = 0; gbc.gridy = 14; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 2, 5);
        formPanel.add(printRewriteSummaryCheckbox, gbc);

        // Re-rename checkboxes (allow re-renaming already-named items)
        renameNamedLocalsCheckbox = new JCheckBox("Re-rename already named locals");
        renameNamedLocalsCheckbox.setToolTipText("Allow LLM to rename local variables that already have descriptive names (not decompiler defaults)");
        gbc.gridx = 0; gbc.gridy = 15; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 2, 5);
        formPanel.add(renameNamedLocalsCheckbox, gbc);

        renameNamedFieldsCheckbox = new JCheckBox("Re-rename already named fields");
        renameNamedFieldsCheckbox.setToolTipText("Allow LLM to rename struct fields that already have m_ prefixed names");
        gbc.gridx = 0; gbc.gridy = 16; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 2, 5);
        formPanel.add(renameNamedFieldsCheckbox, gbc);

        renameNamedFunctionsCheckbox = new JCheckBox("Re-rename already named functions");
        renameNamedFunctionsCheckbox.setToolTipText("Allow LLM to rename function calls that already have F_/M_ prefixed names");
        gbc.gridx = 0; gbc.gridy = 17; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 2, 5);
        formPanel.add(renameNamedFunctionsCheckbox, gbc);

        renameNamedClassesCheckbox = new JCheckBox("Re-rename already named classes");
        renameNamedClassesCheckbox.setToolTipText("Allow LLM to rename classes that already have C_ prefixed names (not cls_0x defaults)");
        gbc.gridx = 0; gbc.gridy = 18; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 2, 5);
        formPanel.add(renameNamedClassesCheckbox, gbc);

        // Enable Thinking checkbox (Ollama only)
        enableThinkingCheckbox = new JCheckBox("Enable thinking (Ollama)");
        enableThinkingCheckbox.setToolTipText("Allow model to reason before answering (uses more output tokens)");
        gbc.gridx = 0; gbc.gridy = 19; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 2, 5);
        formPanel.add(enableThinkingCheckbox, gbc);

        // Thinking threshold spinner
        thinkingThresholdLabel = new JLabel("Min thinking prompt (KB):");
        gbc.gridx = 0; gbc.gridy = 20; gbc.gridwidth = 1;
        gbc.insets = new Insets(2, 20, 2, 5);
        formPanel.add(thinkingThresholdLabel, gbc);
        thinkingThresholdSpinner = new JSpinner(new SpinnerNumberModel(10, 0, 1000, 1));
        thinkingThresholdSpinner.setToolTipText("Thinking is only sent when prompt size exceeds this threshold (0 = always think)");
        gbc.gridx = 1; gbc.gridy = 20;
        gbc.insets = new Insets(2, 5, 2, 5);
        formPanel.add(thinkingThresholdSpinner, gbc);

        // Thinking timeout spinner
        thinkingTimeoutLabel = new JLabel("Thinking timeout (min):");
        gbc.gridx = 0; gbc.gridy = 21; gbc.gridwidth = 1;
        gbc.insets = new Insets(2, 20, 5, 5);
        formPanel.add(thinkingTimeoutLabel, gbc);
        processingTimeoutSpinner = new JSpinner(new SpinnerNumberModel(APIClient.DEFAULT_PROCESSING_TIMEOUT_MINUTES, 0, 120, 1));
        processingTimeoutSpinner.setToolTipText("Max time for model thinking phase in minutes (0 = no limit). Content generation is not affected.");
        gbc.gridx = 1; gbc.gridy = 21;
        gbc.insets = new Insets(2, 5, 5, 5);
        formPanel.add(processingTimeoutSpinner, gbc);
        enableThinkingCheckbox.addActionListener(e -> updateThinkingThresholdState());
        
        // Debug mode radio buttons
        debugOffRadio = new JRadioButton("Off");
        debugSaveRadio = new JRadioButton("Save");
        debugLoadRadio = new JRadioButton("Load Response");
        debugOffRadio.setSelected(true);
        ButtonGroup debugGroup = new ButtonGroup();
        debugGroup.add(debugOffRadio);
        debugGroup.add(debugSaveRadio);
        debugGroup.add(debugLoadRadio);
        
        debugPathField = new JTextField(15);
        debugPathField.setToolTipText("Folder for debug save/load files (e.g. D:\\\\Temp\\\\ghidra)");
        debugPathField.setEnabled(false);
        
        debugFileField = new JTextField(20);
        debugFileField.setToolTipText("Response filename to load (e.g. FuncName-20260506_112024-response)");
        debugFileField.setEnabled(false);
        
        ActionListener debugRadioListener = e -> {
            debugPathField.setEnabled(!debugOffRadio.isSelected());
            debugFileField.setEnabled(debugLoadRadio.isSelected());
        };
        debugOffRadio.addActionListener(debugRadioListener);
        debugSaveRadio.addActionListener(debugRadioListener);
        debugLoadRadio.addActionListener(debugRadioListener);
        
        JPanel debugPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        debugPanel.add(new JLabel("Debug:"));
        debugPanel.add(debugOffRadio);
        debugPanel.add(debugSaveRadio);
        debugPanel.add(debugLoadRadio);
        debugPanel.add(debugPathField);
        debugPanel.add(new JLabel("File:"));
        debugPanel.add(debugFileField);
        gbc.gridx = 0; gbc.gridy = 22; gbc.gridwidth = 2;
        gbc.insets = new Insets(2, 5, 5, 5);
        formPanel.add(debugPanel, gbc);
        
        // Custom Prompt Instructions
        gbc.gridx = 0; gbc.gridy = 23; gbc.gridwidth = 2;
        gbc.insets = new Insets(5, 5, 2, 5);
        formPanel.add(new JLabel("Custom Prompt Instructions:"), gbc);
        
        customInstructionsArea = new JTextArea(3, 30);
        customInstructionsArea.setLineWrap(true);
        customInstructionsArea.setWrapStyleWord(true);
        customInstructionsArea.setToolTipText("Extra instructions appended to the LLM prompt (e.g. 'Always use camelCase names')");
        JScrollPane instructionsScrollPane = new JScrollPane(customInstructionsArea);
        instructionsScrollPane.setPreferredSize(new Dimension(300, 60));
        gbc.gridx = 0; gbc.gridy = 24; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 5, 5, 5);
        formPanel.add(instructionsScrollPane, gbc);
        
        // Vertical spacer to push everything to the top
        JPanel spacer = new JPanel();
        spacer.setOpaque(false);
        gbc.gridx = 0; gbc.gridy = 25; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0;
        gbc.weightx = 1.0;
        formPanel.add(spacer, gbc);
        
        JScrollPane formScrollPane = new JScrollPane(formPanel);
        formScrollPane.setBorder(null);
        formScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(formScrollPane, BorderLayout.CENTER);
        
        updateModelField();
        
        // Load configuration from file
        loadConfiguration();
        
        // Attach change listeners to mark config dirty
        Runnable markDirty = () -> { configDirty = true; saveButton.setEnabled(true); };
        providerCombo.addActionListener(e -> markDirty.run());
        modelCombo.addActionListener(e -> markDirty.run());
        contextSizeCombo.addActionListener(e -> markDirty.run());
        apiKeyField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
        });
        customApiUrlField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
        });
        debugPathField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
        });
        debugFileField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
        });
        customInstructionsArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { markDirty.run(); }
        });
        maxTokensSpinner.addChangeListener(e -> markDirty.run());
        temperatureSpinner.addChangeListener(e -> markDirty.run());
        timeoutSpinner.addChangeListener(e -> markDirty.run());
        processingTimeoutSpinner.addChangeListener(e -> markDirty.run());
        maxResponseSizeSpinner.addChangeListener(e -> markDirty.run());
        applyFunctionRenameCheckbox.addActionListener(e -> markDirty.run());
        applyFunctionPrototypeCheckbox.addActionListener(e -> markDirty.run());
        printRewriteSummaryCheckbox.addActionListener(e -> markDirty.run());
        renameNamedLocalsCheckbox.addActionListener(e -> markDirty.run());
        renameNamedFieldsCheckbox.addActionListener(e -> markDirty.run());
        renameNamedFunctionsCheckbox.addActionListener(e -> markDirty.run());
        renameNamedClassesCheckbox.addActionListener(e -> markDirty.run());
        enableThinkingCheckbox.addActionListener(e -> markDirty.run());
        thinkingThresholdSpinner.addChangeListener(e -> markDirty.run());
        debugOffRadio.addActionListener(e -> markDirty.run());
        debugSaveRadio.addActionListener(e -> markDirty.run());
        debugLoadRadio.addActionListener(e -> markDirty.run());
    }
    
    /**
     * Returns the toolbar panel with Test/Save buttons, for external placement.
     */
    public JPanel getToolbar() {
        return toolbar;
    }
    
    /**
     * Loads configuration from the configuration manager and updates UI
     */
    private void loadConfiguration() {
        // Load saved values
        providerCombo.setSelectedItem(configManager.getProvider());
        apiKeyField.setText(configManager.getApiKey());
        modelCombo.setSelectedItem(configManager.getModel());
        customApiUrlField.setText(configManager.getCustomApiUrl());
        maxTokensSpinner.setValue(configManager.getMaxTokens());
        contextSizeCombo.setSelectedItem(configManager.getContextSize());
        temperatureSpinner.setValue(configManager.getTemperature());
        timeoutSpinner.setValue(configManager.getTimeoutSeconds());
        processingTimeoutSpinner.setValue(configManager.getProcessingTimeoutMinutes());
        maxResponseSizeSpinner.setValue(configManager.getMaxResponseSizeKb());
        applyFunctionRenameCheckbox.setSelected(configManager.isApplyFunctionRename());
        applyFunctionPrototypeCheckbox.setSelected(configManager.isApplyFunctionPrototype());
        printRewriteSummaryCheckbox.setSelected(configManager.isPrintRewriteSummary());
        renameNamedLocalsCheckbox.setSelected(configManager.isRenameNamedLocals());
        renameNamedFieldsCheckbox.setSelected(configManager.isRenameNamedFields());
        renameNamedFunctionsCheckbox.setSelected(configManager.isRenameNamedFunctions());
        renameNamedClassesCheckbox.setSelected(configManager.isRenameNamedClasses());
        enableThinkingCheckbox.setSelected(configManager.isEnableThinking());
        thinkingThresholdSpinner.setValue(configManager.getThinkingThresholdKb());
        updateThinkingThresholdState();
        String debugMode = configManager.getDebugMode();
        debugOffRadio.setSelected("off".equals(debugMode));
        debugSaveRadio.setSelected("save".equals(debugMode));
        debugLoadRadio.setSelected("load".equals(debugMode));
        debugPathField.setText(configManager.getDebugPath());
        debugPathField.setEnabled(!"off".equals(debugMode));
        debugFileField.setText(configManager.getDebugFile());
        debugFileField.setEnabled("load".equals(debugMode));
        customInstructionsArea.setText(configManager.getCustomInstructions());
        
        // Update visibility of custom URL field
        APIClient.GPTProvider provider = configManager.getProvider();
        boolean isOpenAICompatible = (provider == APIClient.GPTProvider.OPENAI_COMPATIBLE);
        customApiUrlLabel.setVisible(isOpenAICompatible);
        customApiUrlField.setVisible(isOpenAICompatible);
        
        // Update status
        if (configManager.isConfigured()) {
            statusLabel.setText("Configuration loaded");
            statusLabel.setForeground(Color.BLUE);
            
            // Apply to GPT service
            apiClient.setApiKey(configManager.getApiKey());
            apiClient.setProvider(configManager.getProvider());
            apiClient.setModel(configManager.getModel());
            apiClient.setCustomApiUrl(configManager.getCustomApiUrl());
            apiClient.setMaxTokens(configManager.getMaxTokens());
            apiClient.setContextSize(configManager.getContextSize());
            apiClient.setTemperature(configManager.getTemperature());
            apiClient.setTimeoutSeconds(configManager.getTimeoutSeconds());
            apiClient.setProcessingTimeoutMinutes(configManager.getProcessingTimeoutMinutes());
            apiClient.setEnableThinking(configManager.isEnableThinking());
        } else {
            statusLabel.setText("Configuration incomplete");
            statusLabel.setForeground(Color.ORANGE);
        }
    }
    
    private void updateThinkingThresholdState() {
        boolean enabled = enableThinkingCheckbox.isSelected();
        thinkingThresholdSpinner.setEnabled(enabled);
        thinkingThresholdLabel.setEnabled(enabled);
        processingTimeoutSpinner.setEnabled(enabled);
        thinkingTimeoutLabel.setEnabled(enabled);
    }
    
    private void updateModelField() {
        APIClient.GPTProvider provider = (APIClient.GPTProvider) providerCombo.getSelectedItem();
        
        // Reset all configuration fields when provider changes
        resetConfigurationFields();
        
        // Show/hide custom API URL field based on provider
        boolean isOpenAICompatible = (provider == APIClient.GPTProvider.OPENAI_COMPATIBLE);
        customApiUrlLabel.setVisible(isOpenAICompatible);
        customApiUrlField.setVisible(isOpenAICompatible);
        
        // Clear and set placeholder
        modelCombo.removeAllItems();
        modelCombo.addItem("<model>");
        modelCombo.setSelectedItem("<model>");
        
        // Set provider-specific defaults
        if (provider == APIClient.GPTProvider.OLLAMA) {
            apiKeyField.setEnabled(false);  // Ollama doesn't require API key
            apiKeyField.setText("Not required for Ollama (local)");
        } else if (provider == APIClient.GPTProvider.OPENAI_COMPATIBLE) {
            apiKeyField.setEnabled(true);
            if (apiKeyField.getText().equals("Not required for Ollama (local)")) {
                apiKeyField.setText("");
            }
            customApiUrlField.setText("http://localhost:8000/v1");
        } else {
            // For all other providers, enable API key field and clear placeholder
            apiKeyField.setEnabled(true);
            if (apiKeyField.getText().equals("Not required for Ollama (local)")) {
                apiKeyField.setText("");
            }
        }
        
        // Reset status to unconfigured state
        statusLabel.setText("Configuration updated - please test connection");
        statusLabel.setForeground(Color.ORANGE);
    }
    
    private void resetConfigurationFields() {
        // Clear API key field
        apiKeyField.setText("");
        
        // Reset status
        statusLabel.setText("Not configured");
        statusLabel.setForeground(Color.RED);
        
        // Enable API key field by default
        apiKeyField.setEnabled(true);
    }    private void saveConfiguration() {
        String apiKey = apiKeyField.getText().trim();
        APIClient.GPTProvider selectedProvider = (APIClient.GPTProvider) providerCombo.getSelectedItem();
        String customApiUrl = customApiUrlField.getText().trim();
        
        // All providers require API key except Ollama
        if (selectedProvider != APIClient.GPTProvider.OLLAMA && apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an API key", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // OpenAI Compatible requires custom URL
        if (selectedProvider == APIClient.GPTProvider.OPENAI_COMPATIBLE && customApiUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a custom API URL", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // For Ollama, clear any placeholder text from API key field
        if (selectedProvider == APIClient.GPTProvider.OLLAMA) {
            apiKey = "";  // Don't save placeholder text
        }
        
        // Save to configuration manager
        configManager.setApiKey(apiKey);
        configManager.setProvider(selectedProvider);
        configManager.setModel(getSelectedModel());
        configManager.setCustomApiUrl(customApiUrl);
        configManager.setMaxTokens((Integer) maxTokensSpinner.getValue());
        configManager.setContextSize((Integer) contextSizeCombo.getSelectedItem());
        configManager.setTemperature((Double) temperatureSpinner.getValue());
        configManager.setTimeoutSeconds((Integer) timeoutSpinner.getValue());
        configManager.setProcessingTimeoutMinutes((Integer) processingTimeoutSpinner.getValue());
        configManager.setMaxResponseSizeKb((Integer) maxResponseSizeSpinner.getValue());
        configManager.setApplyFunctionRename(applyFunctionRenameCheckbox.isSelected());
        configManager.setApplyFunctionPrototype(applyFunctionPrototypeCheckbox.isSelected());
        configManager.setPrintRewriteSummary(printRewriteSummaryCheckbox.isSelected());
        configManager.setRenameNamedLocals(renameNamedLocalsCheckbox.isSelected());
        configManager.setRenameNamedFields(renameNamedFieldsCheckbox.isSelected());
        configManager.setRenameNamedFunctions(renameNamedFunctionsCheckbox.isSelected());
        configManager.setRenameNamedClasses(renameNamedClassesCheckbox.isSelected());
        configManager.setEnableThinking(enableThinkingCheckbox.isSelected());
        configManager.setThinkingThresholdKb((Integer) thinkingThresholdSpinner.getValue());
        configManager.setDebugMode(debugSaveRadio.isSelected() ? "save" : debugLoadRadio.isSelected() ? "load" : "off");
        configManager.setDebugPath(debugPathField.getText().trim());
        configManager.setDebugFile(debugFileField.getText().trim());
        configManager.setCustomInstructions(customInstructionsArea.getText());
        configManager.saveConfiguration();
        
        // Apply to GPT service
        apiClient.setApiKey(apiKey);
        apiClient.setProvider(selectedProvider);
        apiClient.setModel(getSelectedModel());
        apiClient.setCustomApiUrl(customApiUrl);
        apiClient.setMaxTokens((Integer) maxTokensSpinner.getValue());
        apiClient.setContextSize((Integer) contextSizeCombo.getSelectedItem());
        apiClient.setTemperature((Double) temperatureSpinner.getValue());
        apiClient.setTimeoutSeconds((Integer) timeoutSpinner.getValue());
        apiClient.setProcessingTimeoutMinutes((Integer) processingTimeoutSpinner.getValue());
        apiClient.setMaxResponseSizeKb((Integer) maxResponseSizeSpinner.getValue());
        apiClient.setEnableThinking(enableThinkingCheckbox.isSelected());
        
        configDirty = false;
        saveButton.setEnabled(false);
        statusLabel.setText("Configuration saved");
        statusLabel.setForeground(Color.BLUE);
    }
    
    private void testConnection() {
        // First update the GPTService with current UI values
        String apiKey = apiKeyField.getText().trim();
        APIClient.GPTProvider selectedProvider = (APIClient.GPTProvider) providerCombo.getSelectedItem();
        String model = getSelectedModel();
        String customApiUrl = customApiUrlField.getText().trim();
        
        // Validate inputs before testing
        if (selectedProvider != APIClient.GPTProvider.OLLAMA && apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an API key", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (model.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a model name", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (selectedProvider == APIClient.GPTProvider.OPENAI_COMPATIBLE && customApiUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a custom API URL", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Apply current UI values to GPTService for testing
        apiClient.setApiKey(apiKey);
        apiClient.setProvider(selectedProvider);
        apiClient.setModel(model);
        apiClient.setCustomApiUrl(customApiUrl);
        apiClient.setMaxTokens((Integer) maxTokensSpinner.getValue());
        apiClient.setContextSize((Integer) contextSizeCombo.getSelectedItem());
        apiClient.setTemperature((Double) temperatureSpinner.getValue());
        apiClient.setTimeoutSeconds((Integer) timeoutSpinner.getValue());
        apiClient.setEnableThinking(enableThinkingCheckbox.isSelected());

        testButton.setEnabled(false);
        testButton.setText("Testing...");
        
        // Test in background thread
        SwingWorker<String, Void> worker = new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                return apiClient.sendRequest("Hello, this is a test message. Please respond with 'Connection successful'.");
            }
            
            @Override
            protected void done() {
                try {
                    String response = get();
                    if (response.toLowerCase().contains("successful") || response.toLowerCase().contains("hello")) {
                        statusLabel.setText("Connection successful");
                        statusLabel.setForeground(Color.GREEN);
                        
                        // Show success message and prompt to save
                        int result = JOptionPane.showConfirmDialog(ConfigurationPanel.this, 
                            "Connection test successful!\n\nWould you like to save this configuration?", 
                            "Success", JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE);
                        
                        if (result == JOptionPane.YES_OPTION) {
                            saveConfiguration();
                        }
                    } else {
                        statusLabel.setText("Connection test completed");
                        statusLabel.setForeground(Color.BLUE);
                        JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                            "Connection established but unexpected response:\n" + response, 
                            "Warning", JOptionPane.WARNING_MESSAGE);
                    }
                } catch (Exception e) {
                    statusLabel.setText("Connection failed");
                    statusLabel.setForeground(Color.RED);
                    JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                        "Connection test failed:\n" + e.getMessage(), 
                        "Error", JOptionPane.ERROR_MESSAGE);
                } finally {
                    testButton.setEnabled(true);
                    testButton.setText("Test Connection");
                }
            }
        };
        
        worker.execute();
    }
    
    private void fetchModels() {
        fetchModelsButton.setEnabled(false);
        fetchModelsButton.setText("Fetching...");
        
        // Get current provider settings
        APIClient.GPTProvider selectedProvider = (APIClient.GPTProvider) providerCombo.getSelectedItem();
        String apiKey = apiKeyField.getText().trim();
        String customApiUrl = customApiUrlField.getText().trim();
        
        // Validate inputs before fetching
        if (selectedProvider != APIClient.GPTProvider.OLLAMA && apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an API key first", "Error", JOptionPane.ERROR_MESSAGE);
            fetchModelsButton.setEnabled(true);
            fetchModelsButton.setText("Fetch");
            return;
        }
        
        if (selectedProvider == APIClient.GPTProvider.OPENAI_COMPATIBLE && customApiUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a custom API URL first", "Error", JOptionPane.ERROR_MESSAGE);
            fetchModelsButton.setEnabled(true);
            fetchModelsButton.setText("Fetch");
            return;
        }
        
        // Apply current settings to GPT service for fetching
        apiClient.setApiKey(apiKey);
        apiClient.setProvider(selectedProvider);
        apiClient.setCustomApiUrl(customApiUrl);
        
        // Fetch in background thread
        SwingWorker<List<String>, Void> worker = new SwingWorker<List<String>, Void>() {
            @Override
            protected List<String> doInBackground() throws Exception {
                return apiClient.fetchAvailableModels();
            }
            
            @Override
            protected void done() {
                try {
                    List<String> models = get();
                    if (models.isEmpty()) {
                        JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                            "No models available or provider doesn't support model listing", 
                            "Info", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        // Save current selection
                        String currentModel = getSelectedModel();
                        
                        // Update combo box with fetched models
                        modelCombo.removeAllItems();
                        for (String model : models) {
                            modelCombo.addItem(model);
                        }
                        
                        // Try to restore previous selection if it exists in the list
                        if (currentModel != null && !currentModel.isEmpty()) {
                            modelCombo.setSelectedItem(currentModel);
                        } else if (!models.isEmpty()) {
                            modelCombo.setSelectedIndex(0);
                        }
                        
                        statusLabel.setText("Fetched " + models.size() + " models");
                        statusLabel.setForeground(Color.BLUE);
                    }
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                        "Failed to fetch models:\n" + e.getMessage(), 
                        "Error", JOptionPane.ERROR_MESSAGE);
                } finally {
                    fetchModelsButton.setEnabled(true);
                    fetchModelsButton.setText("Fetch");
                }
            }
        };
        
        worker.execute();
    }
    
    private String getSelectedModel() {
        Object selected = modelCombo.getSelectedItem();
        return selected != null ? selected.toString().trim() : "";
    }
    
    public boolean isConfigured() {
        return configManager.isConfigured();
    }
    
    /**
     * Returns the configuration manager for external access
     */
    public ConfigurationManager getConfigurationManager() {
        return configManager;
    }
    

}
