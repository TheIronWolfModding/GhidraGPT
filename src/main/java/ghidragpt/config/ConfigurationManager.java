package ghidragpt.config;

import ghidragpt.service.APIClient;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * Manages persistent configuration for GhidraGPT plugin
 */
public class ConfigurationManager {
    
    private static final String CONFIG_DIR = System.getProperty("user.home") + File.separator + ".ghidragpt";
    private static final String CONFIG_FILE = "config.properties";
    private static final String API_KEY_ENCRYPTED_PROPERTY = "api.key.encrypted";
    private static final String PROVIDER_PROPERTY = "api.provider";
    private static final String MODEL_PROPERTY = "api.model";
    private static final String MAX_TOKENS_PROPERTY = "api.max.tokens";
    private static final String CONTEXT_SIZE_PROPERTY = "api.context.size";
    private static final String TEMPERATURE_PROPERTY = "api.temperature";
    private static final String PRESENCE_PENALTY_PROPERTY = "api.presence.penalty";
    private static final String REPETITION_PENALTY_PROPERTY = "api.repetition.penalty";
    private static final String TIMEOUT_PROPERTY = "api.timeout.seconds";
    private static final String CUSTOM_API_URL_PROPERTY = "api.custom.url";
    private static final String APPLY_FUNCTION_RENAME_PROPERTY = "rewrite.apply.function.rename";
    private static final String APPLY_FUNCTION_PROTOTYPE_PROPERTY = "rewrite.apply.function.prototype";
    private static final String CUSTOM_INSTRUCTIONS_PROPERTY = "rewrite.custom.instructions";
    private static final String SYSTEM_PROMPT_PROPERTY = "api.system.prompt";
    private static final String LOCK_PROMPTS_PROPERTY = "ui.lock.prompts";
    private static final String DEFAULT_SYSTEM_PROMPT = "You are an expert in reverse engineering decompiled C/C++ code from Ghidra.";
    private static final String PRINT_REWRITE_SUMMARY_PROPERTY = "rewrite.print.summary";
    private static final String DEBUG_MODE_PROPERTY = "rewrite.debug.mode";
    private static final String DEBUG_PATH_PROPERTY = "rewrite.debug.path";
    private static final String DEBUG_FILE_PROPERTY = "rewrite.debug.file";
    private static final String ENABLE_THINKING_PROPERTY = "api.enable.thinking";
    private static final String THINKING_THRESHOLD_PROPERTY = "api.thinking.threshold.kb";
    private static final String PROCESSING_TIMEOUT_PROPERTY = "api.processing.timeout.minutes";
    private static final String MAX_RESPONSE_SIZE_PROPERTY = "api.max.response.size.kb";
    private static final String RENAME_NAMED_LOCALS_PROPERTY = "rewrite.rename.named.locals";
    private static final String RENAME_NAMED_FIELDS_PROPERTY = "rewrite.rename.named.fields";
    private static final String RENAME_NAMED_FUNCTIONS_PROPERTY = "rewrite.rename.named.functions";
    private static final String RENAME_NAMED_CLASSES_PROPERTY = "rewrite.rename.named.classes";
    
    // XOR key for API key obfuscation, not super secure but still better than plaintext
    private static final String XOR_KEY = "GhidraGPT_Sec3@Key_9f4e7a2b#8c1d6f0a@2025!";
    
    private final Properties properties;
    private final Path configPath;
    
    public ConfigurationManager() {
        this.properties = new Properties();
        this.configPath = Paths.get(CONFIG_DIR, CONFIG_FILE);
        loadConfiguration();
    }
    
    /**
     * Loads configuration from file, creates default if doesn't exist
     */
    public void loadConfiguration() {
        try {
            // Create config directory if it doesn't exist
            Path configDir = Paths.get(CONFIG_DIR);
            if (!Files.exists(configDir)) {
                Files.createDirectories(configDir);
            }
            
            // Load existing configuration or create default
            if (Files.exists(configPath)) {
                try (InputStream input = Files.newInputStream(configPath)) {
                    properties.load(input);
                }
            } else {
                createDefaultConfiguration();
            }
        } catch (IOException e) {
            System.err.println("Failed to load configuration: " + e.getMessage());
            createDefaultConfiguration();
        }
    }
    
    /**
     * Creates default configuration
     */
    private void createDefaultConfiguration() {
        properties.setProperty(PROVIDER_PROPERTY, "OPENAI");
        properties.setProperty(MODEL_PROPERTY, "gpt-4");
        properties.setProperty(API_KEY_ENCRYPTED_PROPERTY, "");
    }
    
    /**
     * Saves current configuration to file
     */
    public void saveConfiguration() {
        try {
            // Ensure config directory exists
            Path configDir = Paths.get(CONFIG_DIR);
            if (!Files.exists(configDir)) {
                Files.createDirectories(configDir);
            }
            
            try (OutputStream output = Files.newOutputStream(configPath)) {
                properties.store(output, "GhidraGPT Configuration");
            }
        } catch (IOException e) {
            System.err.println("Failed to save configuration: " + e.getMessage());
        }
    }
    
    /**
     * Gets the API key from encrypted storage
     */
    public String getApiKey() {
        String encryptedKey = properties.getProperty(API_KEY_ENCRYPTED_PROPERTY, "");
        if (encryptedKey.isEmpty()) {
            return "";
        }
        
        String decryptedKey = decryptApiKey(encryptedKey);
        return decryptedKey != null ? decryptedKey : "";
    }
    
    /**
     * Sets the API key - stores in encrypted format only
     */
    public void setApiKey(String apiKey) {
        if (apiKey == null) apiKey = "";
        
        // Store encrypted version
        String encryptedKey = encryptApiKey(apiKey);
        properties.setProperty(API_KEY_ENCRYPTED_PROPERTY, encryptedKey);
    }
    
    /**
     * Gets the provider
     */
    public APIClient.GPTProvider getProvider() {
        String providerName = properties.getProperty(PROVIDER_PROPERTY, APIClient.GPTProvider.OPENAI.name());
        try {
            return APIClient.GPTProvider.valueOf(providerName);
        } catch (IllegalArgumentException e) {
            return APIClient.GPTProvider.OPENAI; // Default fallback
        }
    }
    
    /**
     * Sets the provider
     */
    public void setProvider(APIClient.GPTProvider provider) {
        properties.setProperty(PROVIDER_PROPERTY, provider.name());
    }
    
    /**
     * Gets the model
     */
    public String getModel() {
        return properties.getProperty(MODEL_PROPERTY, "gpt-4");
    }
    
    /**
     * Sets the model
     */
    public void setModel(String model) {
        properties.setProperty(MODEL_PROPERTY, model != null ? model : "");
    }
    
    /**
     * Gets the max tokens
     */
    public int getMaxTokens() {
        return Integer.parseInt(properties.getProperty(MAX_TOKENS_PROPERTY, String.valueOf(APIClient.DEFAULT_MAX_TOKENS)));
    }
    
    /**
     * Sets the max tokens
     */
    public void setMaxTokens(int maxTokens) {
        properties.setProperty(MAX_TOKENS_PROPERTY, String.valueOf(maxTokens));
    }

    public int getContextSize() {
        return Integer.parseInt(properties.getProperty(CONTEXT_SIZE_PROPERTY, String.valueOf(APIClient.DEFAULT_CONTEXT_SIZE)));
    }

    public void setContextSize(int contextSize) {
        properties.setProperty(CONTEXT_SIZE_PROPERTY, String.valueOf(contextSize));
    }
    
    /**
     * Gets the temperature
     */
    public double getTemperature() {
        return Double.parseDouble(properties.getProperty(TEMPERATURE_PROPERTY, String.valueOf(APIClient.DEFAULT_TEMPERATURE)));
    }
    
    /**
     * Sets the temperature
     */
    public void setTemperature(double temperature) {
        properties.setProperty(TEMPERATURE_PROPERTY, String.valueOf(temperature));
    }

    public double getPresencePenalty() {
        return Double.parseDouble(properties.getProperty(PRESENCE_PENALTY_PROPERTY,
                String.valueOf(APIClient.DEFAULT_PRESENCE_PENALTY)));
    }

    public void setPresencePenalty(double presencePenalty) {
        properties.setProperty(PRESENCE_PENALTY_PROPERTY, String.valueOf(presencePenalty));
    }

    public double getRepetitionPenalty() {
        return Double.parseDouble(properties.getProperty(REPETITION_PENALTY_PROPERTY,
                String.valueOf(APIClient.DEFAULT_REPETITION_PENALTY)));
    }

    public void setRepetitionPenalty(double repetitionPenalty) {
        properties.setProperty(REPETITION_PENALTY_PROPERTY, String.valueOf(repetitionPenalty));
    }
    
    /**
     * Checks if configuration is complete and valid
     */
    public boolean isConfigured() {
        String apiKey = getApiKey();
        String model = getModel();
        APIClient.GPTProvider provider = getProvider();
        
        // Ollama doesn't require API key, all others do
        if (provider == APIClient.GPTProvider.OLLAMA) {
            return !model.trim().isEmpty();
        } else if (provider == APIClient.GPTProvider.OPENAI_COMPATIBLE) {
            // OpenAI Compatible requires API key, model, and custom URL
            String customUrl = getCustomApiUrl();
            return !apiKey.trim().isEmpty() && !model.trim().isEmpty() && !customUrl.trim().isEmpty();
        } else {
            return !apiKey.trim().isEmpty() && !model.trim().isEmpty();
        }
    }
    
    /**
     * Checks if configuration file exists
     */
    public boolean configurationFileExists() {
        return Files.exists(configPath);
    }
    
    /**
     * Gets the API timeout in seconds
     */
    public int getTimeoutSeconds() {
        String timeoutStr = properties.getProperty(TIMEOUT_PROPERTY, String.valueOf(APIClient.DEFAULT_TIMEOUT_SECONDS));
        try {
            return Integer.parseInt(timeoutStr);
        } catch (NumberFormatException e) {
            return APIClient.DEFAULT_TIMEOUT_SECONDS;
        }
    }
    
    /**
     * Sets the API timeout in seconds
     */
    public void setTimeoutSeconds(int timeoutSeconds) {
        properties.setProperty(TIMEOUT_PROPERTY, String.valueOf(timeoutSeconds));
    }
    
    /**
     * Gets the custom API URL
     */
    public String getCustomApiUrl() {
        return properties.getProperty(CUSTOM_API_URL_PROPERTY, "");
    }
    
    /**
     * Sets the custom API URL
     */
    public void setCustomApiUrl(String customApiUrl) {
        properties.setProperty(CUSTOM_API_URL_PROPERTY, customApiUrl != null ? customApiUrl : "");
    }
    
    /**
     * Whether to apply LLM-suggested function renames
     */
    public boolean isApplyFunctionRename() {
        return Boolean.parseBoolean(properties.getProperty(APPLY_FUNCTION_RENAME_PROPERTY, "false"));
    }
    
    public void setApplyFunctionRename(boolean apply) {
        properties.setProperty(APPLY_FUNCTION_RENAME_PROPERTY, String.valueOf(apply));
    }
    
    /**
     * Whether to apply LLM-suggested function prototypes
     */
    public boolean isApplyFunctionPrototype() {
        return Boolean.parseBoolean(properties.getProperty(APPLY_FUNCTION_PROTOTYPE_PROPERTY, "false"));
    }
    
    public void setApplyFunctionPrototype(boolean apply) {
        properties.setProperty(APPLY_FUNCTION_PROTOTYPE_PROPERTY, String.valueOf(apply));
    }
    
    /**
     * Whether to print per-suggestion summary to console after rewrite
     */
    public boolean isPrintRewriteSummary() {
        return Boolean.parseBoolean(properties.getProperty(PRINT_REWRITE_SUMMARY_PROPERTY, "true"));
    }
    
    public void setPrintRewriteSummary(boolean print) {
        properties.setProperty(PRINT_REWRITE_SUMMARY_PROPERTY, String.valueOf(print));
    }
    
    public String getDebugMode() {
        return properties.getProperty(DEBUG_MODE_PROPERTY, "off");
    }
    
    public void setDebugMode(String mode) {
        properties.setProperty(DEBUG_MODE_PROPERTY, mode != null ? mode : "off");
    }
    
    public String getDebugPath() {
        return properties.getProperty(DEBUG_PATH_PROPERTY, "");
    }
    
    public void setDebugPath(String path) {
        properties.setProperty(DEBUG_PATH_PROPERTY, path != null ? path : "");
    }

    public String getDebugFile() {
        return properties.getProperty(DEBUG_FILE_PROPERTY, "");
    }

    public void setDebugFile(String file) {
        properties.setProperty(DEBUG_FILE_PROPERTY, file != null ? file : "");
    }
    
    /**
     * Custom instructions appended to the AI prompt
     */
    public String getCustomInstructions() {
        return properties.getProperty(CUSTOM_INSTRUCTIONS_PROPERTY, "");
    }
    
    public void setCustomInstructions(String instructions) {
        properties.setProperty(CUSTOM_INSTRUCTIONS_PROPERTY, instructions != null ? instructions : "");
    }

    public String getSystemPrompt() {
        return properties.getProperty(SYSTEM_PROMPT_PROPERTY, DEFAULT_SYSTEM_PROMPT);
    }

    public void setSystemPrompt(String prompt) {
        properties.setProperty(SYSTEM_PROMPT_PROPERTY, prompt != null ? prompt : DEFAULT_SYSTEM_PROMPT);
    }

    public boolean isLockPrompts() {
        return Boolean.parseBoolean(properties.getProperty(LOCK_PROMPTS_PROPERTY, "false"));
    }

    public void setLockPrompts(boolean lock) {
        properties.setProperty(LOCK_PROMPTS_PROPERTY, String.valueOf(lock));
    }

    public boolean isEnableThinking() {
        return Boolean.parseBoolean(properties.getProperty(ENABLE_THINKING_PROPERTY, "false"));
    }

    public void setEnableThinking(boolean enable) {
        properties.setProperty(ENABLE_THINKING_PROPERTY, String.valueOf(enable));
    }

    public int getThinkingThresholdKb() {
        return Integer.parseInt(properties.getProperty(THINKING_THRESHOLD_PROPERTY, "0"));
    }

    public void setThinkingThresholdKb(int kb) {
        properties.setProperty(THINKING_THRESHOLD_PROPERTY, String.valueOf(kb));
    }

    public int getProcessingTimeoutMinutes() {
        return Integer.parseInt(properties.getProperty(PROCESSING_TIMEOUT_PROPERTY, "0"));
    }

    public void setProcessingTimeoutMinutes(int minutes) {
        properties.setProperty(PROCESSING_TIMEOUT_PROPERTY, String.valueOf(minutes));
    }

    public int getMaxResponseSizeKb() {
        return Integer.parseInt(properties.getProperty(MAX_RESPONSE_SIZE_PROPERTY, "0"));
    }

    public void setMaxResponseSizeKb(int kb) {
        properties.setProperty(MAX_RESPONSE_SIZE_PROPERTY, String.valueOf(kb));
    }

    public boolean isRenameNamedLocals() {
        return Boolean.parseBoolean(properties.getProperty(RENAME_NAMED_LOCALS_PROPERTY, "false"));
    }

    public void setRenameNamedLocals(boolean rename) {
        properties.setProperty(RENAME_NAMED_LOCALS_PROPERTY, String.valueOf(rename));
    }

    public boolean isRenameNamedFields() {
        return Boolean.parseBoolean(properties.getProperty(RENAME_NAMED_FIELDS_PROPERTY, "false"));
    }

    public void setRenameNamedFields(boolean rename) {
        properties.setProperty(RENAME_NAMED_FIELDS_PROPERTY, String.valueOf(rename));
    }

    public boolean isRenameNamedFunctions() {
        return Boolean.parseBoolean(properties.getProperty(RENAME_NAMED_FUNCTIONS_PROPERTY, "false"));
    }

    public void setRenameNamedFunctions(boolean rename) {
        properties.setProperty(RENAME_NAMED_FUNCTIONS_PROPERTY, String.valueOf(rename));
    }

    public boolean isRenameNamedClasses() {
        return Boolean.parseBoolean(properties.getProperty(RENAME_NAMED_CLASSES_PROPERTY, "false"));
    }

    public void setRenameNamedClasses(boolean rename) {
        properties.setProperty(RENAME_NAMED_CLASSES_PROPERTY, String.valueOf(rename));
    }
    
    /**
     * Gets the configuration file path for debugging
     */
    public String getConfigurationPath() {
        return configPath.toString();
    }
    
    // ===== Hardware-Derived Encryption Methods =====
    
    /**
     * Gets the static XOR key for encryption/decryption
     */
    private String getXorKey() {
        return XOR_KEY;
    }
    
    /**
     * Encrypts API key using XOR with static key and hex encoding
     */
    private String encryptApiKey(String apiKey) {
        if (apiKey == null || apiKey.isEmpty()) {
            return "";
        }
        
        try {
            String xorKey = getXorKey();
            byte[] keyBytes = xorKey.getBytes("UTF-8");
            byte[] apiKeyBytes = apiKey.getBytes("UTF-8");
            
            // XOR encryption
            byte[] encrypted = new byte[apiKeyBytes.length];
            for (int i = 0; i < apiKeyBytes.length; i++) {
                encrypted[i] = (byte) (apiKeyBytes[i] ^ keyBytes[i % keyBytes.length]);
            }
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : encrypted) {
                hexString.append(String.format("%02x", b & 0xFF));
            }
            
            return hexString.toString();
            
        } catch (Exception e) {
            System.err.println("Encryption failed, storing as plain text: " + e.getMessage());
            return apiKey; // Fallback to plain text
        }
    }
    
    /**
     * Decrypts API key using XOR with static key from hex encoding
     */
    private String decryptApiKey(String encryptedHex) {
        if (encryptedHex == null || encryptedHex.isEmpty()) {
            return "";
        }
        
        try {
            // Convert hex string back to bytes
            byte[] encrypted = new byte[encryptedHex.length() / 2];
            for (int i = 0; i < encrypted.length; i++) {
                int index = i * 2;
                int val = Integer.parseInt(encryptedHex.substring(index, index + 2), 16);
                encrypted[i] = (byte) val;
            }
            
            // Use same static key for decryption
            String xorKey = getXorKey();
            byte[] keyBytes = xorKey.getBytes("UTF-8");
            
            // XOR decryption (same as encryption for XOR)
            byte[] decrypted = new byte[encrypted.length];
            for (int i = 0; i < encrypted.length; i++) {
                decrypted[i] = (byte) (encrypted[i] ^ keyBytes[i % keyBytes.length]);
            }
            
            return new String(decrypted, "UTF-8");
            
        } catch (Exception e) {
            System.err.println("Decryption failed: " + e.getMessage());
            return null; // Return null to indicate failure
        }
    }
    
    /**
     * Checks if API key is stored in encrypted format
     */
    public boolean isApiKeyEncrypted() {
        String encryptedKey = properties.getProperty(API_KEY_ENCRYPTED_PROPERTY);
        return encryptedKey != null && !encryptedKey.trim().isEmpty();
    }
    
    /**
     * This method is no longer needed since we only use encrypted storage
     * Kept for API compatibility but does nothing
     */
    @Deprecated
    public void migrateToEncryptedApiKey() {
        // No-op: We always use encrypted storage now
    }
    
    /**
     * Tests if the current hardware key can decrypt the stored API key
     * Useful for detecting system changes that break decryption
     */
    public boolean canDecryptStoredKey() {
        String encryptedKey = properties.getProperty(API_KEY_ENCRYPTED_PROPERTY);
        if (encryptedKey == null || encryptedKey.trim().isEmpty()) {
            return true; // No encrypted key to test
        }
        
        String decrypted = decryptApiKey(encryptedKey);
        return decrypted != null && !decrypted.isEmpty();
    }
    
    /**
     * Forces re-encryption of API key with current hardware signature
     * Call this if system changes have made the key unreadable
     */
    public boolean reEncryptApiKey(String newApiKey) {
        if (newApiKey == null || newApiKey.trim().isEmpty()) {
            return false;
        }
        
        // Clear old encrypted key
        properties.setProperty(API_KEY_ENCRYPTED_PROPERTY, "");
        
        // Store new key with current hardware signature
        setApiKey(newApiKey);
        
        // Test that we can read it back
        return canDecryptStoredKey();
    }
}
