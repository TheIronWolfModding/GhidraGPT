package ghidragpt.config;

import ghidragpt.service.APIClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ConfigurationManagerTest {

    @TempDir
    Path tempDir;

    private Path configDir;

    @BeforeEach
    void setUpDir() {
        this.configDir = tempDir;
    }

    private ConfigurationManager fresh() {
        return new ConfigurationManager(configDir);
    }

    @Test
    void freshDefaults() {
        ConfigurationManager cm = fresh();
        assertEquals(APIClient.GPTProvider.OPENAI, cm.getProvider());
        assertEquals("gpt-4", cm.getModel());
        assertEquals("", cm.getApiKey());
        // no encrypted key stored
        assertFalse(cm.isApiKeyEncrypted());
        assertTrue(cm.canDecryptStoredKey());
    }

    @Test
    void saveAndReloadRoundTrip() throws Exception {
        ConfigurationManager cm = fresh();
        cm.setProvider(APIClient.GPTProvider.ANTHROPIC);
        cm.setModel("claude-3");
        cm.setApiKey("sk-test-123");
        cm.setMaxTokens(4096);
        cm.setContextSize(8192);
        cm.setTemperature(0.7);
        cm.setTopP(0.5);
        cm.setTopK(10);
        cm.setPresencePenalty(0.2);
        cm.setRepetitionPenalty(1.2);
        cm.setTimeoutSeconds(120);
        cm.setCustomApiUrl("http://example.com/v1");
        cm.setApplyFunctionRename(true);
        cm.setApplyFunctionPrototype(true);
        cm.setCustomInstructions("only C code");
        cm.setSystemPrompt("You are a helper");
        cm.setPrintRewriteSummary(false);
        cm.setDebugMode("save");
        cm.setDebugPath("/tmp/dbg");
        cm.setDebugFile("out.json");
        cm.setLockPrompts(true);
        cm.setEnableThinking(true);
        cm.setThinkingThresholdKb(4);
        cm.setProcessingTimeoutMinutes(2);
        cm.setMaxResponseSizeKb(3);
        cm.setRenameNamedLocals(true);
        cm.setRenameNamedFields(true);
        cm.setRenameNamedFunctions(true);
        cm.setRenameNamedClasses(true);
        cm.saveConfiguration();

        ConfigurationManager reloaded = new ConfigurationManager(configDir);
        assertEquals(APIClient.GPTProvider.ANTHROPIC, reloaded.getProvider());
        assertEquals("claude-3", reloaded.getModel());
        assertEquals("sk-test-123", reloaded.getApiKey());
        assertEquals(4096, reloaded.getMaxTokens());
        assertEquals(8192, reloaded.getContextSize());
        assertEquals(0.7, reloaded.getTemperature());
        assertEquals(0.5, reloaded.getTopP());
        assertEquals(10, reloaded.getTopK());
        assertEquals(0.2, reloaded.getPresencePenalty());
        assertEquals(1.2, reloaded.getRepetitionPenalty());
        assertEquals(120, reloaded.getTimeoutSeconds());
        assertEquals("http://example.com/v1", reloaded.getCustomApiUrl());
        assertTrue(reloaded.isApplyFunctionRename());
        assertTrue(reloaded.isApplyFunctionPrototype());
        assertEquals("only C code", reloaded.getCustomInstructions());
        assertEquals("You are a helper", reloaded.getSystemPrompt());
        assertFalse(reloaded.isPrintRewriteSummary());
        assertEquals("save", reloaded.getDebugMode());
        assertEquals("/tmp/dbg", reloaded.getDebugPath());
        assertEquals("out.json", reloaded.getDebugFile());
        assertTrue(reloaded.isLockPrompts());
        assertTrue(reloaded.isEnableThinking());
        assertEquals(4, reloaded.getThinkingThresholdKb());
        assertEquals(2, reloaded.getProcessingTimeoutMinutes());
        assertEquals(3, reloaded.getMaxResponseSizeKb());
        assertTrue(reloaded.isRenameNamedLocals());
        assertTrue(reloaded.isRenameNamedFields());
        assertTrue(reloaded.isRenameNamedFunctions());
        assertTrue(reloaded.isRenameNamedClasses());
        assertTrue(reloaded.configurationFileExists());
    }

    @Test
    void apiKeyIsEncryptedOnDisk() throws Exception {
        ConfigurationManager cm = fresh();
        cm.setApiKey("my-secret-key");
        cm.saveConfiguration();
        String file = new String(Files.readAllBytes(configDir.resolve("config.properties")));
        assertFalse(file.contains("my-secret-key"), "API key must not appear in plaintext on disk");
        assertTrue(cm.isApiKeyEncrypted());
        // round trip through decrypt
        cm = new ConfigurationManager(configDir);
        assertEquals("my-secret-key", cm.getApiKey());
    }

    @Test
    void emptyKeyHandling() {
        ConfigurationManager cm = fresh();
        cm.setApiKey("");
        assertEquals("", cm.getApiKey());
        cm.setApiKey(null);
        assertEquals("", cm.getApiKey());
    }

    @Test
    void canDecryptStoredKeyAndReEncrypt() {
        ConfigurationManager cm = fresh();
        assertTrue(cm.canDecryptStoredKey());
        cm.setApiKey("abc");
        assertTrue(cm.canDecryptStoredKey());
        cm.saveConfiguration();
        // re-encrypt with empty -> false
        assertFalse(cm.reEncryptApiKey(""));
        assertFalse(cm.reEncryptApiKey("  "));
        assertTrue(cm.reEncryptApiKey("newkey"));
        assertEquals("newkey", cm.getApiKey());
        assertTrue(cm.canDecryptStoredKey());
    }

    @Test
    void isConfigured_matrix() {
        ConfigurationManager cm = fresh();
        // No key -> not configured
        assertFalse(cm.isConfigured());
        // With key (default model present) -> configured
        cm.setApiKey("k");
        assertTrue(cm.isConfigured());
        // Ollama needs only model
        cm.setProvider(APIClient.GPTProvider.OLLAMA);
        cm.setApiKey("");
        assertTrue(cm.isConfigured());
        cm.setModel("");
        assertFalse(cm.isConfigured());
        // OPENAI_COMPATIBLE requires key + model + custom URL
        cm.setProvider(APIClient.GPTProvider.OPENAI_COMPATIBLE);
        cm.setModel("some-model");
        cm.setApiKey("");
        cm.setCustomApiUrl("");
        assertFalse(cm.isConfigured());
        cm.setApiKey("k");
        cm.setCustomApiUrl("http://localhost:8000");
        assertTrue(cm.isConfigured());
    }

    @Test
    void invalidProviderFallsBackToOpenAi() throws Exception {
        configDir.resolve("config.properties").toFile().getParentFile().mkdirs();
        Files.writeString(configDir.resolve("config.properties"), "api.provider=bogus\n");
        ConfigurationManager cm = new ConfigurationManager(configDir);
        assertEquals(APIClient.GPTProvider.OPENAI, cm.getProvider());
    }

    @Test
    void corruptedConfigFileFallsBackToDefaults() throws Exception {
        // Make the config path unreadable as a file (a directory) -> IOException path
        Files.createDirectories(configDir);
        Files.createDirectory(configDir.resolve("config.properties"));
        ConfigurationManager cm = new ConfigurationManager(configDir);
        assertEquals(APIClient.GPTProvider.OPENAI, cm.getProvider());
        assertEquals("gpt-4", cm.getModel());
    }

    @Test
    void timeoutCorruptValueFallsBackDefault() throws Exception {
        Files.writeString(configDir.resolve("config.properties"), "api.timeout.seconds=notanumber\n");
        ConfigurationManager cm = new ConfigurationManager(configDir);
        assertEquals(APIClient.DEFAULT_TIMEOUT_SECONDS, cm.getTimeoutSeconds());
        cm.setTimeoutSeconds(45);
        cm.saveConfiguration();
        assertEquals(45, new ConfigurationManager(configDir).getTimeoutSeconds());
    }

    @Test
    void getConfigurationPathPointsInsideBaseDir() {
        ConfigurationManager cm = fresh();
        assertTrue(cm.getConfigurationPath().startsWith(configDir.toString()));
    }
}
