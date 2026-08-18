package ghidragpt.ui;

import ghidragpt.config.ConfigurationManager;
import ghidragpt.service.APIClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.JComboBox;
import java.lang.reflect.Field;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ConfigurationPanelTest {

    @TempDir
    Path tempDir;

    @Test
    void loadConfiguration_appliesPersistedValuesToClient() throws Exception {
        ConfigurationManager config = new ConfigurationManager(tempDir);
        config.setApiKey("test-key");
        config.setProvider(APIClient.GPTProvider.OLLAMA);
        config.setModel("qwen3");
        config.setProcessingTimeoutMinutes(7);
        config.setMaxResponseSizeKb(256);
        config.setEnableThinking(true);
        config.setSystemPrompt("system");
        config.saveConfiguration();

        APIClient client = new APIClient();
        new ConfigurationPanel(client, new ConfigurationManager(tempDir));

        assertEquals(APIClient.GPTProvider.OLLAMA, client.getProvider());
        assertEquals("qwen3", client.getModel());
        assertEquals(7, client.getProcessingTimeoutMinutes());
        assertEquals(256, client.getMaxResponseSizeKb());
        assertTrue(client.isEnableThinking());
        assertEquals("system", client.getSystemPrompt());
    }

    @Test
    void restoreConfiguration_reloadsSavedValues() throws Exception {
        ConfigurationManager config = new ConfigurationManager(tempDir);
        config.setProvider(APIClient.GPTProvider.OPENAI);
        config.setModel("gpt-test");
        config.saveConfiguration();

        APIClient client = new APIClient();
        ConfigurationPanel panel = new ConfigurationPanel(client, new ConfigurationManager(tempDir));
        JComboBox<?> providers = field(panel, "providerCombo", JComboBox.class);
        JComboBox<?> models = field(panel, "modelCombo", JComboBox.class);

        assertNotNull(providers);
        assertEquals(APIClient.GPTProvider.OPENAI, providers.getSelectedItem());
        assertEquals("gpt-test", models.getSelectedItem());
    }

    @Test
    void panelCanBeConstructedWithoutGhidra() {
        assertNotNull(new ConfigurationPanel(new APIClient(), new ConfigurationManager(tempDir)));
    }

    @SuppressWarnings("unchecked")
    private static <T> T field(Object target, String name, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return (T) field.get(target);
    }
}
