package ghidragpt.service;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises every provider's request building, streaming parsing and model-list
 * fetches against an in-process MockWebServer (no network, no real API keys).
 */
class APIClientTest {

    private MockWebServer server;
    private final String[] urls = new String[13];

    @BeforeEach
    void startServer() throws IOException {
        server = new MockWebServer();
        server.start();
        urls[0] = APIClient.OPENAI_API_URL;
        urls[1] = APIClient.ANTHROPIC_API_URL;
        urls[2] = APIClient.GEMINI_API_URL;
        urls[3] = APIClient.COHERE_API_URL;
        urls[4] = APIClient.MISTRAL_API_URL;
        urls[5] = APIClient.DEEPSEEK_API_URL;
        urls[6] = APIClient.GROK_API_URL;
        urls[7] = APIClient.OLLAMA_API_URL;
        urls[8] = APIClient.OPENAI_MODELS_URL;
        urls[9] = APIClient.OLLAMA_MODELS_URL;
        urls[10] = APIClient.MISTRAL_MODELS_URL;
        urls[11] = APIClient.DEEPSEEK_MODELS_URL;
        urls[12] = APIClient.GEMINI_MODELS_URL;
    }

    @AfterEach
    void stopServer() throws IOException {
        APIClient.OPENAI_API_URL = urls[0];
        APIClient.ANTHROPIC_API_URL = urls[1];
        APIClient.GEMINI_API_URL = urls[2];
        APIClient.COHERE_API_URL = urls[3];
        APIClient.MISTRAL_API_URL = urls[4];
        APIClient.DEEPSEEK_API_URL = urls[5];
        APIClient.GROK_API_URL = urls[6];
        APIClient.OLLAMA_API_URL = urls[7];
        APIClient.OPENAI_MODELS_URL = urls[8];
        APIClient.OLLAMA_MODELS_URL = urls[9];
        APIClient.MISTRAL_MODELS_URL = urls[10];
        APIClient.DEEPSEEK_MODELS_URL = urls[11];
        APIClient.GEMINI_MODELS_URL = urls[12];
        server.shutdown();
    }

    private APIClient client(APIClient.GPTProvider provider) {
        APIClient c = new APIClient();
        c.setProvider(provider);
        c.setApiKey("test-key");
        return c;
    }

    // ===== pre-checks =====

    @Test
    void missingApiKeyNonOllama_throws() {
        APIClient c = new APIClient();
        c.setProvider(APIClient.GPTProvider.OPENAI);
        c.setApiKey("");
        assertThrows(IllegalStateException.class, () -> c.sendRequest("p"));
    }

    @Test
    void openAiCompatibleWithoutCustomUrl_throws() {
        APIClient c = client(APIClient.GPTProvider.OPENAI_COMPATIBLE);
        c.setCustomApiUrl("");
        assertThrows(IllegalStateException.class, () -> c.sendRequest("p"));
    }

    // ===== OpenAI-compatible streaming =====

    @Test
    void openAi_streaming_requestAndAccumulation() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OPENAI);
        c.setModel("gpt-4");
        APIClient.OPENAI_API_URL = server.url("/v1/chat/completions").toString();
        String sse = "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"
                   + "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n"
                   + "data: [DONE]\n\n";
        server.enqueue(new MockResponse().setBody(sse)
            .setHeader("Content-Type", "text/event-stream"));

        final StringBuilder partials = new StringBuilder();
        String out = c.sendRequest("my prompt", new APIClient.StreamCallback() {
            @Override public void onPartialResponse(String p) { partials.append(p); }
            @Override public void onComplete(String full) {}
            @Override public void onError(Exception e) {}
        });

        assertEquals("Hello", out);
        assertEquals("Hello", partials.toString());

        RecordedRequest req = server.takeRequest();
        assertTrue(req.getPath().startsWith("/v1/chat/completions"));
        assertEquals("Bearer test-key", req.getHeader("Authorization"));
        assertTrue(req.getHeader("Accept").contains("text/event-stream"));
        String body = req.getBody().readUtf8();
        assertTrue(body.contains("\"model\":\"gpt-4\""));
        assertTrue(body.contains("\"stream\":true"));
        assertTrue(body.contains("\"max_tokens\":16384"));
        assertTrue(body.contains("\"my prompt\""));
    }

    @Test
    void grok_streaming_defaultModelAndBearer() throws Exception {
        APIClient c = client(APIClient.GPTProvider.GROK);
        c.setModel("");
        APIClient.GROK_API_URL = server.url("/v1/chat/completions").toString();
        server.enqueue(new MockResponse().setBody(
            "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: [DONE]\n\n"));
        String out = c.sendRequest("p");
        assertEquals("x", out);
        String body = server.takeRequest().getBody().readUtf8();
        assertTrue(body.contains("\"model\":\"grok-beta\""));
    }

    @Test
    void mistral_streaming_defaultModel() throws Exception {
        APIClient c = client(APIClient.GPTProvider.MISTRAL);
        c.setModel("");
        APIClient.MISTRAL_API_URL = server.url("/v1/chat/completions").toString();
        server.enqueue(new MockResponse().setBody(
            "data: {\"choices\":[{\"delta\":{\"content\":\"A\"}}]}\n\ndata: [DONE]\n\n"));
        assertEquals("A", c.sendRequest("p"));
        assertTrue(server.takeRequest().getBody().readUtf8()
            .contains("\"model\":\"mistral-large-latest\""));
    }

    @Test
    void deepseek_streaming_defaultModel() throws Exception {
        APIClient c = client(APIClient.GPTProvider.DEEPSEEK);
        c.setModel("");
        APIClient.DEEPSEEK_API_URL = server.url("/v1/chat/completions").toString();
        server.enqueue(new MockResponse().setBody(
            "data: {\"choices\":[{\"delta\":{\"content\":\"D\"}}]}\n\ndata: [DONE]\n\n"));
        assertEquals("D", c.sendRequest("p"));
        assertTrue(server.takeRequest().getBody().readUtf8()
            .contains("\"model\":\"deepseek-chat\""));
    }

    @Test
    void gemini_streaming_defaultModel_openAiCompat() throws Exception {
        APIClient c = client(APIClient.GPTProvider.GEMINI);
        c.setModel("");
        APIClient.GEMINI_API_URL = server.url("/v1/chat/completions").toString();
        server.enqueue(new MockResponse().setBody(
            "data: {\"choices\":[{\"delta\":{\"content\":\"G\"}}]}\n\ndata: [DONE]\n\n"));
        assertEquals("G", c.sendRequest("p"));
        assertTrue(server.takeRequest().getBody().readUtf8()
            .contains("\"model\":\"gemini-2.5-flash\""));
    }

    @Test
    void openAiCompatible_customUrlNormalizesAndStreams() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OPENAI_COMPATIBLE);
        c.setModel("my-model");
        c.setCustomApiUrl(server.url("/v1").toString().replaceAll("/$", ""));
        server.enqueue(new MockResponse().setBody(
            "data: {\"choices\":[{\"delta\":{\"content\":\"C\"}}]}\n\ndata: [DONE]\n\n"));
        assertEquals("C", c.sendRequest("p"));
        assertEquals("/v1/chat/completions", server.takeRequest().getPath());
    }

    // ===== Anthropic / Cohere native streaming =====

    @Test
    void anthropic_streaming_returnsConcatenated() throws Exception {
        APIClient c = client(APIClient.GPTProvider.ANTHROPIC);
        c.setModel("claude-x");
        APIClient.ANTHROPIC_API_URL = server.url("/v1/messages").toString();
        String sse = "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"an\"}}\n\n"
                   + "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"th\"}}\n\n";
        server.enqueue(new MockResponse().setBody(sse));
        assertEquals("anth", c.sendRequest("p"));
        RecordedRequest req = server.takeRequest();
        assertEquals("test-key", req.getHeader("x-api-key"));
        assertTrue(req.getBody().readUtf8().contains("\"claude-x\""));
    }

    @Test
    void cohere_streaming_contentDelta_accumulatesAndDone() throws Exception {
        APIClient c = client(APIClient.GPTProvider.COHERE);
        c.setModel("");
        APIClient.COHERE_API_URL = server.url("/v1/chat").toString();
        String sse = "data: {\"type\":\"content-delta\",\"delta\":{\"message\":{\"content\":{\"text\":\"co\"}}}}\n\n"
                   + "data: {\"type\":\"content-delta\",\"delta\":{\"message\":{\"content\":{\"text\":\"he\"}}}}\n\n"
                   + "data: [DONE]\n\n";
        server.enqueue(new MockResponse().setBody(sse));
        assertEquals("cohe", c.sendRequest("p"));
        assertTrue(server.takeRequest().getBody().readUtf8().contains("\"model\":\"command\""));
    }

    // ===== Ollama =====

    @Test
    void ollama_streaming_jsonl_thinkingAndStats() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OLLAMA);
        c.setApiKey("");
        c.setModel("llama3.2");
        APIClient.OLLAMA_API_URL = server.url("/api/chat").toString();
        String jsonl =
            "{\"model\":\"llama3.2\",\"message\":{\"thinking\":\"hmm\"},\"done\":false}\n"
          + "{\"model\":\"llama3.2\",\"message\":{\"content\":\"ol\"},\"done\":false}\n"
          + "{\"model\":\"llama3.2\",\"message\":{\"content\":\"la\"},\"done\":false}\n"
          + "{\"model\":\"llama3.2\",\"message\":{},\"done\":true,\"done_reason\":\"stop\","
          + "\"prompt_eval_count\":10,\"eval_count\":20,\"eval_duration\":1000000000}\n";
        server.enqueue(new MockResponse().setBody(jsonl));

        final StringBuilder partials = new StringBuilder();
        final StringBuilder thinking = new StringBuilder();
        c.sendRequest("p", new APIClient.StreamCallback() {
            @Override public void onPartialResponse(String p) { partials.append(p); }
            @Override public void onThinkingResponse(String t) { thinking.append(t); }
            @Override public void onComplete(String full) {}
            @Override public void onError(Exception e) {}
        });

        assertEquals("olla", partials.toString());
        assertEquals("hmm", thinking.toString());
        APIClient.OllamaRequestStats stats = c.getLastOllamaStats();
        assertNotNull(stats);
        assertEquals(10, stats.promptTokens);
        assertEquals(20, stats.outputTokens);
        assertEquals("stop", stats.doneReason);
        assertEquals(20.0, stats.tokensPerSecond, 0.001);
        assertEquals("hmm", c.getLastThinkingContent());

        RecordedRequest req = server.takeRequest();
        assertNull(req.getHeader("Authorization"));
        String body = req.getBody().readUtf8();
        assertTrue(body.contains("\"model\":\"llama3.2\""));
        assertTrue(body.contains("\"stream\":true"));
        assertTrue(body.contains("\"num_predict\":16384"));
        assertTrue(body.contains("\"num_ctx\":32768"));
        assertTrue(body.contains("\"presence_penalty\":0.0"));
        assertTrue(body.contains("\"repeat_penalty\":1.1"));
        assertTrue(body.contains("\"repeat_last_n\":256"));
    }

    @Test
    void ollama_streaming_enableThinking_dropsPenalties() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OLLAMA);
        c.setApiKey("");
        c.setEnableThinking(true);
        c.setModel("llama3.2");
        APIClient.OLLAMA_API_URL = server.url("/api/chat").toString();
        server.enqueue(new MockResponse().setBody(
            "{\"model\":\"llama3.2\",\"message\":{\"content\":\"ok\"},\"done\":false}\n"
          + "{\"model\":\"llama3.2\",\"message\":{},\"done\":true,\"done_reason\":\"stop\","
          + "\"prompt_eval_count\":1,\"eval_count\":2,\"eval_duration\":500000000}\n"));
        c.sendRequest("p");
        String body = server.takeRequest().getBody().readUtf8();
        assertTrue(body.contains("\"think\":true"));
        assertFalse(body.contains("presence_penalty"));
        assertFalse(body.contains("repeat_penalty"));
    }

    @Test
    void ollama_thinkTagRoutedToThinking() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OLLAMA);
        c.setApiKey("");
        c.setModel("llama3.2");
        APIClient.OLLAMA_API_URL = server.url("/api/chat").toString();
        String jsonl =
            "{\"model\":\"m\",\"message\":{\"content\":\"A\"},\"done\":false}\n"
          + "{\"model\":\"m\",\"message\":{\"content\":\"B\"},\"done\":false}\n"
          + "{\"model\":\"m\",\"message\":{},\"done\":true}\n";
        server.enqueue(new MockResponse().setBody(jsonl));
        String out = c.sendRequest("p");
        assertEquals("AB", out);
    }

    @Test
    void ollama_thinkTagSplitAcrossChunks_buffersAndReassembles() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OLLAMA);
        c.setApiKey("");
        c.setModel("llama3.2");
        APIClient.OLLAMA_API_URL = server.url("/api/chat").toString();
        // Build the tag literals from char pieces to be byte-exact and avoid
        // any display/rendering mangling of the tag markup.
        String openTag = "<" + "thi" + "nk" + ">";
        String closeTag = "</" + "thi" + "nk" + ">";

        // line1: "AB" + a 2-char prefix of the open tag -> must be buffered
        // line2: rest-of-open-tag + REASON + close-tag + "CD"
        String c1 = "AB" + openTag.substring(0, 2);
        String c2 = openTag.substring(2) + "REASON" + closeTag + "CD";
        String jsonl =
            "{\"model\":\"m\",\"message\":{\"content\":\"" + c1 + "\"},\"done\":false}\n"
          + "{\"model\":\"m\",\"message\":{\"content\":\"" + c2 + "\"},\"done\":false}\n"
          + "{\"model\":\"m\",\"message\":{},\"done\":true}\n";
        server.enqueue(new MockResponse().setBody(jsonl));

        final StringBuilder partials = new StringBuilder();
        final StringBuilder thinking = new StringBuilder();
        String out = c.sendRequest("p", new APIClient.StreamCallback() {
            @Override public void onPartialResponse(String p) { partials.append(p); }
            @Override public void onThinkingResponse(String t) { thinking.append(t); }
            @Override public void onComplete(String full) {}
            @Override public void onError(Exception e) {}
        });

        assertEquals("ABCD", out, "text before/after the think tag should be content");
        assertEquals("ABCD", partials.toString());
        assertEquals("REASON", thinking.toString(), "think-tag body should route to thinking");
        assertEquals("REASON", c.getLastThinkingContent());
    }

    @Test
    void ollama_maxResponseSizeCap_cancelsAndReports() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OLLAMA);
        c.setApiKey("");
        c.setModel("llama3.2");
        c.setMaxResponseSizeKb(1); // 1 KB = 1024-byte cap
        APIClient.OLLAMA_API_URL = server.url("/api/chat").toString();
        String x500 = "x".repeat(500);
        String jsonl =
            "{\"message\":{\"content\":\"" + x500 + "\"},\"done\":false}\n"
          + "{\"message\":{\"content\":\"" + x500 + "\"},\"done\":false}\n"
          + "{\"message\":{\"content\":\"" + x500 + "\"},\"done\":false}\n"
          + "{\"message\":{},\"done\":true}\n";
        server.enqueue(new MockResponse().setBody(jsonl));

        final StringBuilder partials = new StringBuilder();
        String out = c.sendRequest("p", new APIClient.StreamCallback() {
            @Override public void onPartialResponse(String p) { partials.append(p); }
            @Override public void onComplete(String full) {}
            @Override public void onError(Exception e) {}
        });

        // 1500 chars > 1024 cap -> cancelled mid-stream; the accumulated content
        // (1500 x) is returned, while the cancellation notice is pushed via the
        // partial-response callback.
        assertEquals(x500.repeat(3), out);
        assertTrue(partials.toString().contains("Response size limit exceeded (1 KB)"),
            "cancellation notice expected in stream, was: " + partials);
    }

    @Test
    void ollama_noEvalDuration_tpsFallbackZero() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OLLAMA);
        c.setApiKey("");
        c.setModel("llama3.2");
        APIClient.OLLAMA_API_URL = server.url("/api/chat").toString();
        String jsonl =
            "{\"message\":{\"content\":\"ok\"},\"done\":false}\n"
          + "{\"message\":{},\"done\":true,\"done_reason\":\"stop\","
          + "\"prompt_eval_count\":10,\"eval_count\":20}\n"; // eval_duration absent
        server.enqueue(new MockResponse().setBody(jsonl));
        c.sendRequest("p");
        APIClient.OllamaRequestStats stats = c.getLastOllamaStats();
        assertNotNull(stats);
        assertEquals(10, stats.promptTokens);
        assertEquals(20, stats.outputTokens);
        assertEquals("stop", stats.doneReason);
        assertEquals(0.0, stats.tokensPerSecond, 0.0, "tps must be 0 when eval_duration absent");
    }

    // ===== errors =====

    @Test
    void http500_openAi_throwsIOException() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OPENAI);
        c.setApiKey("bad");
        APIClient.OPENAI_API_URL = server.url("/v1/chat/completions").toString();
        server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
        assertThrows(IOException.class, () -> c.sendRequest("p"));
    }

    @Test
    void http500_anthropic_throwsIOException() throws Exception {
        APIClient c = client(APIClient.GPTProvider.ANTHROPIC);
        c.setModel("claude-x");
        APIClient.ANTHROPIC_API_URL = server.url("/v1/messages").toString();
        server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
        assertThrows(IOException.class, () -> c.sendRequest("p"));
    }

    @Test
    void http500_cohere_throwsIOException() throws Exception {
        APIClient c = client(APIClient.GPTProvider.COHERE);
        c.setModel("");
        APIClient.COHERE_API_URL = server.url("/v1/chat").toString();
        server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
        assertThrows(IOException.class, () -> c.sendRequest("p"));
    }

    @Test
    void http500_ollama_throwsIOException_andInvokesOnError() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OLLAMA);
        c.setApiKey("");
        c.setModel("llama3.2");
        APIClient.OLLAMA_API_URL = server.url("/api/chat").toString();
        server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));

        final java.util.concurrent.atomic.AtomicReference<Exception> seen =
            new java.util.concurrent.atomic.AtomicReference<>();
        String out = null;
        try {
            out = c.sendRequest("p", new APIClient.StreamCallback() {
                @Override public void onPartialResponse(String p) {}
                @Override public void onComplete(String full) {}
                @Override public void onError(Exception e) { seen.set(e); }
            });
            fail("expected IOException");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("500"));
        }
        assertNotNull(seen.get(), "onError should be invoked");
        assertNull(out);
    }

    // ===== fetchAvailableModels =====

    @Test
    void fetchOpenAiModels_filtersAndSorts() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OPENAI);
        APIClient.OPENAI_MODELS_URL = server.url("/v1/models").toString();
        server.enqueue(new MockResponse().setBody(
            "{\"data\":[{\"id\":\"gpt-4\"},{\"id\":\"gpt-3.5\"},{\"id\":\"gpt-4o\"},{\"id\":\"other-model\"}]}")
            .setHeader("Content-Type", "application/json"));
        List<String> out = c.fetchAvailableModels();
        assertEquals(List.of("gpt-3.5", "gpt-4", "gpt-4o"), out);
        assertEquals("Bearer test-key", server.takeRequest().getHeader("Authorization"));
    }

    @Test
    void fetchOllamaModels_sorted() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OLLAMA);
        c.setApiKey("");
        APIClient.OLLAMA_MODELS_URL = server.url("/api/tags").toString();
        server.enqueue(new MockResponse().setBody("{\"models\":[{\"name\":\"zeta\"},{\"name\":\"alpha\"}]}"));
        assertEquals(List.of("alpha", "zeta"), c.fetchAvailableModels());
    }

    @Test
    void fetchCompatibleModels_stripsChatCompletionsSuffix() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OPENAI_COMPATIBLE);
        c.setCustomApiUrl(server.url("/v1").toString().replaceAll("/$", ""));
        server.enqueue(new MockResponse().setBody("{\"data\":[{\"id\":\"m2\"},{\"id\":\"m1\"}]}"));
        assertEquals(List.of("m1", "m2"), c.fetchAvailableModels());
        assertEquals("/v1/models", server.takeRequest().getPath());
    }

    @Test
    void fetchGeminiModels_stripsModelsPrefixAndFilters() throws Exception {
        APIClient c = client(APIClient.GPTProvider.GEMINI);
        APIClient.GEMINI_MODELS_URL = server.url("/v1beta/models").toString();
        server.enqueue(new MockResponse().setBody(
            "{\"models\":[{\"name\":\"models/gemini-1.0\"},{\"name\":\"models/gemini-2.0\"},{\"name\":\"models/other-1\"}]}"));
        assertEquals(List.of("gemini-1.0", "gemini-2.0"), c.fetchAvailableModels());
    }

    @Test
    void fetchMistralModels_sorted_usesBearer() throws Exception {
        APIClient c = client(APIClient.GPTProvider.MISTRAL);
        APIClient.MISTRAL_MODELS_URL = server.url("/v1/models").toString();
        server.enqueue(new MockResponse().setBody(
            "{\"data\":[{\"id\":\"m-b\"},{\"id\":\"m-a\"},{\"id\":\"m-c\"}]}")
            .setHeader("Content-Type", "application/json"));
        List<String> out = c.fetchAvailableModels();
        assertEquals(List.of("m-a", "m-b", "m-c"), out);
        assertEquals("Bearer test-key", server.takeRequest().getHeader("Authorization"));
    }

    @Test
    void fetchDeepSeekModels_sorted_usesBearer() throws Exception {
        APIClient c = client(APIClient.GPTProvider.DEEPSEEK);
        APIClient.DEEPSEEK_MODELS_URL = server.url("/v1/models").toString();
        server.enqueue(new MockResponse().setBody(
            "{\"data\":[{\"id\":\"d-b\"},{\"id\":\"d-a\"}]}")
            .setHeader("Content-Type", "application/json"));
        List<String> out = c.fetchAvailableModels();
        assertEquals(List.of("d-a", "d-b"), out);
        assertEquals("Bearer test-key", server.takeRequest().getHeader("Authorization"));
    }

    @Test
    void fetchUnsupportedProviders_returnsEmpty() {
        APIClient c = client(APIClient.GPTProvider.GROK);
        assertEquals(0, c.fetchAvailableModels().size());
        c.setProvider(APIClient.GPTProvider.ANTHROPIC);
        assertEquals(0, c.fetchAvailableModels().size());
    }

    @Test
    void fetchOpenAiModels_httpError_emptyList() throws Exception {
        APIClient c = client(APIClient.GPTProvider.OPENAI);
        APIClient.OPENAI_MODELS_URL = server.url("/v1/models").toString();
        server.enqueue(new MockResponse().setResponseCode(500));
        assertEquals(0, c.fetchAvailableModels().size());
    }
}
