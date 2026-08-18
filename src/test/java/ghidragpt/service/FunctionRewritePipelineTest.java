package ghidragpt.service;

import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import ghidragpt.ui.Console;

class FunctionRewritePipelineTest {

    @TempDir
    Path tempDir;

    private Program program;
    private Function function;
    private TaskMonitor monitor;
    private DecompInterface decompiler;
    private APIClient apiClient;

    @BeforeEach
    void setUp() {
        program = mock(Program.class);
        function = mock(Function.class);
        monitor = mock(TaskMonitor.class);
        decompiler = mock(DecompInterface.class);
        apiClient = mock(APIClient.class);

        DataType ret = mock(DataType.class);
        org.mockito.Mockito.when(ret.getDisplayName()).thenReturn("void");
        AddressSetView body = mock(AddressSetView.class);
        org.mockito.Mockito.when(body.getNumAddresses()).thenReturn(50L);

        when(function.getName()).thenReturn("FUN_00400000");
        when(function.getReturnType()).thenReturn(ret);
        when(function.getBody()).thenReturn(body);
        when(function.getParameters()).thenReturn(new ghidra.program.model.listing.Parameter[0]);
        when(function.getLocalVariables()).thenReturn(new ghidra.program.model.listing.Variable[0]);
        when(monitor.isCancelled()).thenReturn(false);
        when(program.startTransaction(anyString())).thenReturn(1);
    }

    private FunctionRewrite build() {
        return new FunctionRewrite(apiClient, null, null, decompiler);
    }

    // ===== early-failure paths =====

    @Test
    void decompilerOpenFails_reportsError() {
        when(decompiler.openProgram(program)).thenReturn(false);
        FunctionRewrite.EnhancementResult result = build().rewriteFunction(function, program, monitor);
        assertFalse(result.errors.isEmpty());
        assertTrue(result.errors.get(0).contains("Failed to initialize decompiler"));
    }

    @Test
    void decompileFails_reportsError() {
        when(decompiler.openProgram(program)).thenReturn(true);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(null);
        FunctionRewrite.EnhancementResult result = build().rewriteFunction(function, program, monitor);
        assertFalse(result.errors.isEmpty());
        assertTrue(result.errors.get(0).contains("Failed to decompile function"));
    }

    // ===== LLM happy path (no apply actions, config = defaults) =====

    @Test
    void llmResponse_emptySpec_noChangesApplied() throws Exception {
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void __thiscall f() { return; }");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(results);
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
            .thenReturn("{\"variable_renames\":{}}");

        FunctionRewrite.EnhancementResult result = build().rewriteFunction(function, program, monitor);
        assertTrue(result.errors.isEmpty(), "errors: " + result.errors);
    }

    @Test
    void functionRenameAppliedWhenConfigEnabled() throws Exception {
        ghidragpt.config.ConfigurationManager cm = new ghidragpt.config.ConfigurationManager(tempDir);
        cm.setApplyFunctionRename(true);

        FunctionRewrite fr = new FunctionRewrite(apiClient, null, cm, decompiler);
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void f() { }");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(results);
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
            .thenReturn("{\"function_name\":\"renamedFunction\"}");

        FunctionRewrite.EnhancementResult result = fr.rewriteFunction(function, program, monitor);
        assertTrue(result.functionRenamed);
        assertEquals("renamedFunction", result.newFunctionName);
    }

    @Test
    void variableRenameDecompileFailure_recordedAsError() throws Exception {
        FunctionRewrite fr = build();
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void f() { }");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        // happy path: one decompile for the main flow, null for internal batches
        when(decompiler.decompileFunction(any(Function.class), anyInt(), eq(monitor))).thenReturn(results);
        when(decompiler.decompileFunction(any(Function.class), anyInt(), any(ghidra.util.task.ConsoleTaskMonitor.class)))
            .thenReturn(null);
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
            .thenReturn("{\"variable_renames\":{\"ivar1\":\"someName\"}}");

        FunctionRewrite.EnhancementResult result = fr.rewriteFunction(function, program, monitor);
        assertTrue(result.errors.stream().anyMatch(e -> e.contains("Failed to rename variable: ivar1")),
            "errors: " + result.errors);
    }

    // ===== debug "load" mode: response read from file, LLM never called =====

    @Test
    void debugLoad_readsResponseFromFile_andSkipsLlm() throws Exception {
        ghidragpt.config.ConfigurationManager cm = new ghidragpt.config.ConfigurationManager(tempDir);
        cm.setDebugMode("load");
        cm.setDebugPath(tempDir.toString());
        cm.setDebugFile("response.txt");
        cm.setApplyFunctionRename(true);

        Files.write(tempDir.resolve("response.txt"),
            "{\"function_name\":\"loadedFromDisk\"}".getBytes());

        FunctionRewrite fr = new FunctionRewrite(apiClient, null, cm, decompiler);
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void f() {}");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(results);

        FunctionRewrite.EnhancementResult result = fr.rewriteFunction(function, program, monitor);
        assertTrue(result.functionRenamed);
        assertEquals("loadedFromDisk", result.newFunctionName);
        verify(apiClient, never()).sendRequest(anyString(), any(APIClient.StreamCallback.class));
    }

    @Test
    void debugLoad_missingDirectory_reportsError() throws Exception {
        ghidragpt.config.ConfigurationManager cm = new ghidragpt.config.ConfigurationManager(tempDir);
        cm.setDebugMode("load");
        cm.setDebugPath("");
        FunctionRewrite fr = new FunctionRewrite(apiClient, null, cm, decompiler);
        // decompile must succeed so the flow reaches the debug-load check
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void f() {}");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(results);

        FunctionRewrite.EnhancementResult result = fr.rewriteFunction(function, program, monitor);
        assertTrue(result.errors.stream().anyMatch(e -> e.contains("Debug Load mode requires a directory path")));
    }

    @Test
    void debugLoad_missingFile_reportsError() throws Exception {
        ghidragpt.config.ConfigurationManager cm = new ghidragpt.config.ConfigurationManager(tempDir);
        cm.setDebugMode("load");
        cm.setDebugPath(tempDir.toString());
        cm.setDebugFile("no-such-file.txt");
        FunctionRewrite fr = new FunctionRewrite(apiClient, null, cm, decompiler);
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void f() {}");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(results);

        FunctionRewrite.EnhancementResult result = fr.rewriteFunction(function, program, monitor);
        assertTrue(result.errors.stream().anyMatch(e -> e.contains("Debug response file not found")));
    }

    // ===== debug "save" mode: writes prompt + response files =====

    @Test
    void debugSave_writesPromptAndResponseFiles() throws Exception {
        Path debugDir = Files.createDirectory(tempDir.resolve("dbg"));
        ghidragpt.config.ConfigurationManager cm = new ghidragpt.config.ConfigurationManager(tempDir);
        cm.setDebugMode("save");
        cm.setDebugPath(debugDir.toString());
        cm.setApplyFunctionRename(false);

        FunctionRewrite fr = new FunctionRewrite(apiClient, null, cm, decompiler);
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void f() {}");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(results);
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
            .thenReturn("{\"variable_renames\":{}}");

        FunctionRewrite.EnhancementResult result = fr.rewriteFunction(function, program, monitor);
        assertTrue(result.errors.isEmpty(), "errors: " + result.errors);

        String[] files = debugDir.toFile().list();
        assertNotNull(files);
        assertEquals(2, files.length, "prompt and response files written");
        // File.list() order is not guaranteed; match by suffix instead of index
        java.util.List<String> names = java.util.Arrays.asList(files);
        assertTrue(names.stream().anyMatch(n -> n.endsWith("-prompt")));
        String respName = names.stream().filter(n -> n.endsWith("-response")).findFirst().orElseThrow();
        String resp = new String(Files.readAllBytes(debugDir.resolve(respName)));
        assertTrue(resp.contains("variable_renames"));
    }

    // ===== cancellation =====

    @Test
    void cancelledBeforeApply_returnsCancelledMessage() throws Exception {
        FunctionRewrite fr = build();
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void f() {}");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(results);
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
            .thenReturn("{\"function_name\":\"x\"}");
        // cancel after LLM response, before parse/apply
        when(monitor.isCancelled()).thenReturn(true);

        FunctionRewrite.EnhancementResult result = fr.rewriteFunction(function, program, monitor);
        assertFalse(result.errors.isEmpty());
        assertTrue(result.errors.get(0).contains("Operation cancelled by user before changes were applied"));
    }

    // ===== console interaction (mocked Console — no Ghidra execution) =====

    private void stubFullPipeline() {
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void f() { return 42; }");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(results);

        when(apiClient.getProvider()).thenReturn(APIClient.GPTProvider.OPENAI);
        when(apiClient.getModel()).thenReturn("gpt-test");
        when(apiClient.getContextSize()).thenReturn(1 << 20);
        when(apiClient.getLastOllamaStats()).thenReturn(null);
        when(apiClient.getLastThinkingContent()).thenReturn(null);
    }

    @Test
    void console_receivesAnalysisHeaderAndOptions() throws Exception {
        ghidragpt.config.ConfigurationManager cm = new ghidragpt.config.ConfigurationManager(tempDir);
        cm.setEnableThinking(false);
        Console console = mock(Console.class);
        FunctionRewrite fr = new FunctionRewrite(apiClient, console, cm, decompiler);
        stubFullPipeline();
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
            .thenReturn("{\"variable_renames\":{}}");

        fr.rewriteFunction(function, program, monitor);

        org.mockito.ArgumentCaptor<String[][]> optsCaptor =
            org.mockito.ArgumentCaptor.forClass(String[][].class);
        verify(console).appendOptions(optsCaptor.capture());
        String[][] opts = optsCaptor.getValue();
        assertTrue(opts.length >= 11, "expect >= 11 option rows, got " + opts.length);
        assertTrue(Arrays.stream(opts).anyMatch(o -> o[0].equals("temperature")));
        assertTrue(Arrays.stream(opts).anyMatch(o -> o[0].equals("think") && o[1].equals("false")));

        verify(console).printAnalysisHeader(
            eq("Comprehensive Function Rewrite"),
            eq("FUN_00400000"),
            eq("OPENAI"),
            eq("gpt-test"),
            anyInt()); // prompt length is promptBuilder-determined
    }

    @Test
    void console_receivesStreamHeaderOnce_andOneAppendPerChunk() throws Exception {
        Console console = mock(Console.class);
        FunctionRewrite fr = new FunctionRewrite(apiClient, console, null, decompiler);
        stubFullPipeline();
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
            .thenAnswer(invocation -> {
                APIClient.StreamCallback cb = invocation.getArgument(1);
                cb.onPartialResponse("{\"function");
                cb.onPartialResponse("_name\":\"renamedFunc\"}");
                cb.onComplete("{\"function_name\":\"renamedFunc\"}");
                return "{\"function_name\":\"renamedFunc\"}";
            });

        fr.rewriteFunction(function, program, monitor);

        verify(console, times(1)).printStreamHeader();
        verify(console).appendStreamingText("{\"function");
        verify(console).appendStreamingText("_name\":\"renamedFunc\"}");
        verify(console).printStreamClose();
        verify(console).printAnalysisStats(
            eq("model analysis"), anyLong(), anyInt(),
            eq("{\"function_name\":\"renamedFunc\"}".length()), any());
    }

    @Test
    void console_receivesThinkingText_andStreamErrorOnError() throws Exception {
        Console console = mock(Console.class);
        FunctionRewrite fr = new FunctionRewrite(apiClient, console, null, decompiler);
        stubFullPipeline();
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
            .thenAnswer(invocation -> {
                APIClient.StreamCallback cb = invocation.getArgument(1);
                cb.onThinkingResponse("let me reason...");
                cb.onError(new RuntimeException("boom"));
                return "{\"variable_renames\":{}}";
            });

        fr.rewriteFunction(function, program, monitor);

        verify(console, times(1)).printStreamHeader();
        verify(console).appendThinkingText("let me reason...");
        verify(console).printStreamError("model analysis", "boom");
    }

    @Test
    void console_thinkingBelowThreshold_isDisabledAndAnnotated() throws Exception {
        ghidragpt.config.ConfigurationManager cm = new ghidragpt.config.ConfigurationManager(tempDir);
        cm.setEnableThinking(true);
        cm.setThinkingThresholdKb(1024);
        Console console = mock(Console.class);
        FunctionRewrite fr = new FunctionRewrite(apiClient, console, cm, decompiler);
        stubFullPipeline();
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
            .thenReturn("{\"variable_renames\":{}}");

        fr.rewriteFunction(function, program, monitor);

        verify(apiClient).setEnableThinking(false);
        verify(console).appendInfo(org.mockito.ArgumentMatchers.argThat(
            msg -> msg != null && msg.startsWith("Thinking disabled: prompt ")
                   && msg.contains("< threshold 1024KB")));
        org.mockito.ArgumentCaptor<String[][]> optsCaptor =
            org.mockito.ArgumentCaptor.forClass(String[][].class);
        verify(console).appendOptions(optsCaptor.capture());
        assertTrue(Arrays.stream(optsCaptor.getValue())
            .anyMatch(o -> o[0].equals("think") && o[1].equals("false")));
    }

    /**
     * Gap #2: generateAddressAnnotatedCode + collectTokens — drive the real pipeline
     * with a non-null Clang token tree so the address-annotation logic executes
     * (existing tests stub getCCodeMarkup() -> null, skipping it entirely).
     * ClangToken/ClangBreak/ClangTokenGroup are concrete non-final classes → mockable
     * without any Ghidra execution.
     */
    @Test
    void pipeline_producesaddressAnnotatedCode_inPrompt() throws Exception {
        Address addrA = mock(Address.class);
        when(addrA.toString()).thenReturn("0x00401000");
        Address addrB = mock(Address.class);
        when(addrB.toString()).thenReturn("0x00401008");

        ClangToken tA = mock(ClangToken.class);
        when(tA.getMinAddress()).thenReturn(addrA);
        when(tA.toString()).thenReturn("int x = 5;");

        ClangBreak br = mock(ClangBreak.class);
        when(br.toString()).thenReturn(""); // instanceof ClangBreak triggers line break

        ClangToken tB = mock(ClangToken.class);
        when(tB.getMinAddress()).thenReturn(addrB);
        when(tB.toString()).thenReturn("return x;");

        ClangTokenGroup root = mock(ClangTokenGroup.class);
        when(root.numChildren()).thenReturn(3);
        when(root.Child(0)).thenReturn((ClangNode) tA);
        when(root.Child(1)).thenReturn((ClangNode) br);
        when(root.Child(2)).thenReturn((ClangNode) tB);

        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction dfn = mock(DecompiledFunction.class);
        when(dfn.getC()).thenReturn("void f() { int x = 5; return x; }");
        when(results.getDecompiledFunction()).thenReturn(dfn);
        when(results.decompileCompleted()).thenReturn(true);
        when(results.getCCodeMarkup()).thenReturn(root);
        when(decompiler.decompileFunction(function, 30, monitor)).thenReturn(results);

        when(apiClient.getProvider()).thenReturn(APIClient.GPTProvider.OPENAI);
        when(apiClient.getModel()).thenReturn("gpt-test");
        when(apiClient.getContextSize()).thenReturn(1 << 20);

        org.mockito.ArgumentCaptor<String> promptCaptor =
            org.mockito.ArgumentCaptor.forClass(String.class);
        when(apiClient.sendRequest(promptCaptor.capture(), any(APIClient.StreamCallback.class)))
            .thenReturn("{\"variable_renames\":{}}");

        frWithNullConsole().rewriteFunction(function, program, monitor);

        String prompt = promptCaptor.getValue();
        assertTrue(prompt.contains("/* 0x00401000 */ int x = 5;"),
            "prompt should contain first annotated line, was:\n" + prompt);
        assertTrue(prompt.contains("/* 0x00401008 */ return x;"),
            "prompt should contain second annotated line, was:\n" + prompt);
    }

    private FunctionRewrite frWithNullConsole() {
        return new FunctionRewrite(apiClient, null, null, decompiler);
    }

    // ===== EnhancementResult.getReport =====

    @Test
    void enhancementResult_reportRendersOutcomesAndErrors() {
        FunctionRewrite.EnhancementResult r = new FunctionRewrite.EnhancementResult();
        r.message = "Function renamed";
        r.functionRenamed = true;
        r.originalFunctionName = "old";
        r.newFunctionName = "new";
        r.functionName = "new";
        r.variableRenames.put("a", "b");
        r.typeUpdates.put("a", "int");
        r.globalRenames.put("g", "h");
        r.globalTypeUpdates.put("g", "float");
        r.errors.add("boom");
        r.suggestionOutcomes.add(new FunctionRewrite.SuggestionOutcome(
            "Variable Rename", "a -> b", true, null));
        r.suggestionOutcomes.add(new FunctionRewrite.SuggestionOutcome(
            "Comment", "note", false, "address not found"));

        String report = r.getReport();
        assertTrue(report.contains("Function Rename:"));
        assertTrue(report.contains("old → new"));
        assertTrue(report.contains("Variable Renames Applied:"));
        assertTrue(report.contains("a → b"));
        assertTrue(report.contains("Errors encountered:"));
        assertTrue(report.contains("- boom"));
        assertTrue(report.contains("[OK] [Variable Rename] a -> b"));
        assertTrue(report.contains("[FAIL] [Comment] note"));
        assertTrue(report.contains("address not found"));
    }
}
