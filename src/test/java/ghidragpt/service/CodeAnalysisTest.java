package ghidragpt.service;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import ghidragpt.ui.Console;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.*;

/**
 * Phase 7 — CodeAnalysis.
 *
 * Uses the package-private 4-arg constructor so we can inject mocked APIClient,
 * Console, DecompInterface, and FunctionRewrite. No real DecompInterface is ever
 * constructed, no Ghidra runtime needed.
 */
class CodeAnalysisTest {

    private Program program;
    private Function function;
    private TaskMonitor monitor;
    private DecompInterface decompiler;
    private APIClient apiClient;
    private Console console;
    private FunctionRewrite functionRewriteService;

    @BeforeEach
    void setUp() {
        program = mock(Program.class);
        function = mock(Function.class);
        monitor = mock(TaskMonitor.class);
        decompiler = mock(DecompInterface.class);
        apiClient = mock(APIClient.class);
        console = mock(Console.class);
        functionRewriteService = mock(FunctionRewrite.class);

        when(function.getName()).thenReturn("FUN_00400000");
        when(function.getEntryPoint()).thenReturn(mock(Address.class));
        when(monitor.isCancelled()).thenReturn(false);
    }

    /**
     * Standard stubs for "decompile succeeds" path — used by detectVulnerabilities
     * and explainFunction happy-path tests.
     */
    private void stubDecompileSuccess(String code) throws Exception {
        DecompileResults results = mock(DecompileResults.class);
        DecompiledFunction df = mock(DecompiledFunction.class);
        when(results.decompileCompleted()).thenReturn(true);
        when(results.getDecompiledFunction()).thenReturn(df);
        when(df.getC()).thenReturn(code);
        when(decompiler.decompileFunction(function, 10, monitor)).thenReturn(results);

        SymbolTable st = mock(SymbolTable.class);
        Symbol sym = mock(Symbol.class);
        when(sym.getName()).thenReturn("entry");
        when(st.getSymbols(function.getEntryPoint())).thenReturn(new Symbol[]{sym});
        when(program.getSymbolTable()).thenReturn(st);
    }

    /**
     * Standard stubs for "service is configured" (OPENAI with API key).
     */
    private void stubConfigured() {
        when(apiClient.getProvider()).thenReturn(APIClient.GPTProvider.OPENAI);
        when(apiClient.getModel()).thenReturn("gpt-4");
        when(apiClient.getApiKey()).thenReturn("sk-test-123");
    }

    // ===== rewriteFunction delegation =====

    @Test
    void rewriteFunction_unconfiguredReturnsConfigError() {
        when(apiClient.getProvider()).thenReturn(APIClient.GPTProvider.OPENAI);
        when(apiClient.getModel()).thenReturn("gpt-4");
        when(apiClient.getApiKey()).thenReturn(null);

        String report = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .rewriteFunction(function, program, monitor);

        assertTrue(report.contains("Configuration Error:"), "expected config error, got: " + report);
        assertTrue(report.contains("Provider: OPENAI"));
        assertTrue(report.contains("API Key: not configured"));
        verify(functionRewriteService, never()).rewriteFunction(any(), any(), any());
    }

    @Test
    void rewriteFunction_ollamaConfiguredEvenWithoutKey() {
        when(apiClient.getProvider()).thenReturn(APIClient.GPTProvider.OLLAMA);
        when(apiClient.getModel()).thenReturn("llama3");
        when(apiClient.getApiKey()).thenReturn(null);

        FunctionRewrite.EnhancementResult er = new FunctionRewrite.EnhancementResult();
        er.message = "OLLAMA-REWRITE-OK";
        er.functionRenamed = true;
        er.originalFunctionName = "FUN_00400000";
        er.newFunctionName = "computeHash";
        when(functionRewriteService.rewriteFunction(function, program, monitor)).thenReturn(er);

        String report = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .rewriteFunction(function, program, monitor);

        assertTrue(report.contains("OLLAMA-REWRITE-OK"));
        assertTrue(report.contains("FUN_00400000"));
        assertTrue(report.contains("computeHash"));
        verify(functionRewriteService).rewriteFunction(function, program, monitor);
    }

    @Test
    void rewriteFunction_delegateThrows_returnsErrorStringNotException() {
        stubConfigured();
        when(functionRewriteService.rewriteFunction(function, program, monitor))
                .thenThrow(new RuntimeException("boom"));

        String report = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .rewriteFunction(function, program, monitor);

        assertTrue(report.startsWith("Error during function rewrite:"));
        assertTrue(report.contains("boom"));
    }

    // ===== detectVulnerabilities =====

    @Test
    void detectVulnerabilities_decompileFails_returnsFailure() throws Exception {
        DecompileResults results = mock(DecompileResults.class);
        when(results.decompileCompleted()).thenReturn(false);
        when(decompiler.decompileFunction(function, 10, monitor)).thenReturn(results);
        stubConfigured();

        String out = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .detectVulnerabilities(function, program, monitor);

        assertEquals("Failed to decompile function: FUN_00400000", out);
        verify(apiClient, never()).sendRequest(anyString(), any());
    }

    @Test
    void detectVulnerabilities_nullDecompileResults_returnsFailure() throws Exception {
        when(decompiler.decompileFunction(function, 10, monitor)).thenReturn(null);
        stubConfigured();

        String out = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .detectVulnerabilities(function, program, monitor);

        assertEquals("Failed to decompile function: FUN_00400000", out);
    }

    @Test
    void detectVulnerabilities_unconfigured_returnsConfigError() throws Exception {
        stubDecompileSuccess("void x(){}");
        when(apiClient.getProvider()).thenReturn(APIClient.GPTProvider.OPENAI);
        when(apiClient.getModel()).thenReturn("gpt-4");
        when(apiClient.getApiKey()).thenReturn("");

        String out = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .detectVulnerabilities(function, program, monitor);

        assertTrue(out.contains("Configuration Error:"));
        assertTrue(out.contains("API Key: not configured"));
        verify(apiClient, never()).sendRequest(anyString(), any());
    }

    @Test
    void detectVulnerabilities_configuredStreamsResponse() throws Exception {
        stubDecompileSuccess("void FUN_00400000() { /* body */ }");
        stubConfigured();
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
                .thenAnswer(inv -> {
                    APIClient.StreamCallback cb = inv.getArgument(1);
                    cb.onPartialResponse("Found ");
                    cb.onPartialResponse("1 vuln");
                    cb.onComplete("Found 1 vuln");
                    return "Found 1 vuln";
                });

        CodeAnalysis ca = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService);
        String out = ca.detectVulnerabilities(function, program, monitor);

        assertEquals("Found 1 vuln", out);
        // Console interactions (best-effort: the method should call all three lifecycle phases)
        verify(console).printAnalysisHeader(anyString(), eq("FUN_00400000"), anyString(), anyString(), anyInt());
        verify(console, atLeastOnce()).printStreamHeader();
        verify(console, atLeastOnce()).appendStreamingText(anyString());
        verify(console, atLeastOnce()).printStreamComplete(eq("vulnerability detection"), anyLong(), anyInt());
    }

    @Test
    void detectVulnerabilities_apiError_returnsApiErrorString() throws Exception {
        stubDecompileSuccess("int y(){}");
        stubConfigured();
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
                .thenThrow(new java.io.IOException("net down"));

        String out = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .detectVulnerabilities(function, program, monitor);

        assertEquals("API Error: net down", out);
    }

    // ===== explainFunction =====

    @Test
    void explainFunction_decompileFails_returnsFailure() throws Exception {
        DecompileResults results = mock(DecompileResults.class);
        when(results.decompileCompleted()).thenReturn(false);
        when(decompiler.decompileFunction(function, 10, monitor)).thenReturn(results);
        stubConfigured();

        String out = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .explainFunction(function, program, monitor);

        assertEquals("Failed to decompile function: FUN_00400000", out);
    }

    @Test
    void explainFunction_unconfigured_returnsConfigError() throws Exception {
        stubDecompileSuccess("void z(){}");
        when(apiClient.getProvider()).thenReturn(APIClient.GPTProvider.OPENAI);
        when(apiClient.getModel()).thenReturn("gpt-4");
        when(apiClient.getApiKey()).thenReturn(null);

        String out = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .explainFunction(function, program, monitor);

        assertTrue(out.contains("Configuration Error:"));
        verify(apiClient, never()).sendRequest(anyString(), any());
    }

    @Test
    void explainFunction_configuredStreamsResponse() throws Exception {
        stubDecompileSuccess("void FUN_00400000() { /* expl target */ }");
        stubConfigured();
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
                .thenAnswer(inv -> {
                    APIClient.StreamCallback cb = inv.getArgument(1);
                    cb.onPartialResponse("This ");
                    cb.onPartialResponse("does X");
                    cb.onComplete("This does X");
                    return "This does X";
                });

        String out = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .explainFunction(function, program, monitor);

        assertEquals("This does X", out);
        verify(console).printAnalysisHeader(anyString(), eq("FUN_00400000"), anyString(), anyString(), anyInt());
        verify(console, atLeastOnce()).printStreamHeader();
        verify(console, atLeastOnce()).appendStreamingText(anyString());
        verify(console, atLeastOnce()).printStreamComplete(eq("function explanation"), anyLong(), anyInt());
    }

    @Test
    void explainFunction_apiError_returnsApiErrorString() throws Exception {
        stubDecompileSuccess("void w(){}");
        stubConfigured();
        when(apiClient.sendRequest(anyString(), any(APIClient.StreamCallback.class)))
                .thenThrow(new java.io.IOException("timeout"));

        String out = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService)
                .explainFunction(function, program, monitor);

        assertEquals("API Error: timeout", out);
    }

    // ===== prompt builders =====

    @Test
    void buildVulnerabilityPrompt_containsAllRequiredSections() {
        CodeAnalysis ca = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService);
        String p = ca.buildVulnerabilityPrompt("int f(){}", "Symbol: entry\n");

        assertTrue(p.startsWith("SECURITY ANALYSIS - Find REAL, EXPLOITABLE vulnerabilities only:"));
        assertTrue(p.contains("Context: Symbol: entry"));
        assertTrue(p.contains("Code:\nint f(){}"));
        assertTrue(p.contains("STRICT CRITERIA - Only report vulnerabilities that are:"));
        assertTrue(p.contains("DEFINITELY exploitable"));
        assertTrue(p.contains("No exploitable vulnerabilities detected."));
    }

    @Test
    void buildExplanationPrompt_containsFunctionNameAndCode() {
        CodeAnalysis ca = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService);
        String p = ca.buildExplanationPrompt("void g(){ return; }", "computeHash");

        assertTrue(p.startsWith("CONCISE FUNCTION ANALYSIS for: computeHash"));
        assertTrue(p.contains("Code:\nvoid g(){ return; }"));
        assertTrue(p.contains("[•] Purpose"));
        assertTrue(p.contains("[»] How it works"));
        assertTrue(p.contains("Keep it under 150 words total"));
    }

    // ===== lifecycle =====

    @Test
    void initializeDecompiler_callsSetOptionsAndOpenProgram() {
        CodeAnalysis ca = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService);
        ca.initializeDecompiler(program);
        verify(decompiler).setOptions(any());
        verify(decompiler).openProgram(program);
    }

    @Test
    void dispose_delegatesToBoth() {
        CodeAnalysis ca = new CodeAnalysis(apiClient, console, decompiler, functionRewriteService);
        ca.dispose();
        verify(decompiler).dispose();
        verify(functionRewriteService).dispose();
    }
}
