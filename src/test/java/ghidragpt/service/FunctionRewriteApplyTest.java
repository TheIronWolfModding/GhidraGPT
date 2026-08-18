package ghidragpt.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import ghidragpt.config.ConfigurationManager;

/**
 * Phase 6 — FunctionRewrite apply methods.
 *
 * Pipeline-gated tests reach their target through the public {@code rewriteFunction}
 * entry point (the two deferred items live inside that flow). The apply-methods
 * tests invoke the package-private methods directly against mocked Ghidra types.
 */
class FunctionRewriteApplyTest {

    @TempDir
    Path tempDir;

    private Function function;
    private Program program;
    private TaskMonitor monitor;
    private APIClient apiClient;
    private DecompInterface decompiler;
    private ConfigurationManager cm;
    private FunctionRewrite fr;

    @BeforeEach
    void setUp() {
        function = mock(Function.class);
        when(function.getName()).thenReturn("FUN_00401234");
        program = mock(Program.class);
        monitor = mock(TaskMonitor.class);
        apiClient = mock(APIClient.class);
        decompiler = mock(DecompInterface.class);
        cm = new ConfigurationManager(tempDir);
        fr = new FunctionRewrite(apiClient, null, cm, decompiler);
    }

    // ---------- shared helpers ----------

    private DecompileResults mockDecompResult(String cCode, HighFunction highFunction) {
        DecompiledFunction dfunc = mock(DecompiledFunction.class);
        when(dfunc.getC()).thenReturn(cCode);
        DecompileResults dr = mock(DecompileResults.class);
        when(dr.decompileCompleted()).thenReturn(true);
        when(dr.getDecompiledFunction()).thenReturn(dfunc);
        when(dr.getHighFunction()).thenReturn(highFunction);
        when(dr.getCCodeMarkup()).thenReturn(null);
        return dr;
    }

    private HighFunction hfWithSymbols(String... names) {
        HighFunction hf = mock(HighFunction.class);
        LocalSymbolMap lsm = mock(LocalSymbolMap.class);
        List<HighSymbol> syms = new ArrayList<>();
        for (String n : names) {
            HighSymbol s = mock(HighSymbol.class);
            when(s.getName()).thenReturn(n);
            syms.add(s);
        }
        when(lsm.getSymbols()).thenReturn(syms.iterator());
        when(lsm.getNumParams()).thenReturn(0);
        when(hf.getLocalSymbolMap()).thenReturn(lsm);
        return hf;
    }

    /** Drives the whole rewriteFunction path to completion with a no-op decompiler. */
    private void stubPipeline(String code) {
        HighFunction hf = hfWithSymbols();
        when(decompiler.openProgram(program)).thenReturn(true);
        DecompileResults dr = mockDecompResult(code, hf);
        when(decompiler.decompileFunction(eq(function), eq(30), any())).thenReturn(dr);
        when(function.getParameters()).thenReturn(new Parameter[0]);
        when(function.getLocalVariables()).thenReturn(new Variable[0]);
        DataType ret = mock(DataType.class);
        when(ret.getDisplayName()).thenReturn("/void");
        when(function.getReturnType()).thenReturn(ret);
        when(function.getSignatureSource()).thenReturn(SourceType.USER_DEFINED);
        Address entry = mock(Address.class);
        when(function.getEntryPoint()).thenReturn(entry);
        AddressSetView body = mock(AddressSetView.class);
        when(function.getBody()).thenReturn(body);
        // LLM round-trip
        when(apiClient.getProvider()).thenReturn(null);
        when(apiClient.getModel()).thenReturn("dummy");
        when(apiClient.getContextSize()).thenReturn(1 << 20);
        when(apiClient.getLastOllamaStats()).thenReturn(null);
        when(apiClient.getLastThinkingContent()).thenReturn(null);
    }

    private Symbol globalSymbol() {
        Symbol sym = mock(Symbol.class);
        when(sym.isGlobal()).thenReturn(true);
        return sym;
    }

    private SymbolIterator symbolIter(Symbol... syms) {
        final List<Symbol> list = new ArrayList<>(Arrays.asList(syms));
        SymbolIterator base = new SymbolIterator() {
            private int idx = 0;
            @Override public boolean hasNext() { return idx < list.size(); }
            @Override public Symbol next() { return list.get(idx++); }
            @Override public java.util.Iterator<Symbol> iterator() { return this; }
        };
        return base;
    }

    // ===== pipeline gates (through the public rewriteFunction path) =====

    @Test
    void thinking_threshold_promptBelow_setsEnableThinkingFalse() throws Exception {
        cm.setEnableThinking(true);
        cm.setThinkingThresholdKb(1024); // tiny prompt never reaches 1MB threshold
        stubPipeline("void f() {}");
        when(apiClient.sendRequest(anyString(), any())).thenReturn("{\"function_name\":\"renamed_f\"}");

        fr.rewriteFunction(function, program, monitor);

        verify(apiClient).setEnableThinking(false);
    }

    @Test
    void thinking_threshold_promptAbove_setsEnableThinkingTrue() throws Exception {
        cm.setEnableThinking(true);
        cm.setThinkingThresholdKb(0); // 0 disables the threshold → thinking stays active
        stubPipeline("void f() {}");
        when(apiClient.sendRequest(anyString(), any())).thenReturn("{\"function_name\":\"renamed_f\"}");

        fr.rewriteFunction(function, program, monitor);

        verify(apiClient).setEnableThinking(true);
    }

    @Test
    void applyFunctionRename_off_configDisables_renameNotApplied() throws Exception {
        cm.setApplyFunctionRename(false);
        stubPipeline("void f() {}");
        when(apiClient.sendRequest(anyString(), any())).thenReturn("{\"function_name\":\"llm_chosen_name\"}");

        fr.rewriteFunction(function, program, monitor);

        verify(function, never()).setName(anyString(), any(SourceType.class));
    }

    @Test
    void applyFunctionRename_on_configEnables_renameApplied() throws Exception {
        cm.setApplyFunctionRename(true);
        stubPipeline("void f() {}");
        when(apiClient.sendRequest(anyString(), any())).thenReturn("{\"function_name\":\"llm_chosen_name\"}");

        fr.rewriteFunction(function, program, monitor);

        verify(function).setName("llm_chosen_name", SourceType.USER_DEFINED);
    }

    // ===== isDefaultGlobalName =====

    @Test
    void isDefaultGlobalName_rejectsUserNames() {
        assertFalse(fr.isDefaultGlobalName("myVariable"));
        assertFalse(fr.isDefaultGlobalName("DAT_"));
        assertFalse(fr.isDefaultGlobalName(""));
        assertFalse(fr.isDefaultGlobalName(null));
    }

    @Test
    void isDefaultGlobalName_acceptsDefaultPatterns() {
        assertTrue(fr.isDefaultGlobalName("DAT_0054a938"));
        assertTrue(fr.isDefaultGlobalName("FUN_00401234"));
        assertTrue(fr.isDefaultGlobalName("cls_5099d0"));
        assertTrue(fr.isDefaultGlobalName("LAB_00401000"));
        assertTrue(fr.isDefaultGlobalName("PTR_00401000"));
        assertTrue(fr.isDefaultGlobalName("s_abcd"));
        assertTrue(fr.isDefaultGlobalName("meth_0x12345"));
        assertTrue(fr.isDefaultGlobalName("thunk_FUN_00400000"));
    }

    // ===== applyGlobalRename =====

    @Test
    void applyGlobalRename_symbolFound_renamesSuccessfully() throws Exception {
        Symbol sym = globalSymbol();
        SymbolTable st = mock(SymbolTable.class);
        SymbolIterator iter = symbolIter(sym);
        when(st.getSymbols("DAT_0054a938")).thenReturn(iter);
        when(program.getSymbolTable()).thenReturn(st);

        boolean ok = fr.applyGlobalRename(program, "DAT_0054a938", "myNewGlobal");
        assertTrue(ok);
        verify(sym).setName("myNewGlobal", SourceType.USER_DEFINED);
    }

    @Test
    void applyGlobalRename_nonDefaultName_skipped() throws Exception {
        boolean ok = fr.applyGlobalRename(program, "myUserGlobal", "something");
        assertFalse(ok, "non-default name must short-circuit to false");
        verify(program, never()).getSymbolTable();
    }

    @Test
    void applyGlobalRename_datAddressFallback_resolves() throws Exception {
        SymbolTable st = mock(SymbolTable.class);
        when(st.getSymbols("DAT_0054a938")).thenReturn(symbolIter()); // empty → no name hit

        Address addr = mock(Address.class);
        AddressFactory af = mock(AddressFactory.class);
        when(af.getAddress("0054a938")).thenReturn(addr);
        when(program.getAddressFactory()).thenReturn(af);

        Symbol byAddr = globalSymbol();
        when(st.getPrimarySymbol(addr)).thenReturn(byAddr);
        when(program.getSymbolTable()).thenReturn(st);

        boolean ok = fr.applyGlobalRename(program, "DAT_0054a938", "myNewGlobal");
        assertTrue(ok, "address fallback should find a primary symbol and rename it");
        verify(byAddr).setName("myNewGlobal", SourceType.USER_DEFINED);
    }

    @Test
    void applyGlobalRename_unknown_returnsFalse() throws Exception {
        SymbolTable st = mock(SymbolTable.class);
        when(st.getSymbols("DAT_0054a938")).thenReturn(symbolIter());
        when(st.getPrimarySymbol(any())).thenReturn(null);
        when(program.getSymbolTable()).thenReturn(st);
        AddressFactory af = mock(AddressFactory.class);
        when(af.getAddress(anyString())).thenReturn(null);
        when(program.getAddressFactory()).thenReturn(af);

        boolean ok = fr.applyGlobalRename(program, "DAT_0054a938", "myNewGlobal");
        assertFalse(ok, "no symbol and no address fallback should return false");
    }

    // ===== applyComment =====

    @Test
    void applyComment_absoluteAddressInsideBody_applies() throws Exception {
        Address bodyAddr = mock(Address.class);
        AddressFactory af = mock(AddressFactory.class);
        when(af.getAddress("0x401000")).thenReturn(bodyAddr);
        when(program.getAddressFactory()).thenReturn(af);
        when(function.getEntryPoint()).thenReturn(mock(Address.class));
        AddressSetView body = mock(AddressSetView.class);
        when(body.contains(bodyAddr)).thenReturn(true);
        when(function.getBody()).thenReturn(body);
        Listing listing = mock(Listing.class);
        when(program.getListing()).thenReturn(listing);

        boolean ok = fr.applyComment(function, program, "0x401000", "absolute comment");
        assertTrue(ok);
        verify(listing).setComment(bodyAddr, CodeUnit.EOL_COMMENT, "absolute comment");
    }

    @Test
    void applyComment_baseAdjustFallback_applies() throws Exception {
        Address bodyAddr = mock(Address.class);
        // absolute not found → try rawAddr - 0x400000 in the default space
        AddressFactory af = mock(AddressFactory.class);
        AddressSpace as = mock(AddressSpace.class);
        when(af.getAddress("0x1400010a0")).thenReturn(null);
        // adjusted = 0x1400010a0 - 0x400000 = 0x13fc010a0
        when(as.getAddress(0x13fc010a0L)).thenReturn(bodyAddr);
        when(af.getDefaultAddressSpace()).thenReturn(as);
        when(program.getAddressFactory()).thenReturn(af);
        when(function.getEntryPoint()).thenReturn(mock(Address.class));
        AddressSetView body = mock(AddressSetView.class);
        when(body.contains(bodyAddr)).thenReturn(true);
        when(function.getBody()).thenReturn(body);
        Listing listing = mock(Listing.class);
        when(program.getListing()).thenReturn(listing);

        boolean ok = fr.applyComment(function, program, "0x1400010a0", "rehomed comment");
        assertTrue(ok);
        verify(listing).setComment(bodyAddr, CodeUnit.EOL_COMMENT, "rehomed comment");
    }

    @Test
    void applyComment_entryOffsetFallback_applies() throws Exception {
        Address entry = mock(Address.class);
        Address offsetAddr = mock(Address.class);
        when(entry.add(0x10L)).thenReturn(offsetAddr);
        when(function.getEntryPoint()).thenReturn(entry);

        AddressFactory af = mock(AddressFactory.class);
        AddressSpace as = mock(AddressSpace.class);
        when(af.getAddress(anyString())).thenReturn(null);
        when(as.getAddress(anyLong())).thenReturn(null);
        when(af.getDefaultAddressSpace()).thenReturn(as);
        when(program.getAddressFactory()).thenReturn(af);

        AddressSetView body = mock(AddressSetView.class);
        when(body.contains(offsetAddr)).thenReturn(true);
        when(function.getBody()).thenReturn(body);
        Listing listing = mock(Listing.class);
        when(program.getListing()).thenReturn(listing);

        boolean ok = fr.applyComment(function, program, "0x10", "offset comment");
        assertTrue(ok);
        verify(listing).setComment(offsetAddr, CodeUnit.EOL_COMMENT, "offset comment");
    }

    @Test
    void applyComment_unresolvable_returnsFalse() throws Exception {
        when(function.getEntryPoint()).thenReturn(mock(Address.class));
        AddressFactory af = mock(AddressFactory.class);
        AddressSpace as = mock(AddressSpace.class);
        when(af.getAddress(anyString())).thenReturn(null);
        when(as.getAddress(anyLong())).thenReturn(null);
        when(af.getDefaultAddressSpace()).thenReturn(as);
        when(program.getAddressFactory()).thenReturn(af);
        AddressSetView body = mock(AddressSetView.class);
        when(body.contains(any(Address.class))).thenReturn(false);
        when(function.getBody()).thenReturn(body);
        Listing listing = mock(Listing.class);
        when(program.getListing()).thenReturn(listing);

        boolean ok = fr.applyComment(function, program, "0x999999", "orphan comment");
        assertFalse(ok);
        verify(listing, never()).setComment(any(Address.class), any(), anyString());
    }

    // ===== applyGlobalTypeChange =====

    private Data dataOfType(String name, int len) {
        DataType dt = (DataType) java.lang.reflect.Proxy.newProxyInstance(
            DataType.class.getClassLoader(), new Class<?>[] { DataType.class },
            (proxy, method, args) -> {
                switch (method.getName()) {
                    case "getName": return name;
                    case "getLength": return len;
                    case "getDisplayName": return "/" + name;
                    case "hashCode": return System.identityHashCode(proxy);
                    case "equals": return proxy == args[0];
                    case "toString": return name;
                    default: return null;
                }
            });
        return (Data) java.lang.reflect.Proxy.newProxyInstance(
            Data.class.getClassLoader(), new Class<?>[] { Data.class },
            (proxy, method, args) -> {
                if ("getDataType".equals(method.getName())) return dt;
                if ("hashCode".equals(method.getName())) return System.identityHashCode(proxy);
                if ("equals".equals(method.getName())) return proxy == args[0];
                return null;
            });
    }

    @Test
    void applyGlobalTypeChange_undefinedType_createsNewData() throws Exception {
        Symbol sym = globalSymbol();
        when(sym.getAddress()).thenReturn(mock(Address.class));
        SymbolTable st = mock(SymbolTable.class);
        when(st.getSymbols("DAT_0054a938")).thenReturn(symbolIter(sym));
        when(program.getSymbolTable()).thenReturn(st);

        Listing listing = mock(Listing.class);
        when(program.getListing()).thenReturn(listing);
        when(listing.getDataAt(any(Address.class))).thenReturn(dataOfType("undefined4", 4));

        DataType newType = mock(DataType.class);
        when(newType.getLength()).thenReturn(4);
        ghidra.program.model.data.ProgramBasedDataTypeManager dtm =
            mock(ghidra.program.model.data.ProgramBasedDataTypeManager.class);
        when(program.getDataTypeManager()).thenReturn(dtm);
        when(dtm.getAllDataTypes()).thenReturn(java.util.Collections.<DataType>emptyList().iterator());
        when(dtm.getDataType("/int")).thenReturn(newType);

        String reason = fr.applyGlobalTypeChange(program, "DAT_0054a938", "int");
        assertNull(reason, "undefined→int should apply cleanly: " + reason);
        verify(listing).createData(any(Address.class), same(newType));
    }

    @Test
    void applyGlobalTypeChange_alreadyTyped_returnsSkipReason() throws Exception {
        Symbol sym = globalSymbol();
        when(sym.getAddress()).thenReturn(mock(Address.class));
        SymbolTable st = mock(SymbolTable.class);
        when(st.getSymbols("DAT_0054a938")).thenReturn(symbolIter(sym));
        when(program.getSymbolTable()).thenReturn(st);

        Listing listing = mock(Listing.class);
        when(program.getListing()).thenReturn(listing);
        when(listing.getDataAt(any(Address.class))).thenReturn(dataOfType("int", 4));

        String reason = fr.applyGlobalTypeChange(program, "DAT_0054a938", "float");
        assertTrue(reason != null && reason.startsWith("Already typed as"),
            "expected a skip reason; got: " + reason);
    }

    @Test
    void applyGlobalTypeChange_symbolNotAddressable_notFound() throws Exception {
        SymbolTable st = mock(SymbolTable.class);
        when(st.getSymbols("DAT_0054a938")).thenReturn(symbolIter());
        when(program.getSymbolTable()).thenReturn(st);
        AddressFactory af = mock(AddressFactory.class);
        when(af.getAddress(anyString())).thenReturn(null);
        when(program.getAddressFactory()).thenReturn(af);

        String reason = fr.applyGlobalTypeChange(program, "DAT_0054a938", "int");
        assertEquals("Global symbol not found", reason);
    }

    @Test
    void applyGlobalTypeChange_unresolvableType_returnsReason() throws Exception {
        Symbol sym = globalSymbol();
        when(sym.getAddress()).thenReturn(mock(Address.class));
        SymbolTable st = mock(SymbolTable.class);
        when(st.getSymbols("DAT_0054a938")).thenReturn(symbolIter(sym));
        when(program.getSymbolTable()).thenReturn(st);

        Listing listing = mock(Listing.class);
        when(program.getListing()).thenReturn(listing);
        when(listing.getDataAt(any(Address.class))).thenReturn(dataOfType("undefined4", 4));

        ghidra.program.model.data.ProgramBasedDataTypeManager dtm =
            mock(ghidra.program.model.data.ProgramBasedDataTypeManager.class);
        when(program.getDataTypeManager()).thenReturn(dtm);
        when(dtm.getAllDataTypes()).thenReturn(java.util.Collections.<DataType>emptyList().iterator());
        when(dtm.getDataType(anyString())).thenReturn(null); // nothing resolves → null

        String reason = fr.applyGlobalTypeChange(program, "DAT_0054a938", "myCustomUnknownType");
        assertTrue(reason != null && reason.startsWith("Could not resolve type"),
            "expected a 'Could not resolve type' reason; got: " + reason);
    }

    // ===== checkFullCommit (static) =====

    @Test
    void checkFullCommit_nonParameter_symbol_returnsFalse() {
        HighSymbol sym = mock(HighSymbol.class);
        when(sym.isParameter()).thenReturn(false);
        HighFunction hf = mock(HighFunction.class);
        boolean required = FunctionRewrite.checkFullCommit(sym, hf);
        assertFalse(required);
        verify(hf, never()).getFunction();
    }

    @Test
    void checkFullCommit_paramCountMismatch_returnsTrue() {
        HighSymbol paramSym = mock(HighSymbol.class);
        when(paramSym.isParameter()).thenReturn(true);

        HighFunction hf = mock(HighFunction.class);
        Function f = mock(Function.class);
        when(hf.getFunction()).thenReturn(f);
        LocalSymbolMap lsm = mock(LocalSymbolMap.class);
        when(lsm.getNumParams()).thenReturn(3);
        when(hf.getLocalSymbolMap()).thenReturn(lsm);
        when(f.getParameters()).thenReturn(new Parameter[] { mock(Parameter.class) });

        boolean required = FunctionRewrite.checkFullCommit(paramSym, hf);
        assertTrue(required, "param count mismatch (high=3, listing=1) must trigger full commit");
    }

    // ===== applyVariableRenameBatch =====

    @Test
    void applyVariableRenameBatch_knownLocal_renamed() throws Exception {
        HighFunction hf = hfWithSymbols("local_18");
        DecompileResults dr = mockDecompResult("void f(){}", hf);
        when(decompiler.decompileFunction(eq(function), eq(30), any())).thenReturn(dr);
        when(function.getSignatureSource()).thenReturn(SourceType.USER_DEFINED);

        Map<String, String> renames = new LinkedHashMap<>();
        renames.put("local_18", "myLocal");

        try (MockedStatic<HighFunctionDBUtil> hs = mockStatic(HighFunctionDBUtil.class)) {

            List<FunctionRewrite.RenameResult> results =
                fr.applyVariableRenameBatch(function, program, renames, monitor);

            assertEquals(1, results.size());
            FunctionRewrite.RenameResult r = results.get(0);
            assertTrue(r.applied, "known local variable should be renamed: " + r);
            assertEquals("local_18", r.oldName);
            assertEquals("myLocal", r.newName);
            hs.verify(() -> HighFunctionDBUtil.updateDBVariable(
                any(HighSymbol.class), eq("myLocal"), any(), eq(SourceType.USER_DEFINED)));
        }
    }

    @Test
    void applyVariableRenameBatch_hallucinatedName_dropped() throws Exception {
        HighFunction hf = hfWithSymbols("local_18"); // no 'ghostVar'
        DecompileResults dr = mockDecompResult("void f(){}", hf);
        when(decompiler.decompileFunction(eq(function), eq(30), any())).thenReturn(dr);
        when(function.getSignatureSource()).thenReturn(SourceType.USER_DEFINED);

        Map<String, String> renames = new LinkedHashMap<>();
        renames.put("ghostVar", "realVar");

        try (MockedStatic<HighFunctionDBUtil> hs = mockStatic(HighFunctionDBUtil.class)) {
            List<FunctionRewrite.RenameResult> results =
                fr.applyVariableRenameBatch(function, program, renames, monitor);
            assertTrue(results.isEmpty(),
                "hallucinated names are silently dropped in pre-filter: " + results);
            hs.verifyNoInteractions();
        }
    }

    @Test
    void applyVariableRenameBatch_codeLabel_dropped() throws Exception {
        HighFunction hf = hfWithSymbols("LAB_00401200", "local_18");
        DecompileResults dr = mockDecompResult("void f(){}", hf);
        when(decompiler.decompileFunction(eq(function), eq(30), any())).thenReturn(dr);
        when(function.getSignatureSource()).thenReturn(SourceType.USER_DEFINED);

        Map<String, String> renames = new LinkedHashMap<>();
        renames.put("LAB_00401200", "myLabel");

        try (MockedStatic<HighFunctionDBUtil> hs = mockStatic(HighFunctionDBUtil.class)) {
            List<FunctionRewrite.RenameResult> results =
                fr.applyVariableRenameBatch(function, program, renames, monitor);
            assertTrue(results.isEmpty(),
                "code labels (LAB_*) must be pre-filtered out: " + results);
        }
    }

    @Test
    void applyVariableRenameBatch_duplicateTarget_onlyFirstApplied() throws Exception {
        HighFunction hf = hfWithSymbols("local_18", "local_1a", "local_20");
        DecompileResults dr = mockDecompResult("void f(){}", hf);
        when(decompiler.decompileFunction(eq(function), eq(30), any())).thenReturn(dr);
        when(function.getSignatureSource()).thenReturn(SourceType.USER_DEFINED);

        Map<String, String> renames = new LinkedHashMap<>();
        renames.put("local_18", "MyVar");
        renames.put("local_1a", "MyVar");
        renames.put("local_20", "MyVar");

        try (MockedStatic<HighFunctionDBUtil> hs = mockStatic(HighFunctionDBUtil.class)) {
            List<FunctionRewrite.RenameResult> results =
                fr.applyVariableRenameBatch(function, program, renames, monitor);

            assertEquals(3, results.size(), "each rename produces one result entry: " + results);
            FunctionRewrite.RenameResult applied = results.stream()
                .filter(r -> "local_18".equals(r.oldName)).findFirst().orElseThrow();
            FunctionRewrite.RenameResult dup1 = results.stream()
                .filter(r -> "local_1a".equals(r.oldName)).findFirst().orElseThrow();
            FunctionRewrite.RenameResult dup2 = results.stream()
                .filter(r -> "local_20".equals(r.oldName)).findFirst().orElseThrow();
            assertTrue(applied.applied, "first-seen rename should apply: " + applied);
            assertFalse(dup1.applied, "second duplicate should be skipped: " + dup1);
            assertFalse(dup2.applied, "third duplicate should be skipped: " + dup2);
        }
    }
}
