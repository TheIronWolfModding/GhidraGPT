package ghidragpt.service;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidragpt.config.ConfigurationManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Phase 5 — FunctionRewrite prompt generation + resolveDataType.
 *
 * Uses the package-private 4-arg FunctionRewrite constructor so we can inject
 * a mocked DecompInterface without ever constructing the real thing, and a temp-dir
 * ConfigurationManager for per-instance toggles (custom instructions, re-rename flags).
 */
class FunctionRewritePromptGenTest {

    @TempDir
    Path tempDir;

    private Function function;
    private FunctionRewrite fr;
    private ConfigurationManager cm;

    @BeforeEach
    void setUp() {
        function = mock(Function.class);
        when(function.getName()).thenReturn("FUN_00401234");
        cm = new ConfigurationManager(tempDir);
        fr = new FunctionRewrite(mock(APIClient.class), null, cm, mock(DecompInterface.class));
    }

    // ===== generateComprehensiveRewritePrompt =====

    private VariableAnalysis va(String name, String typeDisplay, boolean param, boolean needsType) {
        DataType dt = mock(DataType.class);
        when(dt.getDisplayName()).thenReturn(typeDisplay);
        VariableAnalysis v = new VariableAnalysis(name, dt, param);
        // needsTypeAnalysis depends on display-name string; use a type that makes it truthy where needed
        return v;
    }

    private FunctionAnalysis fa(String fnName, VariableAnalysis... vars) {
        FunctionAnalysis an = mock(FunctionAnalysis.class);
        when(an.getFunctionName()).thenReturn(fnName);
        List<VariableAnalysis> list = Arrays.asList(vars);
        when(an.getVariables()).thenReturn(list);
        when(an.getIssues()).thenReturn(java.util.List.of());
        when(an.getComplexity()).thenReturn(FunctionAnalysis.FunctionComplexity.SIMPLE);
        when(an.hasDecompilerOutput()).thenReturn(true);
        return an;
    }

    @Test
    void customInstructions_appearAtTop_whenConfigured() {
        cm.setCustomInstructions("  prefer camelCase  ");
        String p = fr.generateComprehensiveRewritePrompt(function, "void f(){ }",
            fa("FUN_00401234"), null);
        assertTrue(p.startsWith("prefer camelCase"),
            "prompt should begin with the trimmed custom instructions; got: " + p.substring(0, Math.min(80, p.length())));
    }

    @Test
    void customInstructions_absentWhenEmptyOrBlank() {
        cm.setCustomInstructions("   ");
        String p = fr.generateComprehensiveRewritePrompt(function, "void f(){ }",
            fa("FUN_00401234"), null);
        assertFalse(p.startsWith("   "), "blank instructions must not be injected");
        assertTrue(p.startsWith("Analyze this decompiled function"));
    }

    @Test
    void functionNameAndDecompiledCode_present() {
        String p = fr.generateComprehensiveRewritePrompt(function, "void FUN_00401234(){ return 1; }",
            fa("FUN_00401234"), null);
        assertTrue(p.contains("Current function: FUN_00401234"));
        assertTrue(p.contains("Decompiled code:\nvoid FUN_00401234(){ return 1; }"));
    }

    @Test
    void parameters_sectionListsParameters() {
        VariableAnalysis p1 = va("param_1", "int", true, false);
        VariableAnalysis p2 = va("param_2", "PVOID", true, false);
        String out = fr.generateComprehensiveRewritePrompt(function, "void f(){}",
            fa("FUN_00401234", p1, p2), null);
        assertTrue(out.contains("Parameters:"));
        assertTrue(out.contains("- param_1 (int)"));
        assertTrue(out.contains("- param_2 (PVOID)"));
    }

    @Test
    void seFrameVariables_skipped() {
        VariableAnalysis seh = va("unaff_FS_OFFSET", "undefined8", false, false);
        VariableAnalysis seStack = va("puStack_10", "undefined1", false, false);
        String out = fr.generateComprehensiveRewritePrompt(function, "void f(){}",
            fa("FUN_00401234", seh, seStack), null);
        assertFalse(out.contains("unaff_FS_OFFSET"), "SEH frame variable must be excluded");
        assertFalse(out.contains("puStack_10"), "undefined1 puStack_ must be excluded");
    }

    @Test
    void decompilerTemporaryIvar_categorised() {
        VariableAnalysis ivar1 = va("iVar1", "undefined4", false, false);
        String out = fr.generateComprehensiveRewritePrompt(function, "void f(){}",
            fa("FUN_00401234", ivar1), null);
        assertTrue(out.contains("Decompiler Temporaries (need meaningful names):"),
            "expected a temporaries section; got: " + excerpt(out));
        assertTrue(out.contains("- iVar1 (undefined4) - decompiler temporary"));
    }

    @Test
    void stackVariable_categorised() {
        VariableAnalysis stackVar = va("local_18", "undefined4", false, false);
        String out = fr.generateComprehensiveRewritePrompt(function, "void f(){}",
            fa("FUN_00401234", stackVar), null);
        assertTrue(out.contains("Stack Variables (may need renaming):"));
        assertTrue(out.contains("- local_18 (undefined4) - stack variable"));
    }

    @Test
    void wellNamedLocal_skippedUnlessRernamEnabled() {
        // 'myLocal' does NOT match isDecompilerGeneratedName — it only appears in the prompt
        // when isRenameNamedLocals() is true
        VariableAnalysis myLocal = va("myLocal", "int", false, false);
        String off = fr.generateComprehensiveRewritePrompt(function, "void f(){}",
            fa("FUN_00401234", myLocal), null);
        assertFalse(off.contains("- myLocal (int)"), "well-named locals must be omitted by default");

        cm.setRenameNamedLocals(true);
        String on = fr.generateComprehensiveRewritePrompt(function, "void f(){}",
            fa("FUN_00401234", myLocal), null);
        assertTrue(on.contains("Local Variables (may need better names):"));
        assertTrue(on.contains("- myLocal (int)"));
    }

    @Test
    void globals_sectionContainsOnlyDefaultNames() {
        FunctionRewrite.GlobalVarInfo d = new FunctionRewrite.GlobalVarInfo();
        d.name = "DAT_0054a938"; d.type = "undefined4"; d.address = mock(Address.class);
        FunctionRewrite.GlobalVarInfo u = new FunctionRewrite.GlobalVarInfo();
        u.name = "myUserGlobal"; u.type = "int"; u.address = mock(Address.class);

        String out = fr.generateComprehensiveRewritePrompt(function, "void f(){}",
            fa("FUN_00401234"), Arrays.asList(d, u));
        assertTrue(out.contains("Referenced Global Variables (DAT_*, cls_*, etc.):"));
        assertTrue(out.contains("- DAT_0054a938"));
        assertFalse(out.contains("- myUserGlobal"), "user-named globals must be skipped");
    }

    @Test
    void memberFieldSection_extractedFromDecompileCode() {
        String code = "cls_0x5099d0 * this = DAT_00000000; " +
                      "this->field_0x10 = iVar1; " +
                      "this->mbr_0x20 = local_18;";
        String out = fr.generateComprehensiveRewritePrompt(function, code, fa("FUN_00401234"), null);
        assertTrue(out.contains("Struct Member Fields (need renaming via variable_renames):"));
        assertTrue(out.contains("field_0x10"));
        assertTrue(out.contains("mbr_0x20"));
    }

    @Test
    void memberFieldM_prefix_onlyWhenRenameNamedFields() {
        // Without isRenameNamedFields, m_* fields are NOT captured (only field*/mbr_*)
        // Anchor on the dynamic "- <name>" line format to sidestep the fixed JSON skeleton / Examples
        String code = "obj->m_rotationX = iVar1;";
        cm.setRenameNamedFields(false);
        String off = fr.generateComprehensiveRewritePrompt(function, code, fa("FUN_00401234"), null);
        assertFalse(off.contains("- m_rotationX"),
            "m_* field should NOT appear in the dynamic section when toggle is off");
        cm.setRenameNamedFields(true);
        String on = fr.generateComprehensiveRewritePrompt(function, code, fa("FUN_00401234"), null);
        assertTrue(on.contains("- m_rotationX"),
            "m_* field should appear in the dynamic section when toggle is on");
    }

    @Test
    void functionCalls_sectionExtraction() {
        String code = "void f() { FUN_00412345(); cls_0x4099e0::meth_0x432070(); }";
        String out = fr.generateComprehensiveRewritePrompt(function, code, fa("FUN_00401234"), null);
        assertTrue(out.contains("Function Calls (need descriptive names via function_renames):"));
        assertTrue(out.contains("- FUN_00412345"));
        assertTrue(out.contains("cls_0x4099e0::meth_0x432070"));
    }

    @Test
    void renamedFuncs_includedOnlyWhenEnabled() {
        // Without isRenameNamedFunctions, already-named F_/M_ functions are NOT listed
        String code = "void F_MyFunc(arg) {} M_Calc(x)();";
        cm.setRenameNamedFunctions(false);
        String off = fr.generateComprehensiveRewritePrompt(function, code, fa("FUN_00401234"), null);
        assertFalse(off.contains("- F_MyFunc"));
        assertFalse(off.contains("- M_Calc"));
        cm.setRenameNamedFunctions(true);
        String on = fr.generateComprehensiveRewritePrompt(function, code, fa("FUN_00401234"), null);
        assertTrue(on.contains("- F_MyFunc"));
        assertTrue(on.contains("- M_Calc"));
    }

    @Test
    void classes_section_containsClsAndNamedClasses() {
        String code = "void f() { cls_0x5099d0 * a; C_AIW b; }";
        String out = fr.generateComprehensiveRewritePrompt(function, code, fa("FUN_00401234"), null);
        assertTrue(out.contains("Classes/Structs (suggest descriptive names via class_suggestions):"));
        assertTrue(out.contains("- cls_0x5099d0"));
    }

    @Test
    void namedClasses_filteredWhenRernamClassesOff() {
        // C_AIW is a "named class" — excluded when isRenameNamedClasses() is false.
        // Needs a pointer/star so extractClassReferences' typePattern captures it.
        String code = "void f() { cls_0x5099d0 * a; C_AIW *b; }";
        cm.setRenameNamedClasses(false);
        String off = fr.generateComprehensiveRewritePrompt(function, code, fa("FUN_00401234"), null);
        assertTrue(off.contains("- cls_0x5099d0"), "unnamed cls_ still appears");
        assertFalse(off.contains("- C_AIW"), "named C_ should be filtered out when toggle is off");
        cm.setRenameNamedClasses(true);
        String on = fr.generateComprehensiveRewritePrompt(function, code, fa("FUN_00401234"), null);
        assertTrue(on.contains("- C_AIW"), "named C_ appears when toggle is on");
    }

    @Test
    void jsonSkeleton_examples_andNotes_present() {
        String any = fr.generateComprehensiveRewritePrompt(function, "void f(){}",
            fa("FUN_00401234"), null);
        assertTrue(any.contains("\"function_name\""));
        assertTrue(any.contains("\"variable_renames\""));
        assertTrue(any.contains("\"variable_types\""));
        assertTrue(any.contains("\"function_prototype\""));
        assertTrue(any.contains("\"comments\""));
        assertTrue(any.contains("\"global_renames\""));
        assertTrue(any.contains("\"global_types\""));
        assertTrue(any.contains("\"field_renames\""));
        assertTrue(any.contains("\"function_renames\""));
        assertTrue(any.contains("\"class_suggestions\""));
        assertTrue(any.contains("Examples:"));
        assertTrue(any.contains("Notes:"));
        assertTrue(any.contains("For comments, use ONLY addresses"));
    }

    private static String excerpt(String s) {
        return s.length() <= 400 ? s : s.substring(0, 400) + "…";
    }

    // ===== resolveDataType =====

    private DataType mockDtype(String name) {
        DataType dt = mock(DataType.class);
        when(dt.getName()).thenReturn(name);
        return dt;
    }

    private DataTypeManager dtmReturning(DataType... types) {
        DataTypeManager dtm = mock(DataTypeManager.class);
        List<DataType> list = Arrays.asList(types);
        Iterator<DataType> it = list.iterator();
        when(dtm.getAllDataTypes()).thenReturn(it);
        return dtm;
    }

    @Test
    void resolveDataType_exactMatchReturnsFromManager() {
        DataType intType = mockDtype("int");
        DataTypeManager dtm = mock(DataTypeManager.class);
        List<DataType> all = Arrays.asList(mockDtype("float"), intType);
        when(dtm.getAllDataTypes()).thenReturn(all.iterator());

        DataType got = fr.resolveDataType(dtm, "int");
        assertSame(intType, got, "exact name match from getAllDataTypes must win");
    }

    @Test
    void resolveDataType_caseInsensitiveExactMatch() {
        DataType intType = mockDtype("INT");
        DataTypeManager dtm = mock(DataTypeManager.class);
        when(dtm.getAllDataTypes()).thenReturn(Arrays.asList(intType).iterator());

        DataType got = fr.resolveDataType(dtm, "int");
        assertSame(intType, got, "name match is case-insensitive per the implementation");
    }

    @Test
    void resolveDataType_pPrefix_fallsToPointerOfBase_whenBaseExists() {
        // PINT → base "INT" exists → PointerDataType(INT)
        DataType intType = mockDtype("INT");
        DataTypeManager dtm = mock(DataTypeManager.class);
        when(dtm.getAllDataTypes()).thenReturn(Arrays.asList(intType).iterator());

        DataType got = fr.resolveDataType(dtm, "PINT");
        assertNotNull(got);
        assertTrue(got instanceof PointerDataType,
            "P-prefixed type should resolve to PointerDataType (got " + got.getClass().getSimpleName() + ")");
    }

    @Test
    void resolveDataType_pPrefix_fallsToPointerOfVoid_whenBaseMissing() {
        // PFOO → base "FOO" is not in manager → PointerDataType(/void)
        DataType voidType = mockDtype("void");
        DataTypeManager dtm = mock(DataTypeManager.class);
        when(dtm.getAllDataTypes()).thenReturn(java.util.Collections.<DataType>emptyList().iterator());
        when(dtm.getDataType("/void")).thenReturn(voidType);

        DataType got = fr.resolveDataType(dtm, "PFOO");
        assertTrue(got instanceof PointerDataType,
            "P-unknown falls back to PointerDataType(/void) (got " + (got == null ? "null" : got.getClass().getSimpleName()) + ")");
    }

    @Test
    void resolveDataType_builtins_viaDtGetData() {
        DataTypeManager dtm = mock(DataTypeManager.class);
        when(dtm.getAllDataTypes()).thenReturn(java.util.Collections.<DataType>emptyList().iterator());
        for (String[] tc : new String[][] {
            {"int", "/int"}, {"long", "/int"},
            {"uint", "/uint"}, {"dword", "/uint"}, {"unsigned int", "/uint"},
            {"short", "/short"},
            {"word", "/ushort"}, {"ushort", "/ushort"},
            {"byte", "/char"}, {"char", "/char"},
            {"__int64", "/longlong"}, {"longlong", "/longlong"},
            {"bool", "/bool"}, {"void", "/void"} } ) {
            DataType expected = mockDataTypeNamed(tc[1]);
            when(dtm.getDataType(tc[1])).thenReturn(expected);
            DataType got = fr.resolveDataType(dtm, tc[0]);
            assertSame(expected, got,
                tc[0] + " should map to " + tc[1] + " (got " + (got == null ? "null" : got.getClass().getSimpleName()) + ")");
        }
    }

    private DataType mockDataTypeNamed(String n) {
        DataType d = mock(DataType.class);
        when(d.getName()).thenReturn(n);
        return d;
    }

    @Test
    void resolveDataType_unknownFallsBackToInt() {
        DataTypeManager dtm = mock(DataTypeManager.class);
        when(dtm.getAllDataTypes()).thenReturn(java.util.Collections.<DataType>emptyList().iterator());
        // default branch: try "/UNKNOWN_TYPE" first
        when(dtm.getDataType("/UNKNOWN_TYPE")).thenReturn(null);
        DataType fallback = mockDataTypeNamed("/int");
        when(dtm.getDataType("/int")).thenReturn(fallback);

        DataType got = fr.resolveDataType(dtm, "UNKNOWN_TYPE");
        assertSame(fallback, got, "unknown type should fall back to /int (got " + (got == null ? "null" : got.getName()) + ")");
    }

    @Test
    void resolveDataType_knownDirectTypeFoundBeforeFallback() {
        DataTypeManager dtm = mock(DataTypeManager.class);
        when(dtm.getAllDataTypes()).thenReturn(java.util.Collections.<DataType>emptyList().iterator());
        DataType myType = mockDataTypeNamed("/myType");
        when(dtm.getDataType("/myType")).thenReturn(myType);

        // "myType" is not a known builtin → default branch → tries /myType first
        DataType got = fr.resolveDataType(dtm, "myType");
        assertSame(myType, got);
    }
}
