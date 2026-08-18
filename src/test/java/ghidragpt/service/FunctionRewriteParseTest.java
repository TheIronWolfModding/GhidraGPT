package ghidragpt.service;

import ghidra.app.decompiler.DecompInterface;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for the pure (no-Ghidra-side-effect) parsing and naming logic of
 * {@link FunctionRewrite}. Constructed with a mock DecompInterface so no real
 * decompiler/state is created.
 */
class FunctionRewriteParseTest {

    private FunctionRewrite fr;
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        // mock decompiler, no console (null-checked everywhere), no config (defaults)
        fr = new FunctionRewrite(
                mock(APIClient.class),
                null,
                null,
                mock(DecompInterface.class));
    }

    // ===== parseComprehensiveRewriteResponse =====

    @Test
    void parseValidJson_populatesAllMaps() {
        String json = "{"
            + "\"function_name\":\"computeTotal\","
            + "\"variable_renames\":{\"iVar1\":\"counter\",\"local_10\":\"total\"},"
            + "\"variable_types\":{\"counter\":\"int\"},"
            + "\"function_prototype\":\"int computeTotal(int a)\","
            + "\"comments\":{\"0x1\":\"note\"},"
            + "\"global_renames\":{\"DAT_0054a938\":\"defaultMouseX\"},"
            + "\"global_types\":{\"DAT_0054a938\":\"float\"},"
            + "\"field_renames\":{\"field_0x60\":\"m_speed\"},"
            + "\"function_renames\":{\"FUN_00400000\":\"calcDamage\",\"cls_0x10::meth_0x20\":\"getName\"},"
            + "\"class_suggestions\":{\"cls_0x10\":\"Player\"}"
            + "}";
        FunctionRewrite.ComprehensiveRewriteSpec spec = fr.parseComprehensiveRewriteResponse("prefix " + json + " suffix");
        assertEquals("computeTotal", spec.functionName);
        assertEquals("counter", spec.variableRenames.get("iVar1"));
        assertEquals("total", spec.variableRenames.get("local_10"));
        assertEquals("int", spec.variableTypes.get("counter"));
        assertEquals("int computeTotal(int a)", spec.functionPrototype);
        assertEquals("note", spec.comments.get("0x1"));
        assertEquals("defaultMouseX", spec.globalRenames.get("DAT_0054a938"));
        assertEquals("float", spec.globalTypes.get("DAT_0054a938"));
        // field_renames is merged into variableRenames
        assertEquals("m_speed", spec.variableRenames.get("field_0x60"));
        // :: is replaced with _ in function_renames
        assertEquals("calculateDamage".replace("calculateDamage", "calcDamage"), spec.functionRenames.get("FUN_00400000"));
        assertEquals("getName", spec.functionRenames.get("cls_0x10::meth_0x20"));
        assertEquals("Player", spec.classSuggestions.get("cls_0x10"));
    }

    @Test
    void parseDuplicateKeys_firstWins() {
        String json = "{\"variable_renames\":{\"a\":\"first\",\"a\":\"second\"}}";
        FunctionRewrite.ComprehensiveRewriteSpec spec = fr.parseComprehensiveRewriteResponse(json);
        assertEquals("first", spec.variableRenames.get("a"));
    }

    @Test
    void parseThisPrefixStrippedFromVariableKeys() {
        String json = "{\"variable_renames\":{\"this->field_0x10\":\"m_health\"},\"variable_types\":{\"this->field_0x10\":\"int\"}}";
        FunctionRewrite.ComprehensiveRewriteSpec spec = fr.parseComprehensiveRewriteResponse(json);
        assertTrue(spec.variableRenames.containsKey("field_0x10"));
        assertFalse(spec.variableRenames.containsKey("this->field_0x10"));
        assertTrue(spec.variableTypes.containsKey("field_0x10"));
    }

    @Test
    void parseNormalizesTypeValues() {
        Map<String, String> in = new HashMap<>();
        in.put("INT", "INT");
        fr.normalizeTypeValues(in);
        assertEquals("int", in.get("INT"));
        Map<String, String> in2 = new HashMap<>();
        in2.put("FLOAT", "FLOAT");
        fr.normalizeTypeValues(in2);
        assertEquals("float", in2.get("FLOAT"));
    }

    @Test
    void parseFunctionRenamesColonColonReplaced() {
        String json = "{\"function_renames\":{\"a::b\":\"Foo\"}}";
        FunctionRewrite.ComprehensiveRewriteSpec spec = fr.parseComprehensiveRewriteResponse(json);
        assertEquals("Foo", spec.functionRenames.get("a::b"));
    }

    @Test
    void parseSimpleJson_truncated_keepsParsedPartAndSetsTruncated() {
        // malformed tail: the partial object is kept, truncated flag is set
        FunctionRewrite.ComprehensiveRewriteSpec spec =
            fr.parseSimpleJson("{\"variable_renames\":{\"a\":\"b\"},\"var");
        assertEquals("b", spec.variableRenames.get("a"));
        assertTrue(spec.truncated);
    }

    @Test
    void parseComprehensiveRewriteResponse_noJsonFallsBackGracefully() {
        FunctionRewrite.ComprehensiveRewriteSpec spec = fr.parseComprehensiveRewriteResponse("no json here");
        assertNull(spec.functionName);
    }

    @Test
    void parseNoJson_fallsBackToText() {
        FunctionRewrite.ComprehensiveRewriteSpec spec = fr.parseComprehensiveRewriteResponse(
            "FUNCTION_NAME: doThing\nRENAME: aVar -> bVar\nTYPE_HINT: aVar -> int");
        assertEquals("doThing", spec.functionName);
        assertEquals("bVar", spec.variableRenames.get("aVar"));
        assertEquals("int", spec.variableTypes.get("aVar"));
    }

    @Test
    void parseEmpty_returnsEmptySpec() {
        FunctionRewrite.ComprehensiveRewriteSpec spec = fr.parseComprehensiveRewriteResponse("");
        assertNull(spec.functionName);
        assertTrue(spec.variableRenames.isEmpty());
    }

    // ===== isDecompilerGeneratedName =====

    @Test
    void isDecompilerGeneratedName_matches() {
        assertTrue(fr.isDecompilerGeneratedName("param_1"));
        assertTrue(fr.isDecompilerGeneratedName("local_aa"));
        assertTrue(fr.isDecompilerGeneratedName("puStack_10"));
        assertTrue(fr.isDecompilerGeneratedName("iVar1"));
        assertTrue(fr.isDecompilerGeneratedName("in_addr"));
        assertTrue(fr.isDecompilerGeneratedName("temp_0"));
        assertTrue(fr.isDecompilerGeneratedName("extraout_rax"));
        assertFalse(fr.isDecompilerGeneratedName("myVar"));
        assertFalse(fr.isDecompilerGeneratedName("userFoo"));
    }

    // ===== isDefaultGlobalName =====

    @Test
    void isDefaultGlobalName_matches() {
        assertTrue(fr.isDefaultGlobalName("DAT_0054a938"));
        assertTrue(fr.isDefaultGlobalName("FUN_00400000"));
        assertTrue(fr.isDefaultGlobalName("_DAT_0054a938"));
        assertTrue(fr.isDefaultGlobalName("cls_0x1000"));
        assertTrue(fr.isDefaultGlobalName("s_00540000"));
        assertTrue(fr.isDefaultGlobalName("meth_0x1234"));
        assertFalse(fr.isDefaultGlobalName("myGlobal"));
        assertFalse(fr.isDefaultGlobalName(""));
        assertFalse(fr.isDefaultGlobalName(null));
    }

    // ===== isCodeLabel / isMemberFieldName / isDefaultFieldName =====

    @Test
    void isCodeLabel() {
        assertTrue(fr.isCodeLabel("LAB_00400000"));
        assertTrue(fr.isCodeLabel("vftable_0x10"));
        assertFalse(fr.isCodeLabel("iVar1"));
    }

    @Test
    void isMemberFieldName() {
        assertTrue(fr.isMemberFieldName("mbr_0x10"));
        assertTrue(fr.isMemberFieldName("field_0x60"));
        assertTrue(fr.isMemberFieldName("m_health"));
        assertFalse(fr.isMemberFieldName("iVar1"));
    }

    @Test
    void isDefaultFieldName() {
        assertTrue(fr.isDefaultFieldName("mbr_0x10"));
        assertTrue(fr.isDefaultFieldName("field_0x60"));
    }

    // ===== normalizeToCamelCase / normalizeToPascalCase =====

    @Test
    void normalizeToCamelCase() {
        assertEquals("camelCase", fr.normalizeToCamelCase("camelCase"));
        assertEquals("camelCase", fr.normalizeToCamelCase("camel_case"));
        assertEquals("myField", fr.normalizeToCamelCase("m_myField"));
        // PascalCase with no underscore -> lowercase first char
        assertEquals("foo", fr.normalizeToCamelCase("Foo"));
    }

    @Test
    void normalizeToPascalCase() {
        assertEquals("PascalCase", fr.normalizeToPascalCase("pascalCase"));
        assertEquals("PascalCase", fr.normalizeToPascalCase("pascal_case"));
    }

    // ===== extractors (regex) =====

    @Test
    void extractMemberFieldReferences() {
        Map<String, String> out = fr.extractMemberFieldReferences("obj->field_0x60; x.mbr_0x10;");
        assertTrue(out.containsKey("field_0x60"));
        assertTrue(out.containsKey("mbr_0x10"));
        // dedupe: first accessor wins
        Map<String, String> out2 = fr.extractMemberFieldReferences("a->field_0x60; b->field_0x60;");
        assertEquals(1, out2.size());
    }

    @Test
    void extractFunctionCallReferences() {
        Map<String, String> out = fr.extractFunctionCallReferences("FUN_00412340(); cls_0x10::meth_0x20();");
        assertTrue(out.containsKey("FUN_00412340"));
    }

    @Test
    void extractClassReferences() {
        java.util.Set<String> out = fr.extractClassReferences("cls_0x1000 *p; C_AIW x; int n;");
        assertTrue(out.contains("cls_0x1000"));
    }
}
