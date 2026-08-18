package ghidragpt.utils;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class SuggestionApplierTest {

    // ===== parseVariableSuggestions =====

    @Test
    void parseVariableSuggestions_withReason() {
        List<SuggestionApplier.VariableSuggestion> out =
            SuggestionApplier.parseVariableSuggestions("iVar1 -> counter: counts iterations");
        assertEquals(1, out.size());
        assertEquals("iVar1", out.get(0).oldName);
        assertEquals("counter", out.get(0).newName);
        assertEquals("counts iterations", out.get(0).reason);
    }

    @Test
    void parseVariableSuggestions_withoutReasonAndMultiple() {
        String resp = "param_1 -> width\nlocal_80 -> height: from usage\nnot a rename line";
        List<SuggestionApplier.VariableSuggestion> out = SuggestionApplier.parseVariableSuggestions(resp);
        assertEquals(2, out.size());
        assertEquals("width", out.get(0).newName);
        assertEquals("height", out.get(1).newName);
    }

    @Test
    void parseVariableSuggestions_dropsInvalidNewNames() {
        // "int" is a reserved C keyword -> excluded
        List<SuggestionApplier.VariableSuggestion> out =
            SuggestionApplier.parseVariableSuggestions("x -> int");
        assertTrue(out.isEmpty());
    }

    // ===== isValidVariableName =====

    @Test
    void isValidVariableName_table() {
        assertFalse(SuggestionApplier.isValidVariableName(null));
        assertFalse(SuggestionApplier.isValidVariableName(""));
        assertFalse(SuggestionApplier.isValidVariableName("1abc"));
        assertTrue(SuggestionApplier.isValidVariableName("_x"));
        assertTrue(SuggestionApplier.isValidVariableName("myVar_1"));
        assertFalse(SuggestionApplier.isValidVariableName("for"));   // keyword
        assertFalse(SuggestionApplier.isValidVariableName("return"));
        assertFalse(SuggestionApplier.isValidVariableName("bad-name"));
    }

    // ===== extractCodeBlock =====

    @Test
    void extractCodeBlock_fenced() {
        String resp = "prefix\n```c\nint a = 1;\n```\nsuffix";
        assertEquals("int a = 1;", SuggestionApplier.extractCodeBlock(resp));
    }

    @Test
    void extractCodeBlock_noMarkerHeuristic() {
        String resp = "int foo(int a) {\n return 1;\n}\n";
        String out = SuggestionApplier.extractCodeBlock(resp);
        assertTrue(out.contains("int foo(int a) {"));
    }

    // ===== applyVariableSuggestions =====

    @Test
    void applyVariableSuggestions_appliesLocalAndParam() throws Exception {
        @SuppressWarnings("unchecked") Variable localVar = mock(Variable.class);
        @SuppressWarnings("unchecked") Parameter param = mock(Parameter.class);

        @SuppressWarnings("unchecked") Function fn = mock(Function.class);
        when(fn.getLocalVariables()).thenReturn(new Variable[]{localVar});
        when(fn.getParameters()).thenReturn(new Parameter[]{param});

        when(localVar.getName()).thenReturn("iVar1");
        when(param.getName()).thenReturn("param_1");
        when(localVar.getSource()).thenReturn(SourceType.USER_DEFINED);
        when(param.getSource()).thenReturn(SourceType.USER_DEFINED);

        SuggestionApplier.VariableSuggestion s1 = new SuggestionApplier.VariableSuggestion("iVar1", "counter", "");
        SuggestionApplier.VariableSuggestion s2 = new SuggestionApplier.VariableSuggestion("param_1", "handle", "");

        int applied = SuggestionApplier.applyVariableSuggestions(fn, List.of(s1, s2));
        assertEquals(2, applied);
        verify(localVar).setName("counter", SourceType.USER_DEFINED);
        verify(param).setName("handle", SourceType.USER_DEFINED);
    }

    @Test
    void applyVariableSuggestions_duplicateNameSkipped() throws Exception {
        @SuppressWarnings("unchecked") Variable existing = mock(Variable.class);
        @SuppressWarnings("unchecked") Variable duplicate = mock(Variable.class);

        @SuppressWarnings("unchecked") Function fn = mock(Function.class);
        when(fn.getLocalVariables()).thenReturn(new Variable[]{existing, duplicate});
        when(fn.getParameters()).thenReturn(new Parameter[0]);

        when(existing.getName()).thenReturn("iVar1");
        when(duplicate.getName()).thenReturn("iVar2");
        when(duplicate.getSource()).thenReturn(SourceType.USER_DEFINED);
        doThrow(new DuplicateNameException())
            .when(duplicate).setName(anyString(), eq(SourceType.USER_DEFINED));

        SuggestionApplier.VariableSuggestion s1 = new SuggestionApplier.VariableSuggestion("iVar1", "okName", "");
        SuggestionApplier.VariableSuggestion s2 = new SuggestionApplier.VariableSuggestion("iVar2", "okName", "");

        int applied = SuggestionApplier.applyVariableSuggestions(fn, List.of(s1, s2));
        assertEquals(1, applied);
    }

    // ===== generateSuggestionReport =====

    @Test
    void generateSuggestionReport_containsTotalsAndSuggestions() throws Exception {
        @SuppressWarnings("unchecked") Function fn = mock(Function.class);
        when(fn.getName()).thenReturn("FUN_0040");
        SuggestionApplier.VariableSuggestion s = new SuggestionApplier.VariableSuggestion("a", "b", "reason");
        String report = SuggestionApplier.generateSuggestionReport(fn, List.of(s), 1);
        assertTrue(report.contains("FUN_0040"));
        assertTrue(report.contains("Total suggestions: 1"));
        assertTrue(report.contains("a → b"));
    }
}
