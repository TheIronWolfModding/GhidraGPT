package ghidragpt.service;

import ghidra.program.model.data.DataType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class VariableAnalysisTest {

    private static DataType typeNamed(String name) {
        DataType t = mock(DataType.class);
        org.mockito.Mockito.when(t.getDisplayName()).thenReturn(name);
        org.mockito.Mockito.when(t.getName()).thenReturn(name);
        return t;
    }

    @Test
    void categorizeParameter() {
        VariableAnalysis v = new VariableAnalysis("param_1", null, true);
        assertEquals(VariableAnalysis.VariableCategory.PARAMETER, v.getCategory());
        assertTrue(v.isParameter());
    }

    @Test
    void categorizeTemporary() {
        assertEquals(VariableAnalysis.VariableCategory.TEMPORARY,
            new VariableAnalysis("iVar1", null, false).getCategory());
        assertEquals(VariableAnalysis.VariableCategory.TEMPORARY,
            new VariableAnalysis("uVar2", null, false).getCategory());
        assertEquals(VariableAnalysis.VariableCategory.TEMPORARY,
            new VariableAnalysis("fVar3", null, false).getCategory());
    }

    @Test
    void categorizeStack() {
        // Decimal stack-slot names match the ^local_\d+$ / ^[ui]Stack_\d+$ patterns
        assertEquals(VariableAnalysis.VariableCategory.STACK,
            new VariableAnalysis("uStack_10", null, false).getCategory());
        assertEquals(VariableAnalysis.VariableCategory.STACK,
            new VariableAnalysis("local_100", null, false).getCategory());
        // Note: hex digits do NOT match the current decimal-only pattern, so
        // Ghidra-style local_aa/cVar1 fall through to LOCAL. Behavior documented here.
        assertEquals(VariableAnalysis.VariableCategory.LOCAL,
            new VariableAnalysis("local_aa", null, false).getCategory());
    }

    @Test
    void categorizeWellNamedAndLocal() {
        assertEquals(VariableAnalysis.VariableCategory.WELL_NAMED,
            new VariableAnalysis("MyLocal", null, false).getCategory());
        assertEquals(VariableAnalysis.VariableCategory.LOCAL,
            new VariableAnalysis("temp", null, false).getCategory());
    }

    @Test
    void needsTypeAnalysis() {
        assertTrue(new VariableAnalysis("a", typeNamed("undefined4"), false).needsTypeAnalysis());
        assertTrue(new VariableAnalysis("a", typeNamed("undefined1"), false).needsTypeAnalysis());
        assertTrue(new VariableAnalysis("a", typeNamed("int"), false).needsTypeAnalysis());
        assertTrue(new VariableAnalysis("a", typeNamed("uint"), false).needsTypeAnalysis());
        assertTrue(new VariableAnalysis("a", typeNamed("void*"), false).needsTypeAnalysis());
        assertFalse(new VariableAnalysis("a", typeNamed("int32_t"), false).needsTypeAnalysis());
        assertFalse(new VariableAnalysis("a", typeNamed("MyStruct"), false).needsTypeAnalysis());
    }

    @Test
    void getTypeDisplayName_nullType() {
        assertEquals("unknown", new VariableAnalysis("a", null, false).getTypeDisplayName());
        DataType t = mock(DataType.class);
        org.mockito.Mockito.when(t.getDisplayName()).thenReturn("DWORD");
        assertEquals("DWORD", new VariableAnalysis("a", t, false).getTypeDisplayName());
    }
}
