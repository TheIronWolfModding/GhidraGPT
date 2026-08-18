package ghidragpt.service;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FunctionAnalysisTest {

    static DataType dataType(String name, String display) {
        DataType d = mock(DataType.class);
        when(d.getDisplayName()).thenReturn(display != null ? display : name);
        return d;
    }

    static Parameter parameter(String name, DataType type) {
        Parameter p = mock(Parameter.class);
        when(p.getName()).thenReturn(name);
        when(p.getDataType()).thenReturn(type);
        return p;
    }

    static Function function(String name, int paramCount, long instructionCount, DataType returnType) {
        Function f = mock(Function.class);
        when(f.getName()).thenReturn(name);
        when(f.getParameterCount()).thenReturn(paramCount);
        AddressSetView body = mock(AddressSetView.class);
        when(body.getNumAddresses()).thenReturn(instructionCount);
        when(f.getBody()).thenReturn(body);
        when(f.getReturnType()).thenReturn(returnType);
        when(f.getParameters()).thenReturn(new Parameter[0]);
        return f;
    }

    @Test
    void signature_format() {
        DataType ret = dataType("int", "int");
        Function f = function("FUN_00400000", 0, 10, ret);
        FunctionAnalysis analysis = new FunctionAnalysis(f, true);
        assertEquals("int FUN_00400000()", analysis.getSignature());
        assertEquals("FUN_00400000", analysis.getFunctionName());
    }

    @Test
    void signature_includesParameters() {
        DataType ret = dataType("void", "void");
        Function f = mock(Function.class);
        when(f.getName()).thenReturn("handler");
        when(f.getParameterCount()).thenReturn(2);
        AddressSetView body = mock(AddressSetView.class);
        when(body.getNumAddresses()).thenReturn(50L);
        when(f.getBody()).thenReturn(body);
        when(f.getReturnType()).thenReturn(ret);
        DataType t1 = dataType("int", "int");
        DataType t2 = dataType("MyStruct*", "MyStruct*");
        Parameter p1 = parameter("arg1", t1);
        Parameter p2 = parameter("arg2", t2);
        when(f.getParameters()).thenReturn(new Parameter[]{p1, p2});

        FunctionAnalysis analysis = new FunctionAnalysis(f, true);
        assertEquals("void handler(int arg1, MyStruct* arg2)", analysis.getSignature());
    }

    @Test
    void complexitySimple() {
        FunctionAnalysis a = new FunctionAnalysis(function("f", 2, 19, dataType("void", "void")), true);
        assertEquals(FunctionAnalysis.FunctionComplexity.SIMPLE, a.getComplexity());
    }

    @Test
    void complexityModerate() {
        FunctionAnalysis a = new FunctionAnalysis(function("f", 4, 99, dataType("void", "void")), true);
        assertEquals(FunctionAnalysis.FunctionComplexity.MODERATE, a.getComplexity());
    }

    @Test
    void complexityComplex() {
        FunctionAnalysis a = new FunctionAnalysis(function("f", 8, 499, dataType("void", "void")), true);
        assertEquals(FunctionAnalysis.FunctionComplexity.COMPLEX, a.getComplexity());
    }

    @Test
    void complexityVeryComplex() {
        FunctionAnalysis a = new FunctionAnalysis(function("f", 8, 500, dataType("void", "void")), true);
        assertEquals(FunctionAnalysis.FunctionComplexity.VERY_COMPLEX, a.getComplexity());
    }

    @Test
    void needsAnalysis_byComplexity() {
        FunctionAnalysis simple = new FunctionAnalysis(function("f", 1, 10, dataType("void", "void")), true);
        assertFalse(simple.needsAnalysis());
        FunctionAnalysis complex = new FunctionAnalysis(function("f", 8, 200, dataType("void", "void")), true);
        assertTrue(complex.needsAnalysis());
    }

    @Test
    void needsAnalysis_addIssueSetsTrue() {
        FunctionAnalysis simple = new FunctionAnalysis(function("f", 1, 10, dataType("void", "void")), true);
        simple.addIssue("something");
        assertTrue(simple.needsAnalysis());
    }
}
