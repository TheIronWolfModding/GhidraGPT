package ghidragpt.utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class GhidraFunctionModifierTest {

    @Test
    void updateFunctionName_nullOrEmptyOrIdenticalReturnsFalse() {
        Program program = mock(Program.class);
        Function function = mock(Function.class);
        GhidraFunctionModifier m = new GhidraFunctionModifier(program, mock(TaskMonitor.class));

        when(function.getName()).thenReturn("orig");
        assertFalse(m.updateFunctionName(function, null));
        assertFalse(m.updateFunctionName(function, "  "));
        assertFalse(m.updateFunctionName(function, "orig"));
    }

    @Test
    void updateFunctionName_existingSymbolSkips() throws Exception {
        Program program = mock(Program.class);
        Function function = mock(Function.class);
        SymbolTable symbolTable = mock(SymbolTable.class);
        SymbolIterator iterator = mock(SymbolIterator.class);

        GhidraFunctionModifier m = new GhidraFunctionModifier(program, mock(TaskMonitor.class));
        when(function.getName()).thenReturn("orig");
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(symbolTable.getSymbols("newName")).thenReturn(iterator);
        when(iterator.hasNext()).thenReturn(true);

        assertFalse(m.updateFunctionName(function, "newName"));
        verify(function, never()).setName(anyString(), any(SourceType.class));
    }

    @Test
    void updateFunctionName_success() throws Exception {
        Program program = mock(Program.class);
        Function function = mock(Function.class);
        SymbolTable symbolTable = mock(SymbolTable.class);
        SymbolIterator iterator = mock(SymbolIterator.class);

        GhidraFunctionModifier m = new GhidraFunctionModifier(program, mock(TaskMonitor.class));
        when(function.getName()).thenReturn("orig");
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(symbolTable.getSymbols("newName")).thenReturn(iterator);
        when(iterator.hasNext()).thenReturn(false);

        assertTrue(m.updateFunctionName(function, "newName"));
        verify(function).setName(eq("newName"), eq(SourceType.USER_DEFINED));
    }

    @Test
    void updateFunctionComment_nullBlankFalse() {
        Function function = mock(Function.class);
        GhidraFunctionModifier m = new GhidraFunctionModifier(mock(Program.class), mock(TaskMonitor.class));
        assertFalse(m.updateFunctionComment(function, null));
        assertFalse(m.updateFunctionComment(function, "   "));
        assertTrue(m.updateFunctionComment(function, "a note"));
    }

    @Test
    void updateFunctionRepeatableComment_nullBlankFalse() {
        Function function = mock(Function.class);
        GhidraFunctionModifier m = new GhidraFunctionModifier(mock(Program.class), mock(TaskMonitor.class));
        assertFalse(m.updateFunctionRepeatableComment(function, null));
        assertFalse(m.updateFunctionRepeatableComment(function, ""));
        assertTrue(m.updateFunctionRepeatableComment(function, "r"));
    }

    @Test
    void isValidFunctionName_table() {
        assertTrue(GhidraFunctionModifier.isValidFunctionName("validName_1"));
        assertFalse(GhidraFunctionModifier.isValidFunctionName(null));
        assertFalse(GhidraFunctionModifier.isValidFunctionName("   "));
        assertFalse(GhidraFunctionModifier.isValidFunctionName("9abc"));
        assertFalse(GhidraFunctionModifier.isValidFunctionName("has space"));
        assertFalse(GhidraFunctionModifier.isValidFunctionName("while"));
        assertFalse(GhidraFunctionModifier.isValidFunctionName("struct"));
    }
}
