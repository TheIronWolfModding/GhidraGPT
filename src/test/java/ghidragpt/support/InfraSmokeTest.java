package ghidragpt.support;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Data;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.Msg;
import ghidra.util.ErrorLogger;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

public class InfraSmokeTest {

    @Test
    void msgHeadlessSafe() {
        Msg.info(this, "i"); Msg.warn(this, "w"); Msg.error(this, "e");
        Msg.error(this, "et", new RuntimeException("t"));
        final StringBuilder seen = new StringBuilder();
        Msg.setErrorLogger(new ErrorLogger() {
            public void trace(Object o, Object m) {}
            public void debug(Object o, Object m) {}
            public void info(Object o, Object m) { seen.append(m); }
            public void warn(Object o, Object m) { seen.append(m); }
            public void error(Object o, Object m) { seen.append(m); }
            public void trace(Object o, Object m, Throwable t) {}
            public void debug(Object o, Object m, Throwable t) {}
            public void info(Object o, Object m, Throwable t) { seen.append(m); }
            public void warn(Object o, Object m, Throwable t) { seen.append(m); }
            public void error(Object o, Object m, Throwable t) { seen.append(m); }
        });
        Msg.error(this, "captured", new RuntimeException("t"));
        assertTrue(seen.toString().contains("captured"));
    }

    @Test
    void mockInterfaces() {
        Function f = mock(Function.class);
        FunctionManager fm = mock(FunctionManager.class);
        Listing lst = mock(Listing.class);
        SymbolTable st = mock(SymbolTable.class);
        AddressFactory af = mock(AddressFactory.class);
        AddressSpace as = mock(AddressSpace.class);
        AddressSetView body = mock(AddressSetView.class);
        Variable v = mock(Variable.class);
        Parameter p = mock(Parameter.class);
        Data d = mock(Data.class);
        Symbol sym = mock(Symbol.class);
        SymbolIterator it = mock(SymbolIterator.class);
        DataType dt = mock(DataType.class);
        DataTypeManager dtm = mock(DataTypeManager.class);
        Structure struct = mock(Structure.class);
        DataTypeComponent comp = mock(DataTypeComponent.class);
        assertAll(() -> {
            assertNotNull(f); assertNotNull(fm); assertNotNull(lst); assertNotNull(st);
            assertNotNull(af); assertNotNull(as); assertNotNull(body); assertNotNull(v);
            assertNotNull(p); assertNotNull(d); assertNotNull(sym); assertNotNull(it);
            assertNotNull(dt); assertNotNull(dtm); assertNotNull(struct); assertNotNull(comp);
        });
    }

    @Test
    void mockConcreteNonFinal() {
        Address addr = mock(Address.class);
        DecompInterface di = mock(DecompInterface.class);
        DecompileResults dr = mock(DecompileResults.class);
        DecompiledFunction df = mock(DecompiledFunction.class);
        HighFunction hf = mock(HighFunction.class);
        LocalSymbolMap lsm = mock(LocalSymbolMap.class);
        HighSymbol hs = mock(HighSymbol.class);
        Pointer ptr = mock(Pointer.class);
        assertNotNull(addr); assertNotNull(di); assertNotNull(dr);
        assertNotNull(df); assertNotNull(hf); assertNotNull(lsm); assertNotNull(hs);
        assertNotNull(ptr);
    }

    @Test
    void mockStaticHighFunctionDBUtil() throws Exception {
        try (MockedStatic<HighFunctionDBUtil> ms = mockStatic(HighFunctionDBUtil.class)) {
            HighFunctionDBUtil.updateDBVariable(null, "x", null, null);
            ms.verify(() -> HighFunctionDBUtil.updateDBVariable(null, "x", null, null));
        }
    }

    @Test
    void realGhidraObjectConstruction() {
        // These are used by the apply code paths, must be constructable without Ghidra runtime
        DataType base = mock(DataType.class);
        PointerDataType ptr = new PointerDataType(base);
        assertNotNull(ptr);
        assertNotNull(Undefined.getUndefinedDataType(4));
    }

    @Test
    void pcodeAndDecompiledFunctionMocks() {
        DecompInterface di = mock(DecompInterface.class);
        DecompileResults dr = mock(DecompileResults.class);
        DecompiledFunction df = mock(DecompiledFunction.class);
        HighFunction hf = mock(HighFunction.class);
        LocalSymbolMap lsm = mock(LocalSymbolMap.class);
        HighSymbol hs = mock(HighSymbol.class);
        Pointer ptr = mock(Pointer.class);
        assertNotNull(di); assertNotNull(dr); assertNotNull(df);
        assertNotNull(hf); assertNotNull(lsm); assertNotNull(hs); assertNotNull(ptr);
    }

    @Test
    void consoleTaskMonitorConstructibleHeadless() throws Exception {
        // If this throws, the batch path can't be exercised
        ghidra.util.task.ConsoleTaskMonitor m = new ghidra.util.task.ConsoleTaskMonitor();
        assertNotNull(m);
        assertFalse(m.isCancelled());
    }
}
