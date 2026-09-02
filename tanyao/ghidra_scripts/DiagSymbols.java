/* DiagSymbols.java — tanyao diagnostics: image base, symbols, function range. */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class DiagSymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("DIAG imageBase=" + currentProgram.getImageBase());
        SymbolTable st = currentProgram.getSymbolTable();
        int total = 0, named = 0;
        SymbolIterator it = st.getAllSymbols(true);
        for (Symbol s : it) {
            total++;
            String n = s.getName();
            if (n.contains("Java_") || n.contains("ANativeActivity")) {
                println("DIAG symbol: " + n + " @ " + s.getAddress());
                named++;
            }
        }
        println("DIAG symbolTotal=" + total + " interesting=" + named);
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        long min = Long.MAX_VALUE, max = 0;
        int cnt = 0;
        Address target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x131658L);
        Function f = getFunctionContaining(target);
        println("DIAG funcAt0x131658=" + (f == null ? "NONE" : f.getName() + " @ " + f.getEntryPoint()));
        while (fi.hasNext()) {
            Function fn = fi.next();
            long e = fn.getEntryPoint().getOffset();
            if (e < min) min = e;
            if (e > max) max = e;
            cnt++;
        }
        println("DIAG functionCount=" + cnt + " minEntry=0x" + Long.toHexString(min)
                + " maxEntry=0x" + Long.toHexString(max));
    }
}
