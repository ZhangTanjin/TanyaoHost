/* TanyaoDecomp.java — Ghidra headless decompilation script for the tanyao toolchain.
 *
 * Post-script for analyzeHeadless: decompiles every function in the program
 * (cap: maxFunctions arg) to <outDir>/<name>_<entrypoint>.c and writes an
 * index.json mapping entrypoints to names.
 *
 * Usage: analyzeHeadless <projDir> <proj> -import <file> \
 *          -scriptPath <dir> -postScript TanyaoDecomp.java <outDir> <maxFunctions> \
 *          -deleteProject
 */
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class TanyaoDecomp extends GhidraScript {

    private static String safe(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == '$') {
                b.append(c);
            } else {
                b.append('_');
            }
        }
        return b.toString();
    }

    private static String jsonEscape(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("TANYAO_DECOMP_ERROR need args: <outDir> <maxFunctions>");
            return;
        }
        File outDir = new File(args[0]);
        int maxFunctions = Integer.parseInt(args[1]);
        if (!outDir.isDirectory() && !outDir.mkdirs()) {
            println("TANYAO_DECOMP_ERROR cannot create outDir " + outDir);
            return;
        }

        DecompInterface di = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        di.setOptions(opts);
        di.openProgram(currentProgram);

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int done = 0;
        StringBuilder index = new StringBuilder();
        index.append("{\"functions\":[");
        while (it.hasNext() && done < maxFunctions) {
            Function f = it.next();
            if (f.isThunk()) {
                continue;
            }
            DecompileResults res = di.decompileFunction(f, 90, monitor);
            if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
                continue;
            }
            String entry = "0x" + f.getEntryPoint().toString();
            String fname = safe(f.getName()) + "_" + entry.substring(2) + ".c";
            File out = new File(outDir, fname);
            try (PrintWriter w = new PrintWriter(out, StandardCharsets.UTF_8.name())) {
                w.println(res.getDecompiledFunction().getC());
            }
            if (done > 0) {
                index.append(",");
            }
            index.append("{\"name\":\"").append(jsonEscape(f.getName()))
                 .append("\",\"entry\":\"").append(entry)
                 .append("\",\"file\":\"").append(jsonEscape(fname)).append("\"}");
            done++;
            if (done % 25 == 0) {
                println("TANYAO_DECOMP_PROGRESS " + done);
            }
        }
        index.append("],\"count\":").append(done).append("}");
        try (PrintWriter w = new PrintWriter(new File(outDir, "index.json"), StandardCharsets.UTF_8.name())) {
            w.println(index);
        }
        di.dispose();
        println("TANYAO_DECOMP_DONE count=" + done);
    }
}
