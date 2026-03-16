//Decompile all user-defined functions and print C-like pseudocode
//@author CarvedRock Security Training
//@category Analysis
//@description Decompiles functions and prints output for CLI analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        println("=== Decompiled Functions ===");
        println("Binary: " + currentProgram.getName());
        println("========================================\n");

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator functions = funcMgr.getFunctions(true);

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();

            // Skip external/library functions
            if (func.isExternal() || func.isThunk()) {
                continue;
            }

            String name = func.getName();

            // Skip standard C runtime functions
            if (name.startsWith("_") && !name.startsWith("_0x")) {
                continue;
            }
            if (name.equals("frame_dummy") || name.equals("register_tm_clones") ||
                name.equals("deregister_tm_clones") || name.equals("__do_global_dtors_aux") ||
                name.equals("__libc_csu_init") || name.equals("__libc_csu_fini") ||
                name.equals("_start") || name.equals("_init") || name.equals("_fini")) {
                continue;
            }

            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results.getDecompiledFunction() != null) {
                println("--- Function: " + name + " @ " + func.getEntryPoint() + " ---");
                println(results.getDecompiledFunction().getC());
                println("");
            }
        }

        decomp.dispose();
        println("=== End of Decompilation ===");
    }
}
