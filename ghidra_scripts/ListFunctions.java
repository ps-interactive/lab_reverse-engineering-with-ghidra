//List all user-defined (non-library) functions in the binary
//@author CarvedRock Security Training
//@category Analysis
//@description Lists function names and addresses for quick triage

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class ListFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Function Listing ===");
        println("Binary: " + currentProgram.getName());
        println("========================================");

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator functions = funcMgr.getFunctions(true);
        int total = 0;
        int userDefined = 0;

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            total++;

            if (func.isExternal() || func.isThunk()) {
                continue;
            }

            String name = func.getName();

            // Skip standard C runtime boilerplate
            if (name.equals("frame_dummy") || name.equals("register_tm_clones") ||
                name.equals("deregister_tm_clones") || name.equals("__do_global_dtors_aux") ||
                name.equals("__libc_csu_init") || name.equals("__libc_csu_fini") ||
                name.equals("_start") || name.equals("_init") || name.equals("_fini")) {
                continue;
            }

            userDefined++;
            println("    " + func.getEntryPoint() + "  " + name +
                    "  (" + func.getParameterCount() + " params)");
        }

        println("\n[*] Total functions: " + total);
        println("[*] User-defined functions: " + userDefined);
        println("=== End of Function Listing ===");
    }
}
