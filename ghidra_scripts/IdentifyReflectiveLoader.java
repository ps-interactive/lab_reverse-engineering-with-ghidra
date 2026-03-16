//Identify reflective loading and in-memory execution patterns
//@author CarvedRock Security Training
//@category Analysis
//@description Flags mmap/mprotect calls, RWX memory, and injection patterns

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class IdentifyReflectiveLoader extends GhidraScript {

    private static final String[] SUSPICIOUS_FUNCTIONS = {
        "mmap", "mprotect", "munmap", "memcpy", "memset",
        "dlopen", "dlsym", "ptrace", "fork", "execve",
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory"
    };

    private static final String[] SUSPICIOUS_STRINGS = {
        "/proc/self/maps", "/proc/self/status", "TracerPid",
        "PROT_EXEC", "MAP_ANONYMOUS"
    };

    @Override
    public void run() throws Exception {
        println("=== CarvedRock Reflective Loader Detector ===");
        println("Scanning for in-memory execution indicators...\n");

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Listing listing = currentProgram.getListing();
        int riskScore = 0;

        // Check for suspicious function imports
        println("[*] Checking function imports:");
        println("-".repeat(50));

        for (String funcName : SUSPICIOUS_FUNCTIONS) {
            SymbolIterator symbols = symbolTable.getSymbols(funcName);
            while (symbols.hasNext()) {
                Symbol sym = symbols.next();
                println("    [!] Found: " + funcName + " at " + sym.getAddress());
                riskScore++;
            }
        }

        // Check for suspicious string references
        println("\n[*] Checking string references:");
        println("-".repeat(50));

        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        while (allSymbols.hasNext()) {
            Symbol sym = allSymbols.next();
            for (String pattern : SUSPICIOUS_STRINGS) {
                if (sym.getName().contains(pattern)) {
                    println("    [!] Found: " + sym.getName() +
                            " at " + sym.getAddress());
                    riskScore++;
                }
            }
        }

        // Look for function pointer casts (call to register/memory)
        println("\n[*] Checking for indirect calls (function pointer execution):");
        println("-".repeat(50));

        InstructionIterator instructions = listing.getInstructions(true);
        int indirectCalls = 0;

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructions.next();
            String mnemonic = instr.getMnemonicString();

            if (mnemonic.equals("CALL")) {
                String operand = instr.getDefaultOperandRepresentation(0);
                // Indirect calls through registers suggest function pointers
                if (operand.startsWith("R") || operand.startsWith("r") ||
                    operand.contains("[")) {
                    indirectCalls++;
                    if (indirectCalls <= 10) {
                        println("    [*] Indirect call at " + instr.getAddress() +
                                ": CALL " + operand);
                    }
                }
            }
        }

        if (indirectCalls > 0) {
            println("    [*] Total indirect calls: " + indirectCalls);
            riskScore += (indirectCalls > 3) ? 2 : 1;
        }

        // Risk assessment
        println("\n" + "=".repeat(50));
        println(" Reflective Loading Risk Assessment");
        println("=".repeat(50));
        println("    Risk indicators found: " + riskScore);

        if (riskScore >= 6) {
            println("    Assessment: HIGH RISK");
            println("    Likely technique: T1620 (Reflective Code Loading)");
            println("    Recommendation: Deep decompiler analysis required");
        } else if (riskScore >= 3) {
            println("    Assessment: MEDIUM RISK");
            println("    Some indicators of reflective loading present");
        } else {
            println("    Assessment: LOW RISK");
            println("    Few reflective loading indicators");
        }

        println("\n=== Scan Complete ===");
    }
}
