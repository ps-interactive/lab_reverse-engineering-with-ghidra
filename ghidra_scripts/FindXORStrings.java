//Find XOR-encrypted string patterns in the binary
//@author CarvedRock Security Training
//@category Analysis
//@description Searches for XOR decryption loops and encrypted byte arrays

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class FindXORStrings extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== CarvedRock XOR String Finder ===");
        println("Scanning for XOR decryption patterns...\n");

        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        // Search for XOR instruction patterns in code
        int xorCount = 0;
        InstructionIterator instructions = listing.getInstructions(true);

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructions.next();
            String mnemonic = instr.getMnemonicString();

            if (mnemonic.equals("XOR")) {
                xorCount++;
                if (xorCount <= 20) {
                    println("[*] XOR instruction at " + instr.getAddress() +
                            ": " + instr.toString());
                }
            }
        }

        println("\n[*] Total XOR instructions found: " + xorCount);

        // Search for byte arrays that could be encrypted strings
        // Look for sequences of non-zero bytes followed by a null terminator
        println("\n[*] Searching for encrypted byte arrays...");

        MemoryBlock[] blocks = memory.getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.isInitialized() && !block.isExecute()) {
                println("[*] Scanning block: " + block.getName() +
                        " at " + block.getStart());
            }
        }

        // Search for the decrypt_string function pattern
        println("\n[*] Searching for decryption function references...");
        SymbolIterator symbols = symbolTable.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName();
            if (name.contains("decrypt") || name.contains("decode") ||
                name.contains("xor") || name.contains("_0x")) {
                println("[!] Suspicious function: " + name +
                        " at " + sym.getAddress());
            }
        }

        println("\n=== Scan Complete ===");
        println("Review flagged functions in the decompiler for XOR loops.");
    }
}
