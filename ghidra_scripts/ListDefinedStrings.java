//List all defined strings found in the binary
//@author CarvedRock Security Training
//@category Analysis
//@description Extracts and prints all defined string references

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class ListDefinedStrings extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Defined Strings ===");
        println("Binary: " + currentProgram.getName());
        println("========================================");

        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        int count = 0;

        while (dataIter.hasNext() && !monitor.isCancelled()) {
            Data data = dataIter.next();
            DataType dt = data.getDataType();

            if (dt instanceof StringDataType || dt instanceof TerminatedStringDataType ||
                dt instanceof UnicodeDataType || dt.getName().toLowerCase().contains("string")) {
                String value = data.getDefaultValueRepresentation();
                if (value != null && value.length() > 3) {
                    println("    " + data.getAddress() + ": " + value);
                    count++;
                }
            }
        }

        println("\n[*] Total defined strings: " + count);
        println("=== End of Strings ===");
    }
}
