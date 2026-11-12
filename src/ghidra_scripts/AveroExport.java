// AveroExport.java — Ghidra headless script used by `avero decompile`.
//
// Usage (from analyzeHeadless):
//   -postScript AveroExport.java <output.json> [only-name-or-address] [limit]
//
// Emits JSON:
//   {"program","language","image_base","functions":[{"name","entry","size","decompiled"}]}
//
// This file is embedded in the Rust binary and written to a temporary script directory at
// runtime; it is compiled by Ghidra when the headless job runs.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

public class AveroExport extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs.length < 1) {
            println("AveroExport: missing output path argument");
            return;
        }
        String outputPath = scriptArgs[0];
        String only = scriptArgs.length > 1 ? scriptArgs[1] : "";
        int limit = 300;
        if (scriptArgs.length > 2) {
            try {
                limit = Integer.parseInt(scriptArgs[2]);
            } catch (NumberFormatException ignored) {
                limit = 300;
            }
        }
        if (limit < 1) {
            limit = 1;
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        if (!decompiler.openProgram(currentProgram)) {
            println("AveroExport: cannot open program");
            return;
        }

        PrintWriter writer = new PrintWriter(
            new OutputStreamWriter(new FileOutputStream(outputPath), "UTF-8"));
        try {
            writer.print("{\"program\":");
            writer.print(json(currentProgram.getName()));
            writer.print(",\"language\":");
            writer.print(json(currentProgram.getLanguageID().toString()));
            writer.print(",\"image_base\":");
            writer.print(json(Long.toHexString(currentProgram.getImageBase().getOffset())));
            writer.print(",\"functions\":[");

            FunctionManager manager = currentProgram.getFunctionManager();
            int count = 0;
            for (Function function : manager.getFunctions(true)) {
                if (count >= limit) {
                    break;
                }
                String name = function.getName();
                String address = function.getEntryPoint().toString();
                if (!only.isEmpty()
                    && !name.equalsIgnoreCase(only)
                    && !address.equalsIgnoreCase(only)) {
                    continue;
                }
                String code = "";
                try {
                    DecompileResults results =
                        decompiler.decompileFunction(function, 60, new ConsoleTaskMonitor());
                    if (results != null
                        && results.decompileCompleted()
                        && results.getDecompiledFunction() != null) {
                        code = results.getDecompiledFunction().getC();
                    }
                } catch (Exception error) {
                    code = "/* decompilation failed: " + error.getMessage() + " */";
                }
                if (count > 0) {
                    writer.print(",");
                }
                writer.print("{\"name\":");
                writer.print(json(name));
                writer.print(",\"entry\":");
                writer.print(json(address));
                writer.print(",\"size\":");
                writer.print(function.getBody().getNumAddresses());
                writer.print(",\"decompiled\":");
                writer.print(json(code));
                writer.print("}");
                count++;
            }
            writer.print("]}");
            writer.println();
        } finally {
            writer.close();
            decompiler.dispose();
        }
        println("AveroExport: wrote " + limit + " function budget, output " + outputPath);
    }

    private static String json(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder builder = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"':
                    builder.append("\\\"");
                    break;
                case '\\':
                    builder.append("\\\\");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        builder.append(String.format("\\u%04x", (int) character));
                    } else {
                        builder.append(character);
                    }
            }
        }
        builder.append("\"");
        return builder.toString();
    }
}
