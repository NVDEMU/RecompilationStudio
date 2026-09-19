import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExportGameAnalysis extends GhidraScript {
    private static final Pattern ID_PATTERN =
        Pattern.compile("\\$Id:\\s+([A-Za-z0-9_./\\\\-]+\\.[A-Za-z0-9]+)");
    private static final Pattern PATH_PATTERN =
        Pattern.compile("(?:[A-Za-z]:)?(?:[\\\\/][A-Za-z0-9_.-]+)+\\.(?:c|C|cc|cpp|s|S|asm|obj)");
    private static final long MAX_IDENT_OBJECT_SPAN = 64L * 1024L;
    private static final String OBJECT_TREE_NAME = "ObjectFiles";

    private final Map<Long, String> objectByEntry = new HashMap<>();
    private final List<ObjectInterval> objectIntervals = new ArrayList<>();

    private static final class ObjectMarker {
        final Address address;
        final String name;
        final String kind; // "ident" ($Id) or "path"

        ObjectMarker(Address address, String name, String kind) {
            this.address = address;
            this.name = name;
            this.kind = kind;
        }
    }

    private static final class ObjectInterval {
        final Address start;
        final Address endInclusive;
        final String name;

        ObjectInterval(Address start, Address endInclusive, String name) {
            this.start = start;
            this.endInclusive = endInclusive;
            this.name = name;
        }
    }

    private static String quote(String value) {
        if (value == null) return "null";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String basename(String path) {
        if (path == null) return null;
        String name = path.replace('\\', '/');
        int slash = name.lastIndexOf('/');
        if (slash >= 0) name = name.substring(slash + 1);
        return name.isEmpty() ? null : name;
    }

    private void collectFragments(ProgramModule module, List<ProgramFragment> out) {
        Group[] children = module.getChildren();
        if (children == null) return;
        for (Group group : children) {
            if (group instanceof ProgramFragment) {
                out.add((ProgramFragment) group);
            } else if (group instanceof ProgramModule) {
                collectFragments((ProgramModule) group, out);
            }
        }
    }

    private List<ObjectMarker> scanObjectMarkers() {
        List<ObjectMarker> markers = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized()) continue;
            long size = block.getSize();
            if (size <= 0 || size > Integer.MAX_VALUE) continue;
            byte[] buf = new byte[(int) size];
            try {
                block.getBytes(block.getStart(), buf);
            } catch (MemoryAccessException ignored) {
                continue;
            }
            int i = 0;
            while (i < buf.length) {
                if (buf[i] < 32 || buf[i] > 126) {
                    i++;
                    continue;
                }
                int j = i;
                while (j < buf.length && buf[j] >= 32 && buf[j] <= 126) j++;
                if (j - i >= 6) {
                    String text = new String(buf, i, j - i, StandardCharsets.US_ASCII);
                    Matcher id = ID_PATTERN.matcher(text);
                    if (id.find()) {
                        String name = basename(id.group(1));
                        if (name != null) {
                            markers.add(new ObjectMarker(block.getStart().add(i), name, "ident"));
                        }
                    } else {
                        Matcher path = PATH_PATTERN.matcher(text);
                        if (path.find()) {
                            String name = basename(path.group(0));
                            if (name != null) {
                                markers.add(new ObjectMarker(block.getStart().add(i), name, "path"));
                            }
                        }
                    }
                }
                i = j + 1;
            }
        }
        markers.sort(Comparator.comparingLong(m -> m.address.getOffset()));
        return markers;
    }

    private void assignObjectFiles(List<ObjectMarker> markers) {
        objectByEntry.clear();
        objectIntervals.clear();
        List<ObjectMarker> idents = new ArrayList<>();
        for (ObjectMarker marker : markers) {
            if ("ident".equals(marker.kind)) idents.add(marker);
        }
        for (int i = 0; i < idents.size(); i++) {
            ObjectMarker cur = idents.get(i);
            Address end = cur.address;
            if (i + 1 < idents.size()) {
                ObjectMarker next = idents.get(i + 1);
                long span = next.address.getOffset() - cur.address.getOffset();
                if (span > 0 && span <= MAX_IDENT_OBJECT_SPAN) {
                    end = next.address.subtract(1);
                }
            }
            if (end.getOffset() >= cur.address.getOffset()) {
                objectIntervals.add(new ObjectInterval(cur.address, end, cur.name));
            }
        }
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            Address entry = function.getEntryPoint();
            long offset = entry.getOffset();
            for (ObjectInterval interval : objectIntervals) {
                if (offset >= interval.start.getOffset() &&
                    offset <= interval.endInclusive.getOffset()) {
                    objectByEntry.put(offset, interval.name);
                    break;
                }
            }
        }
        for (ObjectMarker marker : markers) {
            ReferenceIterator refs = currentProgram.getReferenceManager()
                .getReferencesTo(marker.address);
            while (refs.hasNext()) {
                Reference reference = refs.next();
                Function function = currentProgram.getFunctionManager()
                    .getFunctionContaining(reference.getFromAddress());
                if (function != null) {
                    objectByEntry.putIfAbsent(function.getEntryPoint().getOffset(), marker.name);
                }
            }
        }
    }

    private void createObjectFileTree() {
        if (objectIntervals.isEmpty()) return;
        int tx = currentProgram.startTransaction("Create object-file program tree");
        boolean ok = false;
        try {
            Listing listing = currentProgram.getListing();
            if (listing.getRootModule(OBJECT_TREE_NAME) == null) {
                listing.createRootModule(OBJECT_TREE_NAME);
            }
            ProgramModule root = listing.getRootModule(OBJECT_TREE_NAME);
            if (root == null) return;
            Map<String, Integer> used = new HashMap<>();
            for (ObjectInterval interval : objectIntervals) {
                int n = used.getOrDefault(interval.name, 0) + 1;
                used.put(interval.name, n);
                String fragName = n == 1 ? interval.name : interval.name + "_" + n;
                ProgramFragment fragment = listing.getFragment(OBJECT_TREE_NAME, fragName);
                if (fragment == null) {
                    fragment = root.createFragment(fragName);
                }
                fragment.move(interval.start, interval.endInclusive);
            }
            ok = true;
        } catch (Exception ignored) {
            // Tree creation is proof for Ghidra GUI; the JSON map is the load-bearing output.
        } finally {
            currentProgram.endTransaction(tx, ok);
        }
    }

    private boolean isMemoryBlockFragment(ProgramFragment fragment) {
        if (fragment == null) return true;
        String name = fragment.getName();
        if (name == null || name.isEmpty()) return true;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (name.equals(block.getName())) return true;
        }
        return false;
    }

    private String fragmentNameContaining(Address address) {
        try {
            Listing listing = currentProgram.getListing();
            String[] trees = listing.getTreeNames();
            if (trees == null) return null;
            ProgramFragment best = null;
            int bestCount = 0;
            for (String tree : trees) {
                ProgramModule root = listing.getRootModule(tree);
                if (root == null) continue;
                List<ProgramFragment> fragments = new ArrayList<>();
                collectFragments(root, fragments);
                int objectFragments = 0;
                for (ProgramFragment fragment : fragments) {
                    if (!isMemoryBlockFragment(fragment)) objectFragments++;
                }
                if (objectFragments <= 1) continue;
                ProgramFragment fragment = listing.getFragment(tree, address);
                if (isMemoryBlockFragment(fragment)) continue;
                if (objectFragments > bestCount) {
                    bestCount = objectFragments;
                    best = fragment;
                } else if (best == null) {
                    best = fragment;
                }
            }
            return best == null ? null : best.getName();
        } catch (Exception ignored) {
            return null;
        }
    }

    private String sourceFileName(Function function) {
        try {
            SourceFileManager manager = currentProgram.getSourceFileManager();
            List<SourceMapEntry> entries = manager.getSourceMapEntries(function.getEntryPoint());
            if (entries == null || entries.isEmpty()) return null;
            var sourceFile = entries.get(0).getSourceFile();
            if (sourceFile == null) return null;
            String path = sourceFile.getPath();
            if (path != null && !path.isEmpty()) return path;
            String filename = sourceFile.getFilename();
            return (filename == null || filename.isEmpty()) ? null : filename;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String namespaceName(Function function) {
        Namespace ns = function.getParentNamespace();
        if (ns == null || ns.isGlobal()) return null;
        String name = ns.getName(true);
        return (name == null || name.isEmpty()) ? null : name;
    }

    private String resolveCompilationUnit(Function function) {
        String source = sourceFileName(function);
        if (source != null) return source;
        String object = objectByEntry.get(function.getEntryPoint().getOffset());
        if (object != null) return object;
        String fragment = fragmentNameContaining(function.getEntryPoint());
        if (fragment != null) return fragment;
        return namespaceName(function);
    }

    private String groupingFor(int sourceMapped, int fragmentMapped, int objectMapped, int namespaceMapped) {
        int kinds = 0;
        if (sourceMapped > 0) kinds++;
        if (fragmentMapped > 0) kinds++;
        if (objectMapped > 0) kinds++;
        if (namespaceMapped > 0) kinds++;
        if (kinds == 0) return "none";
        if (kinds > 1) return "mixed";
        if (sourceMapped > 0) return "source_map";
        if (fragmentMapped > 0) return "program_tree";
        if (objectMapped > 0) return "object_file";
        return "namespace";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) {
            throw new IllegalArgumentException("usage: OUT.json ENTRY LO HI_EXCLUSIVE");
        }
        Path output = Path.of(args[0]);
        long entryValue = Long.decode(args[1]);
        long lo = Long.decode(args[2]);
        long hi = Long.decode(args[3]);
        Address entry = toAddr(entryValue);
        Listing listing = currentProgram.getListing();
        Function entryFunction = currentProgram.getFunctionManager().getFunctionAt(entry);

        List<String> blocks = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            blocks.add("{" +
                "\"name\":" + quote(block.getName()) + "," +
                "\"start\":" + quote(block.getStart().toString()) + "," +
                "\"end\":" + quote(block.getEnd().toString()) + "," +
                "\"size\":" + block.getSize() +
                "}");
        }

        List<ObjectMarker> markers = scanObjectMarkers();
        assignObjectFiles(markers);
        createObjectFileTree();

        List<String> functions = new ArrayList<>();
        List<String> excludedFunctions = new ArrayList<>();
        Map<String, List<String>> units = new LinkedHashMap<>();
        int mappedFunctions = 0;
        int sourceMapped = 0;
        int fragmentMapped = 0;
        int objectMapped = 0;
        int namespaceMapped = 0;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            long address = function.getEntryPoint().getOffset();
            if (address < lo || address >= hi || (address & 3L) != 0L) continue;
            Instruction instruction = listing.getInstructionAt(function.getEntryPoint());
            if (instruction == null) continue;

            // Ghidra can create a one-instruction function when packed data
            // happens to decode as JAL. Reject only the narrow, provable case:
            // the instruction falls through, its entire function body is that
            // one instruction, and every reference comes from outside any
            // function. Keep the required executable entry unconditionally.
            List<String> referenceSources = new ArrayList<>();
            boolean referencedFromFunction = false;
            ReferenceIterator references = currentProgram.getReferenceManager()
                .getReferencesTo(function.getEntryPoint());
            while (references.hasNext()) {
                Reference reference = references.next();
                referenceSources.add(quote(reference.getFromAddress().toString()));
                if (currentProgram.getFunctionManager()
                        .getFunctionContaining(reference.getFromAddress()) != null) {
                    referencedFromFunction = true;
                }
            }
            boolean dataDerivedFalseFunction = address != entryValue &&
                function.getBody().getNumAddresses() == instruction.getLength() &&
                instruction.getFallThrough() != null &&
                !referenceSources.isEmpty() &&
                !referencedFromFunction;
            if (dataDerivedFalseFunction) {
                excludedFunctions.add("{" +
                    "\"entry\":" + quote(String.format("0x%08X", address)) + "," +
                    "\"name\":" + quote(function.getName()) + "," +
                    "\"instruction\":" + quote(instruction.toString()) + "," +
                    "\"reason\":" + quote("single fallthrough instruction referenced only from outside functions") + "," +
                    "\"reference_sources\":[" + String.join(",", referenceSources) + "]" +
                    "}");
                continue;
            }
            String compilationUnit = resolveCompilationUnit(function);
            if (compilationUnit != null) {
                mappedFunctions++;
                units.computeIfAbsent(compilationUnit, key -> new ArrayList<>())
                    .add(String.format("0x%08X", address));
                if (sourceFileName(function) != null) sourceMapped++;
                else if (objectByEntry.containsKey(address)) objectMapped++;
                else if (fragmentNameContaining(function.getEntryPoint()) != null) fragmentMapped++;
                else namespaceMapped++;
            }
            functions.add("{" +
                "\"entry\":" + quote(String.format("0x%08X", address)) + "," +
                "\"name\":" + quote(function.getName()) + "," +
                "\"body_min\":" + quote(function.getBody().getMinAddress().toString()) + "," +
                "\"body_max\":" + quote(function.getBody().getMaxAddress().toString()) + "," +
                "\"compilation_unit\":" + quote(compilationUnit) + "," +
                "\"instruction\":" + quote(instruction.toString()) +
                "}");
        }

        List<String> entryInstructions = new ArrayList<>();
        Instruction instruction = listing.getInstructionAt(entry);
        for (int index = 0; index < 8 && instruction != null; ++index) {
            byte[] bytes = instruction.getBytes();
            StringBuilder word = new StringBuilder();
            for (int byteIndex = bytes.length - 1; byteIndex >= 0; --byteIndex) {
                word.append(String.format("%02X", bytes[byteIndex] & 0xff));
            }
            entryInstructions.add("{" +
                "\"address\":" + quote(instruction.getAddress().toString()) + "," +
                "\"word_little_endian\":" + quote("0x" + word) + "," +
                "\"disassembly\":" + quote(instruction.toString()) +
                "}");
            instruction = instruction.getNext();
        }

        String json = "{\n" +
            "  \"schema\": 1,\n" +
            "  \"program\": " + quote(currentProgram.getName()) + ",\n" +
            "  \"language\": " + quote(currentProgram.getLanguageID().toString()) + ",\n" +
            "  \"image_base\": " + quote(currentProgram.getImageBase().toString()) + ",\n" +
            "  \"entry\": " + quote(String.format("0x%08X", entryValue)) + ",\n" +
            "  \"entry_function\": " + quote(entryFunction == null ? null : entryFunction.getName()) + ",\n" +
            "  \"memory_blocks\": [" + String.join(",", blocks) + "],\n" +
            "  \"entry_instructions\": [" + String.join(",", entryInstructions) + "],\n" +
            "  \"function_count\": " + functions.size() + ",\n" +
            "  \"excluded_function_count\": " + excludedFunctions.size() + ",\n" +
            "  \"excluded_functions\": [" + String.join(",", excludedFunctions) + "],\n" +
            "  \"functions\": [\n    " + String.join(",\n    ", functions) + "\n  ]\n" +
            "}\n";
        Files.createDirectories(output.getParent());
        Files.writeString(output, json, StandardCharsets.UTF_8);

        List<String> unitObjects = new ArrayList<>();
        for (Map.Entry<String, List<String>> unit : units.entrySet()) {
            List<String> quoted = new ArrayList<>();
            for (String addr : unit.getValue()) quoted.add(quote(addr));
            unitObjects.add("{" +
                "\"name\":" + quote(unit.getKey()) + "," +
                "\"functions\":[" + String.join(",", quoted) + "]" +
                "}");
        }
        String grouping = groupingFor(sourceMapped, fragmentMapped, objectMapped, namespaceMapped);
        String cuJson = "{\n" +
            "  \"schema\": 1,\n" +
            "  \"source\": \"ghidra\",\n" +
            "  \"program\": " + quote(currentProgram.getName()) + ",\n" +
            "  \"grouping\": " + quote(grouping) + ",\n" +
            "  \"mapped_function_count\": " + mappedFunctions + ",\n" +
            "  \"unit_count\": " + units.size() + ",\n" +
            "  \"units\": [\n    " + String.join(",\n    ", unitObjects) + "\n  ]\n" +
            "}\n";
        Path cuOutput = output.getParent().resolve("ghidra_compilation_units.json");
        Files.writeString(cuOutput, cuJson, StandardCharsets.UTF_8);
        println("wrote " + output + " (" + functions.size() + " functions, " +
            excludedFunctions.size() + " excluded data-derived functions)");
        println("wrote " + cuOutput + " (" + units.size() + " compilation units, " +
            mappedFunctions + " mapped functions, grouping=" + grouping +
            ", object_files=" + objectIntervals.size() + ")");
    }
}
