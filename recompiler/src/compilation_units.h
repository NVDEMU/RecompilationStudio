// compilation_units.h
// ----------------------------------------------------------------------------
// Split recompiled C across multiple host compilation units instead of one
// bulk *_full.c file.
//
// Grouping, in priority order:
//   1. A Ghidra compilation-unit map (DWARF source files, PSY-Q $Id object
//      files, Program Tree fragments, or non-global namespaces).
//   2. Address-contiguous packs of target_functions_per_unit functions.
//
// Alias groups / keep-together keys always land in the same unit so a
// file-static shared body and its wrappers stay in one translation unit.

#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace PSXRecomp {

constexpr std::size_t kDefaultFunctionsPerUnit = 64;
constexpr std::uint32_t kMaxCompilationUnits = 128;

struct CompilationUnitInterval {
    uint32_t lo = 0;   // inclusive
    uint32_t hi = 0;   // exclusive
    std::string name;
};

struct CompilationUnitMap {
    bool loaded = false;
    std::string source;     // "ghidra" / filename
    std::string grouping;   // "source_map" | "program_tree" | "namespace" | "mixed"
    std::map<uint32_t, std::string> by_entry;  // phys and/or virtual entry
    std::vector<CompilationUnitInterval> intervals;
};

struct FunctionText {
    uint32_t addr = 0;
    uint32_t keep_together = 0;  // 0 = none; else group leader
    std::string name;            // e.g. func_80012345
    std::string signature;       // e.g. void func_80012345(CPUState* cpu)
    std::string code;            // full definition, including signature
};

struct CompilationUnitSpec {
    std::string name;            // Ghidra CU / synthetic label
    std::string source;          // "ghidra" | "address_range"
    std::string filename;        // stem_cu_NNN_name.c
    std::vector<uint32_t> function_addrs;
};

struct CompilationUnitPlan {
    std::string grouping;
    std::vector<CompilationUnitSpec> units;
};

CompilationUnitMap load_compilation_unit_map(const std::filesystem::path& path);

std::string lookup_compilation_unit(const CompilationUnitMap& map, uint32_t addr);

CompilationUnitPlan plan_compilation_units(
    const std::vector<FunctionText>& functions,
    const CompilationUnitMap& ghidra_map,
    std::size_t target_functions_per_unit = kDefaultFunctionsPerUnit,
    uint32_t max_units = kMaxCompilationUnits);

std::string sanitize_unit_name(const std::string& name);

void write_modular_c(
    const std::filesystem::path& out_dir,
    const std::string& stem,
    const std::string& prelude,          // includes + externs + static helpers
    const std::vector<FunctionText>& functions,
    const CompilationUnitPlan& plan);

}  // namespace PSXRecomp
