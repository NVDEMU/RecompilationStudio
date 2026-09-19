#include "compilation_units.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "fmt/format.h"

namespace fs = std::filesystem;
using PSXRecomp::FunctionText;
using PSXRecomp::CompilationUnitMap;
using PSXRecomp::plan_compilation_units;
using PSXRecomp::load_compilation_unit_map;
using PSXRecomp::write_modular_c;
using PSXRecomp::sanitize_unit_name;

static FunctionText fn(uint32_t addr, uint32_t keep = 0) {
    FunctionText t;
    t.addr = addr;
    t.keep_together = keep;
    t.name = fmt::format("func_{:08X}", addr);
    t.signature = fmt::format("void func_{:08X}(CPUState* cpu)", addr);
    t.code = t.signature + " {\n    (void)cpu;\n}\n";
    return t;
}

static void require(bool cond, const char* msg) {
    if (!cond) throw std::runtime_error(msg);
}

int main() {
    require(sanitize_unit_name("C:\\psyq\\src\\libgpu.c") == "libgpu",
            "sanitize should take basename without extension");
    require(sanitize_unit_name("../../foo-bar.c") == "foo-bar",
            "sanitize should keep hyphen");

    {
        std::vector<FunctionText> funcs;
        for (uint32_t i = 0; i < 10; ++i) funcs.push_back(fn(0x80010000u + i * 0x10u));
        auto plan = plan_compilation_units(funcs, {}, 256, 128);
        require(plan.units.size() == 1, "small corpus stays in one unit");
        require(plan.grouping == "address_range", "no ghidra map => address_range");
        require(plan.units[0].function_addrs.size() == 10, "all functions assigned");
    }

    {
        std::vector<FunctionText> funcs;
        for (uint32_t i = 0; i < 300; ++i) funcs.push_back(fn(0x80010000u + i * 0x10u));
        auto plan = plan_compilation_units(funcs, {}, 256, 128);
        require(plan.units.size() == 2, "300 functions at 256/unit => 2 units");
        require(plan.units[0].function_addrs.size() == 256, "first unit packed to target");
        require(plan.units[1].function_addrs.size() == 44, "remainder in last unit");
    }

    {
        // Alias wrappers must not split across units even at a pack boundary.
        std::vector<FunctionText> funcs;
        for (uint32_t i = 0; i < 255; ++i) funcs.push_back(fn(0x80010000u + i * 0x10u));
        uint32_t host = 0x80012000u;
        funcs.push_back(fn(host, host));
        funcs.push_back(fn(host + 4, host));
        funcs.push_back(fn(host + 8, host));
        auto plan = plan_compilation_units(funcs, {}, 256, 128);
        bool together = false;
        for (const auto& unit : plan.units) {
            int seen = 0;
            for (uint32_t a : unit.function_addrs) {
                if (a == host || a == host + 4 || a == host + 8) ++seen;
            }
            if (seen == 3) together = true;
            require(seen == 0 || seen == 3, "alias group split across compilation units");
        }
        require(together, "alias group missing from every unit");
    }

    {
        const fs::path tmp = fs::temp_directory_path() / "psxrecomp-cu-map.json";
        std::ofstream out(tmp);
        out << R"({
  "schema": 1,
  "source": "ghidra",
  "grouping": "source_map",
  "units": [
    {"name": "libgpu.c", "functions": ["0x80020000", "0x80020010"],
     "body_min": "0x80020000", "body_max": "0x8002003F"},
    {"name": "main.c", "functions": ["0x80030000"]}
  ]
})";
        out.close();
        auto map = load_compilation_unit_map(tmp);
        require(map.loaded, "map should load");
        require(map.grouping == "source_map", "grouping field");
        std::vector<FunctionText> funcs = {
            fn(0x80020000), fn(0x80020010), fn(0x80020020), fn(0x80030000),
            fn(0x80040000)
        };
        auto plan = plan_compilation_units(funcs, map, 256, 128);
        require(plan.grouping == "source_map", "ghidra grouping preserved");
        require(plan.units.size() == 3, "libgpu + main + unmapped range");
        fs::remove(tmp);
    }

    {
        const fs::path tmp = fs::temp_directory_path() / "psxrecomp-cu-objects.json";
        std::ofstream out(tmp);
        out << R"({
  "schema": 1,
  "source": "ghidra",
  "grouping": "object_file",
  "units": [
    {"name": "sys.c", "functions": ["0x80014224"]},
    {"name": "intr.c", "functions": ["0x80014454"]}
  ]
})";
        out.close();
        auto map = load_compilation_unit_map(tmp);
        require(map.grouping == "object_file", "object_file grouping");
        require(sanitize_unit_name("sys.c") == "sys", "object basename");
        std::vector<FunctionText> funcs = {fn(0x80014224), fn(0x80014454), fn(0x80020000)};
        auto plan = plan_compilation_units(funcs, map, 256, 128);
        require(plan.grouping == "object_file", "plan keeps object_file grouping");
        require(plan.units.size() == 3, "two objects plus unmapped pack");
        fs::remove(tmp);
    }

    {
        const fs::path dir = fs::temp_directory_path() / "psxrecomp-cu-out";
        fs::create_directories(dir);
        std::ofstream(dir / "game_full.c") << "/* stale monolith */\n";
        std::vector<FunctionText> funcs = {fn(0x80010000), fn(0x80010010)};
        auto plan = plan_compilation_units(funcs, {}, 1, 128);
        require(plan.units.size() == 2, "target 1 function/unit splits a pair");
        write_modular_c(dir, "game", "#include \"psx_runtime.h\"\n", funcs, plan);
        require(fs::exists(dir / "game_decls.h"), "decls header");
        require(fs::exists(dir / "game_cu_prelude.h"), "prelude header");
        require(fs::exists(dir / "game_units.json"), "units manifest");
        require(!fs::exists(dir / "game_full.c"), "stale monolith removed");
        int cu_files = 0;
        for (const auto& e : fs::directory_iterator(dir)) {
            const auto name = e.path().filename().string();
            if (name.rfind("game_cu_", 0) == 0 && name.size() > 2 &&
                name.compare(name.size() - 2, 2, ".c") == 0)
                ++cu_files;
        }
        require(cu_files == 2, "one C file per unit");
        fs::remove_all(dir);
    }

    return 0;
}
