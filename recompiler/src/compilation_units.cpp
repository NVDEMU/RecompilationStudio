#include "compilation_units.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include "fmt/format.h"

namespace PSXRecomp {
namespace fs = std::filesystem;

namespace {

uint32_t parse_hex_u32(const std::string& token) {
    return static_cast<uint32_t>(std::strtoul(token.c_str(), nullptr, 0));
}

void insert_entry(CompilationUnitMap& map, uint32_t addr, const std::string& name) {
    if (name.empty()) return;
    map.by_entry[addr] = name;
    map.by_entry[addr & 0x1FFFFFFFu] = name;
}

std::string json_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char n = s[++i];
            if (n == 'n') out += '\n';
            else if (n == 't') out += '\t';
            else out += n;
        } else {
            out += s[i];
        }
    }
    return out;
}

bool extract_json_string_field(const std::string& obj, const char* key, std::string& out) {
    const std::string pat = std::string("\"") + key + "\"";
    size_t p = obj.find(pat);
    if (p == std::string::npos) return false;
    p = obj.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    p = obj.find('"', p + 1);
    if (p == std::string::npos) return false;
    size_t e = p + 1;
    while (e < obj.size()) {
        if (obj[e] == '\\' && e + 1 < obj.size()) {
            e += 2;
            continue;
        }
        if (obj[e] == '"') break;
        ++e;
    }
    if (e >= obj.size()) return false;
    out = json_unescape(obj.substr(p + 1, e - (p + 1)));
    return true;
}

std::vector<std::string> extract_json_hex_array(const std::string& obj, const char* key) {
    std::vector<std::string> values;
    const std::string pat = std::string("\"") + key + "\"";
    size_t p = obj.find(pat);
    if (p == std::string::npos) return values;
    p = obj.find('[', p + pat.size());
    if (p == std::string::npos) return values;
    size_t e = obj.find(']', p + 1);
    if (e == std::string::npos) return values;
    const std::string body = obj.substr(p + 1, e - (p + 1));
    size_t i = 0;
    while (i < body.size()) {
        while (i < body.size() && body[i] != '"' && body[i] != '0') ++i;
        if (i >= body.size()) break;
        if (body[i] == '"') {
            size_t q = body.find('"', i + 1);
            if (q == std::string::npos) break;
            values.push_back(body.substr(i + 1, q - (i + 1)));
            i = q + 1;
        } else {
            size_t q = i;
            while (q < body.size() && (std::isxdigit(static_cast<unsigned char>(body[q])) ||
                                       body[q] == 'x' || body[q] == 'X'))
                ++q;
            values.push_back(body.substr(i, q - i));
            i = q;
        }
    }
    return values;
}

void write_text_file(const fs::path& path, const std::string& contents) {
    fs::create_directories(path.parent_path());
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error(fmt::format("cannot write {}", path.string()));
    }
    f.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\' || c == '"') {
            out += '\\';
            out += c;
        } else {
            out += c;
        }
    }
    return out;
}

}  // namespace

std::string sanitize_unit_name(const std::string& name) {
    std::string base = name;
    auto slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    auto dot = base.find_last_of('.');
    if (dot != std::string::npos && dot > 0) base = base.substr(0, dot);
    std::string out;
    out.reserve(base.size());
    for (char c : base) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-')
            out += c;
        else
            out += '_';
    }
    while (!out.empty() && out.front() == '_') out.erase(out.begin());
    while (!out.empty() && out.back() == '_') out.pop_back();
    if (out.empty()) out = "unit";
    if (out.size() > 40) out.resize(40);
    return out;
}

CompilationUnitMap load_compilation_unit_map(const fs::path& path) {
    CompilationUnitMap map;
    if (path.empty()) return map;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error(fmt::format("compilation-unit map not found: {}",
                                             path.string()));
    }
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    map.loaded = true;
    map.source = path.filename().string();
    extract_json_string_field(text, "source", map.source);
    extract_json_string_field(text, "grouping", map.grouping);

    size_t units_key = text.find("\"units\"");
    size_t search_from = (units_key == std::string::npos) ? 0 : units_key;
    size_t pos = search_from;
    while (true) {
        size_t obj_start = text.find('{', pos);
        if (obj_start == std::string::npos) break;
        size_t obj_end = text.find('}', obj_start + 1);
        if (obj_end == std::string::npos) break;
        const std::string obj = text.substr(obj_start, obj_end - obj_start + 1);
        pos = obj_end + 1;
        std::string name;
        if (!extract_json_string_field(obj, "name", name) || name.empty()) continue;
        auto funcs = extract_json_hex_array(obj, "functions");
        if (funcs.empty()) {
            // Per-function records: {"entry":"0x...","compilation_unit":"..."}
            std::string entry;
            std::string cu;
            if (extract_json_string_field(obj, "entry", entry) &&
                extract_json_string_field(obj, "compilation_unit", cu) &&
                !cu.empty()) {
                insert_entry(map, parse_hex_u32(entry), cu);
                std::string bmin, bmax;
                if (extract_json_string_field(obj, "body_min", bmin) &&
                    extract_json_string_field(obj, "body_max", bmax)) {
                    CompilationUnitInterval iv;
                    iv.lo = parse_hex_u32(bmin);
                    iv.hi = parse_hex_u32(bmax) + 1u;
                    iv.name = cu;
                    if (iv.hi > iv.lo) map.intervals.push_back(std::move(iv));
                }
            }
            continue;
        }
        uint32_t body_lo = 0xFFFFFFFFu;
        uint32_t body_hi = 0;
        std::string bmin, bmax;
        const bool have_body = extract_json_string_field(obj, "body_min", bmin) &&
                               extract_json_string_field(obj, "body_max", bmax);
        if (have_body) {
            body_lo = parse_hex_u32(bmin);
            body_hi = parse_hex_u32(bmax) + 1u;
        }
        for (const auto& token : funcs) {
            uint32_t addr = parse_hex_u32(token);
            insert_entry(map, addr, name);
            if (!have_body) {
                body_lo = std::min(body_lo, addr);
                body_hi = std::max(body_hi, addr + 4u);
            }
        }
        if (body_hi > body_lo && body_lo != 0xFFFFFFFFu) {
            CompilationUnitInterval iv;
            iv.lo = body_lo;
            iv.hi = body_hi;
            iv.name = name;
            map.intervals.push_back(std::move(iv));
        }
    }

    std::sort(map.intervals.begin(), map.intervals.end(),
              [](const CompilationUnitInterval& a, const CompilationUnitInterval& b) {
                  return a.lo < b.lo;
              });
    if (map.grouping.empty()) {
        map.grouping = map.by_entry.empty() ? "none" : "ghidra";
    }
    return map;
}

std::string lookup_compilation_unit(const CompilationUnitMap& map, uint32_t addr) {
    auto it = map.by_entry.find(addr);
    if (it != map.by_entry.end()) return it->second;
    it = map.by_entry.find(addr & 0x1FFFFFFFu);
    if (it != map.by_entry.end()) return it->second;
    for (const auto& iv : map.intervals) {
        if (addr >= iv.lo && addr < iv.hi) return iv.name;
        const uint32_t phys = addr & 0x1FFFFFFFu;
        const uint32_t lo = iv.lo & 0x1FFFFFFFu;
        const uint32_t hi = iv.hi & 0x1FFFFFFFu;
        if (phys >= lo && phys < hi) return iv.name;
    }
    return {};
}

CompilationUnitPlan plan_compilation_units(
    const std::vector<FunctionText>& functions,
    const CompilationUnitMap& ghidra_map,
    std::size_t target_functions_per_unit,
    uint32_t max_units) {

    CompilationUnitPlan plan;
    if (functions.empty()) {
        plan.grouping = "empty";
        return plan;
    }
    if (target_functions_per_unit == 0) target_functions_per_unit = kDefaultFunctionsPerUnit;
    if (max_units == 0) max_units = kMaxCompilationUnits;

    std::vector<FunctionText> ordered = functions;
    std::sort(ordered.begin(), ordered.end(),
              [](const FunctionText& a, const FunctionText& b) {
                  return a.addr < b.addr;
              });

    std::unordered_map<uint32_t, uint32_t> group_leader;
    for (const auto& fn : ordered) {
        uint32_t leader = fn.keep_together != 0 ? fn.keep_together : fn.addr;
        auto [it, inserted] = group_leader.emplace(leader, leader);
        (void)inserted;
        group_leader[fn.addr] = it->second;
    }
    // Union-find flatten: keep_together may point at a member, not the min addr.
    for (auto& [addr, leader] : group_leader) {
        uint32_t cur = leader;
        while (group_leader[cur] != cur) cur = group_leader[cur];
        leader = cur;
        (void)addr;
    }

    std::map<uint32_t, std::vector<uint32_t>> members;
    for (const auto& fn : ordered) {
        members[group_leader[fn.addr]].push_back(fn.addr);
    }

    const bool use_ghidra = ghidra_map.loaded && !ghidra_map.by_entry.empty();
    plan.grouping = use_ghidra ? ghidra_map.grouping : "address_range";
    if (plan.grouping.empty()) plan.grouping = "ghidra";

    struct Bucket {
        std::string name;
        std::string source;
        std::vector<uint32_t> addrs;
    };
    std::vector<Bucket> buckets;
    std::map<std::string, size_t> ghidra_index;

    auto append_bucket = [&](std::string name, std::string source,
                             std::vector<uint32_t> addrs) {
        if (addrs.empty()) return;
        std::sort(addrs.begin(), addrs.end());
        addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
        Bucket b;
        b.name = std::move(name);
        b.source = std::move(source);
        b.addrs = std::move(addrs);
        buckets.push_back(std::move(b));
    };

    if (use_ghidra) {
        std::map<std::string, std::vector<uint32_t>> by_name;
        std::vector<uint32_t> unmapped;
        std::unordered_set<uint32_t> placed;
        for (const auto& [leader, addrs] : members) {
            std::string cu = lookup_compilation_unit(ghidra_map, leader);
            if (cu.empty()) {
                for (uint32_t a : addrs) {
                    cu = lookup_compilation_unit(ghidra_map, a);
                    if (!cu.empty()) break;
                }
            }
            if (cu.empty()) {
                unmapped.insert(unmapped.end(), addrs.begin(), addrs.end());
            } else {
                auto& dest = by_name[cu];
                dest.insert(dest.end(), addrs.begin(), addrs.end());
            }
            for (uint32_t a : addrs) placed.insert(a);
        }
        for (auto& [name, addrs] : by_name) {
            std::sort(addrs.begin(), addrs.end());
            // Split oversized Ghidra CUs into address-sorted chunks.
            for (size_t i = 0; i < addrs.size();) {
                size_t n = std::min(target_functions_per_unit, addrs.size() - i);
                std::string chunk_name = name;
                if (addrs.size() > target_functions_per_unit) {
                    chunk_name = fmt::format("{}_{:08X}", name, addrs[i]);
                }
                append_bucket(chunk_name, "ghidra",
                              std::vector<uint32_t>(addrs.begin() + static_cast<std::ptrdiff_t>(i),
                                                    addrs.begin() + static_cast<std::ptrdiff_t>(i + n)));
                i += n;
            }
        }
        if (!unmapped.empty()) {
            std::sort(unmapped.begin(), unmapped.end());
            for (size_t i = 0; i < unmapped.size();) {
                size_t n = std::min(target_functions_per_unit, unmapped.size() - i);
                append_bucket(fmt::format("{:08X}", unmapped[i]), "address_range",
                              std::vector<uint32_t>(unmapped.begin() + static_cast<std::ptrdiff_t>(i),
                                                    unmapped.begin() + static_cast<std::ptrdiff_t>(i + n)));
                i += n;
            }
        }
        (void)ghidra_index;
        (void)placed;
    } else {
        std::vector<uint32_t> packed;
        packed.reserve(ordered.size());
        std::unordered_set<uint32_t> seen;
        for (const auto& fn : ordered) {
            uint32_t leader = group_leader[fn.addr];
            if (!seen.insert(leader).second) continue;
            const auto& group = members[leader];
            packed.insert(packed.end(), group.begin(), group.end());
        }
        size_t per = target_functions_per_unit;
        if (packed.size() > static_cast<size_t>(max_units) * per) {
            per = (packed.size() + max_units - 1u) / max_units;
        }
        for (size_t i = 0; i < packed.size();) {
            size_t n = std::min(per, packed.size() - i);
            // Do not split a keep-together group across units.
            while (i + n < packed.size()) {
                uint32_t last = packed[i + n - 1];
                uint32_t next = packed[i + n];
                if (group_leader[last] != group_leader[next]) break;
                ++n;
            }
            append_bucket(fmt::format("{:08X}", packed[i]), "address_range",
                          std::vector<uint32_t>(packed.begin() + static_cast<std::ptrdiff_t>(i),
                                                packed.begin() + static_cast<std::ptrdiff_t>(i + n)));
            i += n;
        }
    }

    if (buckets.size() > max_units) {
        // Merge overflow into the last allowed unit rather than dropping functions.
        Bucket overflow;
        overflow.name = "merged";
        overflow.source = buckets.back().source;
        for (size_t i = max_units - 1; i < buckets.size(); ++i) {
            overflow.addrs.insert(overflow.addrs.end(),
                                  buckets[i].addrs.begin(), buckets[i].addrs.end());
        }
        buckets.resize(max_units - 1);
        buckets.push_back(std::move(overflow));
    }

    plan.units.reserve(buckets.size());
    for (size_t i = 0; i < buckets.size(); ++i) {
        CompilationUnitSpec spec;
        spec.name = buckets[i].name;
        spec.source = buckets[i].source;
        spec.function_addrs = std::move(buckets[i].addrs);
        spec.filename = fmt::format("{}_cu_{:03d}_{}.c",
                                    "stem", i, sanitize_unit_name(spec.name));
        plan.units.push_back(std::move(spec));
    }
    return plan;
}

void write_modular_c(
    const fs::path& out_dir,
    const std::string& stem,
    const std::string& prelude,
    const std::vector<FunctionText>& functions,
    const CompilationUnitPlan& plan) {

    fs::create_directories(out_dir);

    std::unordered_map<uint32_t, const FunctionText*> by_addr;
    by_addr.reserve(functions.size());
    for (const auto& fn : functions) by_addr[fn.addr] = &fn;

    std::ostringstream decls;
    decls << "/* AUTO-GENERATED by PSXRecomp. DO NOT EDIT. */\n";
    decls << "#pragma once\n\n";
    decls << "/* Forward declarations for every recompiled function. */\n";
    std::vector<const FunctionText*> decl_order;
    decl_order.reserve(functions.size());
    for (const auto& fn : functions) decl_order.push_back(&fn);
    std::sort(decl_order.begin(), decl_order.end(),
              [](const FunctionText* a, const FunctionText* b) {
                  return a->addr < b->addr;
              });
    for (const FunctionText* fn : decl_order) {
        decls << fn->signature << ";\n";
    }
    const std::string decls_name = stem + "_decls.h";
    const std::string prelude_name = stem + "_cu_prelude.h";
    write_text_file(out_dir / decls_name, decls.str());

    std::ostringstream prelude_h;
    prelude_h << "/* AUTO-GENERATED by PSXRecomp. DO NOT EDIT. */\n";
    prelude_h << "#pragma once\n\n";
    prelude_h << prelude;
    if (!prelude.empty() && prelude.back() != '\n') prelude_h << '\n';
    prelude_h << "#include \"" << decls_name << "\"\n";
    write_text_file(out_dir / prelude_name, prelude_h.str());

    std::unordered_set<std::string> keep;
    keep.insert(decls_name);
    keep.insert(prelude_name);
    keep.insert(stem + "_units.json");

    std::ostringstream manifest;
    manifest << "{\n";
    manifest << "  \"schema\": 1,\n";
    manifest << fmt::format("  \"stem\": \"{}\",\n", json_escape(stem));
    manifest << fmt::format("  \"grouping\": \"{}\",\n", json_escape(plan.grouping));
    manifest << fmt::format("  \"unit_count\": {},\n", plan.units.size());
    manifest << fmt::format("  \"function_count\": {},\n", functions.size());
    manifest << "  \"units\": [\n";

    for (size_t i = 0; i < plan.units.size(); ++i) {
        CompilationUnitSpec spec = plan.units[i];
        spec.filename = fmt::format("{}_cu_{:03d}_{}.c",
                                    stem, i, sanitize_unit_name(spec.name));
        keep.insert(spec.filename);

        std::ostringstream cu;
        cu << "/* AUTO-GENERATED by PSXRecomp. DO NOT EDIT.\n";
        cu << fmt::format(" * Compilation unit {} of {}: {}\n",
                          i, plan.units.size(), spec.name);
        cu << fmt::format(" * source: {}\n", spec.source);
        cu << " */\n\n";
        cu << "#include \"" << prelude_name << "\"\n\n";
        for (uint32_t addr : spec.function_addrs) {
            auto it = by_addr.find(addr);
            if (it == by_addr.end()) {
                throw std::runtime_error(fmt::format(
                    "compilation unit {} references missing function 0x{:08X}",
                    spec.filename, addr));
            }
            cu << it->second->code;
            if (it->second->code.empty() || it->second->code.back() != '\n') cu << '\n';
            cu << '\n';
        }
        write_text_file(out_dir / spec.filename, cu.str());

        const uint32_t start = spec.function_addrs.front();
        const uint32_t end = spec.function_addrs.back();
        manifest << fmt::format(
            "    {{\"file\":\"{}\",\"name\":\"{}\",\"source\":\"{}\","
            "\"function_count\":{},\"start\":\"0x{:08X}\",\"end\":\"0x{:08X}\"}}{}\n",
            json_escape(spec.filename), json_escape(spec.name),
            json_escape(spec.source), spec.function_addrs.size(),
            start, end,
            (i + 1 == plan.units.size()) ? "" : ",");
    }
    manifest << "  ]\n";
    manifest << "}\n";
    write_text_file(out_dir / (stem + "_units.json"), manifest.str());

    // Drop the old monolith and any leftover units from a previous split count.
    std::error_code ec;
    const fs::path stale_full = out_dir / (stem + "_full.c");
    if (fs::exists(stale_full, ec)) fs::remove(stale_full, ec);
    const std::string prefix = stem + "_cu_";
    for (const auto& entry : fs::directory_iterator(out_dir, ec)) {
        if (!entry.is_regular_file()) continue;
        const std::string name = entry.path().filename().string();
        const bool cu_c = name.size() > prefix.size() &&
                          name.compare(0, prefix.size(), prefix) == 0 &&
                          name.size() > 2 && name.compare(name.size() - 2, 2, ".c") == 0;
        const bool cu_h = name == prelude_name || name == decls_name;
        if ((cu_c || cu_h) && !keep.count(name)) {
            fs::remove(entry.path(), ec);
        }
    }
}

}  // namespace PSXRecomp
