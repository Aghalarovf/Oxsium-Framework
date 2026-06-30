#include "include/core.h"
#include "include/ldap_engine.h"
#include "modules/dominfo/dominfo_collector.h"
#include "modules/ace/ace_collector.h"
#include "modules/trust/trust_collector.h"
#include "modules/gpo/gpo_collector.h"
#include "modules/ou/ou_collector.h"
#include "modules/group/group_collector.h"
#include "modules/computer/computer_collector.h"
#include "modules/user/user_collector.h"
#include "modules/offline processor/offline_processor.h"
#include "modules/certificate/cert_collector.h"
#include "modules/network/network_collector.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <functional>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <windows.h>
#include <zlib.h>

// ─────────────────────────────────────────────────────────────────────────────
//  ZIP packaging helpers
//  Minimal ZIP writer — no external library needed beyond zlib (deflate).
//  Produces oxgen_<RANDOM_ID>.zip containing all Domain Objects jsonl/json files.
//
//  Format: ZIP local file headers + deflated data + central directory + EOCD.
// ─────────────────────────────────────────────────────────────────────────────

// Generate a random 8-char hex ID, e.g. "a3f8c21b"
static std::string generate_random_id() {
    auto seed = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count()
    );
    std::mt19937_64 rng(seed);
    uint32_t hi = static_cast<uint32_t>(rng() & 0xFFFFFFFF);
    uint32_t lo = static_cast<uint32_t>(rng() & 0xFFFFFFFF);
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%08x%08x", hi, lo);
    return std::string(buf, 8);
}

// Write little-endian uint16_t / uint32_t helpers
static void write_u16(std::ostream& os, uint16_t v) {
    uint8_t b[2] = { static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8) };
    os.write(reinterpret_cast<const char*>(b), 2);
}
static void write_u32(std::ostream& os, uint32_t v) {
    uint8_t b[4] = {
        static_cast<uint8_t>(v),
        static_cast<uint8_t>(v >> 8),
        static_cast<uint8_t>(v >> 16),
        static_cast<uint8_t>(v >> 24)
    };
    os.write(reinterpret_cast<const char*>(b), 4);
}

// Simple CRC-32 using zlib
static uint32_t crc32_of(const std::vector<uint8_t>& data) {
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, data.data(), static_cast<uInt>(data.size()));
    return static_cast<uint32_t>(crc);
}

// Deflate compress (raw deflate, stored if compression fails/grows)
static std::vector<uint8_t> deflate_compress(const std::vector<uint8_t>& in,
                                              uint16_t& method_out) {
    // Empty input — store as-is
    if (in.empty()) {
        method_out = 0;
        return in;
    }

    uLongf bound = compressBound(static_cast<uLong>(in.size()));
    std::vector<uint8_t> out(bound);

    z_stream zs{};
    // deflateInit2 return dəyərini yoxla
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        // Init uğursuz — raw saxla
        method_out = 0;
        return in;
    }

    zs.next_in   = const_cast<Bytef*>(in.data());
    zs.avail_in  = static_cast<uInt>(in.size());
    zs.next_out  = out.data();
    zs.avail_out = static_cast<uInt>(out.size());

    // deflate() return dəyərini yoxla — Z_STREAM_END olmalıdır
    int ret = deflate(&zs, Z_FINISH);
    uLong compressed_size = zs.total_out;
    deflateEnd(&zs);

    if (ret != Z_STREAM_END || compressed_size >= in.size()) {
        // Sıxışdırma uğursuz oldu və ya faydası olmadı — raw saxla
        method_out = 0;
        return in;
    }

    method_out = 8;       // ZIP method: deflated
    out.resize(compressed_size);
    return out;
}

struct ZipEntry {
    std::string           name;         // filename inside ZIP
    std::vector<uint8_t>  compressed;
    uint16_t              method;       // 0=stored, 8=deflated
    uint32_t              crc;
    uint32_t              uncompressed_size;
    uint32_t              local_offset; // byte offset of local file header
};

// Package all files in output_dir into oxgen_<id>.zip placed next to output_dir
static std::string package_domain_objects(const fs::path& output_dir,
                                          const fs::path& zip_dir) {
    std::string rand_id = generate_random_id();
    std::string zip_name = "oxgen_" + rand_id + ".zip";
    fs::path zip_path = zip_dir / zip_name;

    // Collect all files in output_dir (non-recursive, flat)
    std::vector<fs::path> files;
    for (auto& entry : fs::directory_iterator(output_dir)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    std::ofstream zf(zip_path, std::ios::binary);
    if (!zf) return "";

    std::vector<ZipEntry> entries;
    entries.reserve(files.size());

    // ── Write local file headers + data ──────────────────────────────────────
    for (const auto& fpath : files) {
        // Read file
        std::ifstream fin(fpath, std::ios::binary);
        if (!fin) continue;
        std::vector<uint8_t> raw_data(
            (std::istreambuf_iterator<char>(fin)),
             std::istreambuf_iterator<char>()
        );
        fin.close();

        ZipEntry e;
        e.name              = fpath.filename().string();
        e.uncompressed_size = static_cast<uint32_t>(raw_data.size());
        e.crc               = crc32_of(raw_data);
        e.compressed        = deflate_compress(raw_data, e.method);

        // tellp() xətasını yoxla (-1 = stream pozulub)
        std::streampos lpos = zf.tellp();
        if (!zf || lpos < 0) { zf.close(); fs::remove(zip_path); return ""; }
        e.local_offset = static_cast<uint32_t>(lpos);

        // Local file header  (signature 0x04034b50)
        write_u32(zf, 0x04034b50);
        write_u16(zf, 20);                              // version needed
        write_u16(zf, 0);                               // general purpose flags
        write_u16(zf, e.method);
        write_u16(zf, 0); write_u16(zf, 0);            // mod time/date (zero)
        write_u32(zf, e.crc);
        write_u32(zf, static_cast<uint32_t>(e.compressed.size()));
        write_u32(zf, e.uncompressed_size);
        write_u16(zf, static_cast<uint16_t>(e.name.size()));
        write_u16(zf, 0);                               // extra field length
        zf.write(e.name.data(), static_cast<std::streamsize>(e.name.size()));
        zf.write(reinterpret_cast<const char*>(e.compressed.data()),
                 static_cast<std::streamsize>(e.compressed.size()));

        // Yazma xətasını yoxla
        if (!zf) { zf.close(); fs::remove(zip_path); return ""; }

        entries.push_back(std::move(e));
    }

    // ── Central directory ─────────────────────────────────────────────────────
    std::streampos cd_pos = zf.tellp();
    if (!zf || cd_pos < 0) { zf.close(); fs::remove(zip_path); return ""; }
    uint32_t cd_offset = static_cast<uint32_t>(cd_pos);
    for (const auto& e : entries) {
        write_u32(zf, 0x02014b50);                      // central dir signature
        write_u16(zf, 20);                              // version made by
        write_u16(zf, 20);                              // version needed
        write_u16(zf, 0);                               // general purpose flags
        write_u16(zf, e.method);
        write_u16(zf, 0); write_u16(zf, 0);            // mod time/date
        write_u32(zf, e.crc);
        write_u32(zf, static_cast<uint32_t>(e.compressed.size()));
        write_u32(zf, e.uncompressed_size);
        write_u16(zf, static_cast<uint16_t>(e.name.size()));
        write_u16(zf, 0);                               // extra
        write_u16(zf, 0);                               // comment
        write_u16(zf, 0);                               // disk start
        write_u16(zf, 0);                               // int attrib
        write_u32(zf, 0);                               // ext attrib
        write_u32(zf, e.local_offset);
        zf.write(e.name.data(), static_cast<std::streamsize>(e.name.size()));
    }
    std::streampos cd_end_pos = zf.tellp();
    if (!zf || cd_end_pos < 0) { zf.close(); fs::remove(zip_path); return ""; }
    uint32_t cd_size = static_cast<uint32_t>(cd_end_pos) - cd_offset;

    // ── End of central directory ──────────────────────────────────────────────
    write_u32(zf, 0x06054b50);                          // EOCD signature
    write_u16(zf, 0);                                   // disk number
    write_u16(zf, 0);                                   // disk with CD
    write_u16(zf, static_cast<uint16_t>(entries.size()));
    write_u16(zf, static_cast<uint16_t>(entries.size()));
    write_u32(zf, cd_size);
    write_u32(zf, cd_offset);
    write_u16(zf, 0);                                   // comment length

    zf.close();
    // Bağlama əməliyyatından sonra stream vəziyyətini yoxla
    if (!zf) {
        fs::remove(zip_path);
        return "";
    }
    return zip_path.string();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Extra UI color codes
// ─────────────────────────────────────────────────────────────────────────────
#define CLR_DARK_GREY   "\033[38;5;240m"
#define CLR_BLOOD       "\033[38;5;160m"
#define CLR_SILVER      "\033[38;5;250m"
#define CLR_FAINT       "\033[38;5;236m"
#define CLR_MUTED       "\033[38;5;244m"
#define CLR_GLOW        "\033[38;5;203m"

static void print_banner() {
    std::cout << "\n";
    std::cout << CLR_FAINT << "  ══════════════════════════════════════════════════════════════════\n" << CLR_RESET;
    std::cout << CLR_BLOOD << CLR_BOLD << "\n";
    std::cout << "        \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97 \xe2\x96\x88\xe2\x96\x88\xe2\x95\x97  \xe2\x96\x88\xe2\x96\x88\xe2\x95\x97 \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97 \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97   \xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\n";
    std::cout << "       \xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x95\x9a\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90 \xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90 \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97  \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\n";
    std::cout << "       \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91   \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91 \xe2\x95\x9a\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91  \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97  \xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97 \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\n";
    std::cout << "       \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91   \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91 \xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97 \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91   \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90 \xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\xe2\x95\x9a\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\n";
    std::cout << "       \xe2\x95\x9a\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d \xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x95\x9a\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x94\xe2\x95\x9d\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x97\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91 \xe2\x95\x9a\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x95\x91\n";
    std::cout << "        \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9d \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d  \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9d \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d  \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9d\n";
    std::cout << CLR_RESET << "\n";
    std::cout << CLR_MUTED << "       Active Directory Enumeration Engine" << CLR_FAINT << "  ·  " << CLR_MUTED << "LDAP / LDAPS" << CLR_FAINT << "  ·  " << CLR_MUTED << "v.12\n" << CLR_RESET;
    std::cout << "\n";
    std::cout << CLR_FAINT << "  ──────────────────────────────────────────────────────────────────\n" << CLR_RESET;
    std::cout << CLR_DARK_GREY << "  Modules  " << CLR_RESET;
    const char* mods[] = { "user", "group", "computer", "network", "ou", "gpo", "certificate", "acl", "dominfo" };
    for (const char* m : mods)
        std::cout << CLR_FAINT << "[ " << CLR_RESET << CLR_SILVER << m << CLR_FAINT << " ]  " << CLR_RESET;
    std::cout << "\n";
    std::cout << CLR_FAINT << "  ──────────────────────────────────────────────────────────────────\n" << CLR_RESET;
    std::cout << CLR_DARK_GREY << "  Type " << CLR_RESET << CLR_GLOW << "help" << CLR_RESET << CLR_DARK_GREY << " to list commands,  " << CLR_RESET << CLR_GLOW << "options" << CLR_RESET << CLR_DARK_GREY << " to review config,  " << CLR_RESET << CLR_GLOW << "connect" << CLR_RESET << CLR_DARK_GREY << " to bind.\n" << CLR_RESET;
    std::cout << CLR_FAINT << "  ══════════════════════════════════════════════════════════════════\n" << CLR_RESET << "\n";
}

static void usage(const char* prog) {
    std::cout << "\n" << CLR_FAINT << "  ══════════════════════════════════════════════════════════════════\n" << CLR_RESET;
    std::cout << CLR_BLOOD << CLR_BOLD << "  OXGEN  " << CLR_RESET << CLR_MUTED << "·  REPL Reference\n" << CLR_RESET;
    std::cout << CLR_FAINT << "  ══════════════════════════════════════════════════════════════════\n\n" << CLR_RESET;
    std::cout << CLR_DARK_GREY << "  STARTUP\n" << CLR_RESET;
    std::cout << CLR_FAINT << "  ──────────────────────────────────────────\n" << CLR_RESET;
    std::cout << "    " << CLR_SILVER << prog << CLR_RESET << CLR_MUTED << "\n\n" << CLR_RESET;
    std::cout << CLR_DARK_GREY << "  REPL COMMANDS\n" << CLR_RESET << CLR_FAINT << "  ──────────────────────────────────────────\n" << CLR_RESET;
    std::cout << CLR_MUTED << "    set <key> <value>   set DOMNAME, DCIP, DCPORT, SSL, DOMUSER, DOMPASS, CAIP, SRVIP, SRVPORT, OUTPUT\n";
    std::cout << "    connect             bind to the Domain Controller\n";
    std::cout << "    run <module|all>    execute enumeration\n";
    std::cout << "    options             show current config table\n";
    std::cout << "    help | menu         show the command reference\n";
    std::cout << "    modules             list available modules\n";
    std::cout << "    show config         dump raw LDAP config state\n";
    std::cout << "    disconnect          unbind / close LDAP session\n";
    std::cout << "    exit | quit         close OxGen\n" << CLR_RESET;
    std::cout << "\n" << CLR_FAINT << "  ══════════════════════════════════════════════════════════════════\n\n" << CLR_RESET;
}


namespace fs = std::filesystem;

enum class Module {
    NONE,
    ALL,
    USERS,
    GROUPS,
    COMPUTERS,
    NETWORK,
    DOMINFO,
    OUS,
    GPOS,
    CERTS,
    ACES
};

struct CLIArgs {
    LDAPConfig  ldap;
    Module      module = Module::NONE;
    std::string output_name;
};

struct ReplOptions {
    std::string dom_name;
    std::string dc_ip;
    std::string ca_ip;
    std::string dom_user;
    std::string dom_pass;
    std::string srv_ip;
    std::string srv_port;   // empty until user sets
    std::string file_type;  // "json" or "jsonl" — empty = default (jsonl)
    bool        dc_port_set = false;
};

static std::string to_upper_copy(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    return value;
}

static std::string domain_to_base_dn(const std::string& domain) {
    if (domain.empty()) {
        return {};
    }

    std::ostringstream out;
    std::stringstream ss(domain);
    std::string label;
    bool first = true;
    while (std::getline(ss, label, '.')) {
        if (label.empty()) {
            continue;
        }
        if (!first) {
            out << ',';
        }
        out << "DC=" << label;
        first = false;
    }
    return out.str();
}




static fs::path domain_objects_root() {
    return fs::current_path() / "Domain Objects";
}

static std::string module_default_filename(Module module) {
    switch (module) {
        case Module::USERS:     return "domain_users.jsonl";
        case Module::GROUPS:    return "domain_groups.jsonl";
        case Module::COMPUTERS: return "domain_computers.jsonl";
        case Module::NETWORK:   return "domain_network.jsonl";
        case Module::DOMINFO:   return "domain_info.jsonl";
        case Module::OUS:       return "domain_ous.jsonl";
        case Module::GPOS:      return "domain_gpos.jsonl";
        case Module::CERTS:     return "domain_certificates.jsonl";
        case Module::ACES:      return "domain_aces.jsonl";
        default:                return "domain_objects.jsonl";
    }
}

static fs::path output_file_for(Module module, const std::string& output_name) {
    fs::path filename = output_name.empty()
        ? fs::path(module_default_filename(module))
        : fs::path(output_name).filename();
    return domain_objects_root() / filename;
}

// Returns the correct file extension based on FILETYPE option.
// jsonl is the default; json wraps all records in a JSON array.
static std::string effective_ext(const std::string& file_type) {
    if (file_type == "json") return "json";
    return "jsonl"; // default
}

// Replaces the extension of a domain_*.jsonl path with the chosen one.
static int run_raw_user_passthrough(LDAPEngine& engine) {
    UserCollector uc(engine);
    if (uc.collect() < 0) {
        log_err("User collection failed");
        return -1;
    }

    fs::path src = fs::current_path() / "raw_cache" / "raw_users.jsonl";
    fs::path dst = domain_objects_root() / "domain_users.jsonl";
    if (!fs::exists(src)) {
        log_err("raw_users.jsonl not found: " + src.string());
        return -1;
    }

    fs::create_directories(dst.parent_path());
    std::error_code ec;
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        log_err("Failed to copy raw_users.jsonl to domain_users.jsonl: " + ec.message());
        return -1;
    }

    log_ok("Raw passthrough saved " + dst.string());
    return 0;
}

static int run_single_module(Module module, LDAPEngine& engine,
                              const fs::path& output_path,
                              const std::string& file_type = "") {
    const std::string ext = (file_type == "json") ? "json" : "jsonl";
    const std::string out_dir = output_path.parent_path().string();
    switch (module) {
        case Module::USERS: {
            UserCollector uc(engine);
            if (uc.collect() < 0) {
                log_err("User collection failed");
                return -1;
            }
            OfflineProcessor op;
            OfflineProcessorOptions opts;
            opts.output_dir = out_dir;
            opts.output_ext = ext;
            if (!op.process_users(opts)) {
                log_err("Offline user processing failed");
                return -1;
            }
            return 0;
        }
        case Module::COMPUTERS: {
            ComputerCollector cc(engine);
            if (cc.collect() < 0) {
                log_err("Computer collection failed");
                return -1;
            }
            OfflineProcessor op;
            OfflineProcessorOptions opts;
            opts.output_dir = out_dir;
            opts.output_ext = ext;
            if (!op.process_computers(opts)) {
                log_err("Offline computer processing failed");
                return -1;
            }
            return 0;
        }
        case Module::GROUPS: {
            GroupCollector gc(engine);
            if (gc.collect() < 0) {
                log_err("Group collection failed");
                return -1;
            }
            OfflineProcessor op;
            OfflineProcessorOptions opts;
            opts.output_dir = out_dir;
            opts.output_ext = ext;
            if (!op.process_groups(opts)) {
                log_err("Offline group processing failed");
                return -1;
            }
            return 0;
        }
        case Module::OUS: {
            OUCollector oc(engine);
            if (oc.collect() < 0) {
                log_err("OU collection failed");
                return -1;
            }
            OfflineProcessor op;
            OfflineProcessorOptions opts;
            opts.output_dir = out_dir;
            opts.output_ext = ext;
            if (!op.process_ous(opts)) {
                log_err("Offline OU processing failed");
                return -1;
            }
            return 0;
        }
        case Module::GPOS: {
            GPOCollector gc(engine);
            GPOCollectorOptions gc_opts;
            gc_opts.output_dir = "raw_cache";
            if (gc.collect(gc_opts) < 0) {
                log_err("GPO collection failed");
                return -1;
            }
            OfflineProcessor op;
            OfflineProcessorOptions opts;
            opts.output_dir = out_dir;
            opts.output_ext = ext;
            if (!op.process_gpos(opts)) {
                log_err("Offline GPO processing failed");
                return -1;
            }
            return 0;
        }
        case Module::NETWORK: {
            NetworkCollector nc;
            NetworkCollectorOptions nc_opts;
            nc_opts.output_dir = "raw_cache";
            if (nc.collect(nc_opts) < 0) {
                log_err("Network collection failed");
                return -1;
            }
            OfflineProcessor op;
            OfflineProcessorOptions opts;
            opts.output_dir = out_dir;
            opts.output_ext = ext;
            if (!op.process_network(opts)) {
                log_err("Offline network processing failed");
                return -1;
            }
            return 0;
        }
        case Module::CERTS: {
            CertificateCollector certc(engine);
            CertificateCollectorOptions cert_opts;
            cert_opts.output_dir = "raw_cache";
            if (certc.collect(cert_opts) < 0) {
                log_err("Certificate collection failed");
                return -1;
            }
            OfflineProcessor op;
            OfflineProcessorOptions opts;
            opts.raw_dir    = "raw_cache";
            opts.output_dir = out_dir;
            opts.output_ext = ext;
            if (!op.process_certificates(opts)) {
                log_err("Offline certificate processing failed");
                return -1;
            }
            return 0;
        }
        case Module::DOMINFO: {
            DomainInfoCollector dic(engine);
            DomainInfoCollectorOptions dic_opts;
            dic_opts.output_dir = "raw_cache";
            if (dic.collect(dic_opts) < 0) {
                log_err("Domain info collection failed");
                return -1;
            }
            OfflineProcessor op;
            OfflineProcessorOptions opts;
            opts.raw_dir    = "raw_cache";
            opts.output_dir = out_dir;
            opts.output_ext = ext;
            if (!op.process_domaininfo(opts)) {
                log_err("Offline domain info processing failed");
                return -1;
            }
            return 0;
        }
        case Module::ACES: {
            AceCollector ac(engine);
            if (ac.collect() < 0) {
                log_err("ACE collection failed");
                return -1;
            }
            OfflineProcessor op;
            OfflineProcessorOptions opts;
            opts.output_dir = out_dir;
            opts.output_ext = ext;
            if (!op.process_aces(opts)) {
                log_err("Offline ACE processing failed");
                return -1;
            }
            return 0;
        }
        default:
            return -1;
    }
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    if (argc > 1) {
        log_err("External CLI options are disabled. Start OxGen with no arguments and use the REPL commands.");
        usage(argv[0]);
        return 1;
    }

    // Start interactive console (REPL)
    if (argc < 2) {
        CLIArgs a;
        ReplOptions options;
        // Ensure SSL defaults to FALSE in interactive mode
        a.ldap.use_tls = false;
        a.ldap.port = 389;
        // Interactive console will print banner itself
        auto interactive_console = [&]() {
            print_banner();
            std::string line;
            std::unique_ptr<LDAPEngine> engine;
            bool connected = false;

            // ── Module completion tracker ─────────────────────────────────────
            // ZIP işə düşməsi üçün bütün 9 əsas modul tamamlanmalıdır.
            // (domain_info + trusts offline_processor içindən avtomatik yazılır,
            //  onlar ayrıca Module enum-unda izlənilmir)
            std::set<Module> completed_modules;
            const std::set<Module> ALL_TRACKABLE = {
                Module::USERS, Module::GROUPS, Module::COMPUTERS,
                Module::NETWORK, Module::DOMINFO, Module::OUS,
                Module::GPOS, Module::CERTS, Module::ACES,
            };

            // Bütün modullar tamamlandıqda ZIP qablaşdır
            auto try_autozip = [&]() {
                if (completed_modules != ALL_TRACKABLE) return;
                log_ok("All modules complete — packaging results...");
                fs::path zip_dir = domain_objects_root().parent_path();
                std::string zip_path = package_domain_objects(domain_objects_root(), zip_dir);
                if (!zip_path.empty()) {
                    log_ok("Packaged → " + zip_path);
                } else {
                    log_warn("ZIP packaging failed — raw files are still in Domain Objects/");
                }
                // Növbəti sessiya üçün sıfırla
                completed_modules.clear();
            };

            auto sync_ldap_from_options = [&]() {
                // bind_dn: sadə ad varsa UPN-ə çevir
                if (!options.dom_user.empty()) {
                    if (options.dom_user.find('@') == std::string::npos &&
                        options.dom_user.find('\\') == std::string::npos &&
                        !options.dom_name.empty())
                    {
                        a.ldap.bind_dn = options.dom_user + "@" + options.dom_name;
                    } else {
                        a.ldap.bind_dn = options.dom_user;
                    }
                }
                if (!options.dom_pass.empty()) {
                    a.ldap.password = options.dom_pass;
                }
                if (!options.dc_ip.empty()) {
                    a.ldap.host = options.dc_ip;
                }
                // QEYD: srv_port — C2 server portudur, LDAP portu deyil; buraya yazılmır
                if (!options.dom_name.empty()) {
                    a.ldap.base_dn = domain_to_base_dn(options.dom_name);
                }
            };

                auto print_options = [&]() {
                // ── color aliases (local, no header pollution) ──────────────
                const char* C_HEAD  = "\033[38;5;160m";   // blood red  – section title
                const char* C_KEY   = "\033[38;5;203m";   // ember      – option name
                const char* C_VAL   = "\033[97m";         // bright white – value
                const char* C_EMPTY = "\033[38;5;240m";   // dark grey  – <not set>
                const char* C_REQ   = "\033[38;5;160m";   // blood red  – Required tag
                const char* C_OPT   = "\033[38;5;244m";   // muted grey – Optional tag
                const char* C_LINE  = "\033[38;5;236m";   // faint      – separator
                const char* C_RST   = "\033[0m";

                struct OptionRow {
                    std::string key;
                    std::string value;
                    bool        required;
                    std::string desc;
                };

                auto print_section = [&](const char* title,
                                         const std::vector<OptionRow>& rows) {
                    std::cout << "\n";
                    std::cout << C_LINE
                              << "  ┌─────────────────────────────────────────────────────────────┐\n"
                              << "  │  " << C_RST << C_HEAD << title
                              << C_RST << C_LINE;
                    // pad title to fill box width (63 inner chars)
                    int pad = 57 - (int)std::string(title).size();
                    if (pad > 0) std::cout << std::string(pad, ' ');
                    std::cout << "│\n";
                    std::cout << "  ├──────────────┬───────────────────────────┬────────────────┤\n"
                              << "  │  " << C_RST << C_OPT << "OPTION        "
                              << C_LINE << "│  " << C_RST << C_OPT << "VALUE                      "
                              << C_LINE << "│  " << C_RST << C_OPT << "STATUS        "
                              << C_LINE << "│\n"
                              << "  ├──────────────┼───────────────────────────┼────────────────┤\n"
                              << C_RST;

                    for (const auto& row : rows) {
                        std::string display_val = row.value.empty() ? "<not set>" : row.value;
                        const char* val_color   = row.value.empty() ? C_EMPTY : C_VAL;
                        const char* req_color   = row.required      ? C_REQ   : C_OPT;
                        const char* req_label   = row.required      ? "Required" : "Optional";

                        // key – pad to 12
                        std::string kpad = row.key;
                        while ((int)kpad.size() < 12) kpad += ' ';

                        // value – pad to 25
                        std::string vpad = display_val;
                        if ((int)vpad.size() > 25) vpad = vpad.substr(0, 22) + "...";
                        while ((int)vpad.size() < 25) vpad += ' ';

                        // status – pad to 12
                        std::string spad = req_label;
                        while ((int)spad.size() < 12) spad += ' ';

                        std::cout << C_LINE << "  │  " << C_RST
                                  << C_KEY  << kpad   << C_RST
                                  << C_LINE << "  │  " << C_RST
                                  << val_color << vpad << C_RST
                                  << C_LINE << "  │  " << C_RST
                                  << req_color << spad << C_RST
                                  << C_LINE << "  │\n" << C_RST;
                    }
                    std::cout << C_LINE
                              << "  └──────────────┴───────────────────────────┴────────────────┘\n"
                              << C_RST;
                };

                std::vector<OptionRow> agent_rows = {
                    {"DOMNAME",  options.dom_name,                                        true,  ""},
                    {"DCIP",     options.dc_ip,                                           true,  ""},
                    {"CAIP",     options.ca_ip,                                           false, ""},
                    {"DCPORT",   std::to_string(a.ldap.port),                             true,  ""},
                    {"SSL",      a.ldap.use_tls ? "TRUE" : "FALSE",                       false, ""},
                    {"DOMUSER",  options.dom_user,                                        true,  ""},
                    {"DOMPASS",  options.dom_pass.empty() ? "" : std::string(options.dom_pass.size(), '*'), true, ""},
                    {"FILETYPE", options.file_type.empty() ? "jsonl (default)" : options.file_type, false, ""},
                };

                std::vector<OptionRow> c2_rows = {
                    {"SRVIP",   options.srv_ip,   true,  ""},
                    {"SRVPORT", options.srv_port, true,  ""},
                };

                print_section("  Agent Configuration", agent_rows);
                print_section("  C2 Connection", c2_rows);
                std::cout << "\n";
            };

            auto repl_help = [&]() {
                const char* C_LINE  = "\033[38;5;236m";
                const char* C_HEAD  = "\033[38;5;160m";
                const char* C_CMD   = "\033[38;5;203m";
                const char* C_ARG   = "\033[38;5;244m";
                const char* C_DESC  = "\033[38;5;250m";
                const char* C_RST   = "\033[0m";

                std::cout << "\n";
                std::cout << C_LINE
                          << "  ┌──────────────────────────────────────────────────────────────┐\n"
                          << "  │  " << C_RST << C_HEAD << "  Command Reference"
                          << C_RST << C_LINE << "                                              │\n"
                          << "  ├────────────────────────────┬─────────────────────────────────┤\n"
                          << "  │  " << C_RST << C_ARG << "COMMAND                     "
                          << C_LINE << "│  " << C_RST << C_ARG << "DESCRIPTION                      "
                          << C_LINE << "│\n"
                          << "  ├────────────────────────────┼─────────────────────────────────┤\n"
                          << C_RST;

                auto row = [&](const char* cmd_str, const char* desc_str) {
                    std::string c(cmd_str), d(desc_str);
                    while ((int)c.size() < 26) c += ' ';
                    while ((int)d.size() < 31) d += ' ';
                    std::cout << C_LINE << "  │  " << C_RST
                              << C_CMD  << c << C_RST
                              << C_LINE << "  │  " << C_RST
                              << C_DESC << d << C_RST
                              << C_LINE << "  │\n" << C_RST;
                };

                row("set <key> <value>",    "Set a configuration key");
                row("options",              "Show current config table");
                row("connect",              "Bind to the Domain Controller");
                row("disconnect",           "Unbind / close LDAP session");
                row("run <module|all>",     "Execute enumeration module");
                row("raw user",             "raw_users.jsonl -> domain_users.jsonl");
                row("modules",              "List available modules");
                row("show config",          "Dump raw LDAP config state");
                row("help  |  menu",        "Show this reference");
                row("exit  |  quit",        "Exit OxGen console");

                std::cout << C_LINE
                          << "  ├────────────────────────────┴─────────────────────────────────┤\n"
                          << "  │  " << C_RST << C_ARG
                          << "  Modules: user  group  computer  network  ou  gpo  cert  acl  dominfo  all"
                          << C_LINE << "  │\n"
                          << "  └──────────────────────────────────────────────────────────────┘\n"
                          << C_RST;
                std::cout << "\n";
            };

            while (true) {
                // Status indicator
                const char* status_clr = connected ? "\033[38;5;28m" : "\033[38;5;240m";
                const char* status_sym = connected ? "●" : "○";
                std::cout << "\033[38;5;236m" << " ╔═" << "\033[0m"
                          << "\033[38;5;160m\033[1m" << " OxGen " << "\033[0m"
                          << "\033[38;5;236m" << "·" << "\033[0m"
                          << "\033[38;5;244m" << " v.12 " << "\033[0m"
                          << status_clr << status_sym << "\033[0m"
                          << "\033[38;5;236m" << " ═╗ " << "\033[0m"
                          << "\033[38;5;203m" << "> " << "\033[0m";
                if (!std::getline(std::cin, line)) break;
                std::istringstream iss(line);
                std::string cmd;
                if (!(iss >> cmd)) continue;

                // make command matching case-insensitive
                std::string lc_cmd = cmd;
                for (char &c : lc_cmd) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                if (lc_cmd == "exit" || lc_cmd == "quit") break;
                else if (lc_cmd == "help" || lc_cmd == "menu") { repl_help(); continue; }
                else if (lc_cmd == "options") { print_options(); continue; }
                else if (lc_cmd == "status") {
                    if (engine && engine->is_connected()) {
                        log_ok("LDAP: connected to " + a.ldap.host + ":" + std::to_string(a.ldap.port) + " as " + a.ldap.bind_dn);
                    } else if (engine) {
                        log_warn(std::string("LDAP: not connected. Last error: ") + engine->last_error());
                    } else {
                        log_warn("LDAP engine not initialized");
                    }
                    continue;
                }
                else if (lc_cmd == "modules") {
                    const char* C_LINE = "\033[38;5;236m";
                    const char* C_MOD  = "\033[38;5;203m";
                    const char* C_RST  = "\033[0m";
                    std::cout << "\n";
                    std::cout << C_LINE << "  ┌──────────────────────────────────┐\n"
                              << "  │  " << C_RST << "\033[38;5;160m" << "  Available Modules        "
                              << C_LINE << "     │\n"
                              << "  ├──────────────────────────────────┤\n" << C_RST;
                    const char* mlist[] = {
                        "user", "group", "computer", "network", "organizational-unit",
                        "group-policy", "certificate", "access-control-list",
                        "dominfo", "all"
                    };
                    for (const char* m : mlist) {
                        std::string ms(m);
                        while ((int)ms.size() < 28) ms += ' ';
                        std::cout << C_LINE << "  │  " << C_RST
                                  << C_MOD  << "  " << ms << C_RST
                                  << C_LINE << "  │\n" << C_RST;
                    }
                    std::cout << C_LINE << "  └──────────────────────────────────┘\n" << C_RST;
                    std::cout << "\n";
                    continue;
                }
                else if (lc_cmd == "set") {
                    // Support multiple comma-separated key value pairs on one line.
                    // Examples:
                    //   set DOMNAME example.local, DCIP 10.0.0.1, DOMUSER Administrator, DOMPASS secret
                    std::string rest;
                    std::getline(iss, rest);
                    if (rest.empty()) { log_err("set requires at least one key/value pair"); continue; }

                    bool connection_state_changed = false;

                    // helper trims (avoid <algorithm> dependence)
                    auto ltrim = [](std::string &s){ size_t i = 0; while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i; s.erase(0, i); };
                    auto rtrim = [](std::string &s){ size_t i = s.size(); while (i > 0 && std::isspace(static_cast<unsigned char>(s[i-1]))) --i; s.erase(i); };
                    auto trim = [&](std::string s){ ltrim(s); rtrim(s); return s; };

                    // split by commas
                    size_t pos = 0;
                    while (pos < rest.size()) {
                        size_t comma = rest.find(',', pos);
                        std::string token = (comma == std::string::npos) ? rest.substr(pos) : rest.substr(pos, comma - pos);
                        pos = (comma == std::string::npos) ? rest.size() : comma + 1;
                        token = trim(token);
                        if (token.empty()) continue;

                        // find separator: '=' or first whitespace
                        std::string key, val;
                        size_t eq = token.find('=');
                        if (eq != std::string::npos) {
                            key = trim(token.substr(0, eq));
                            val = trim(token.substr(eq + 1));
                        } else {
                            // split on first whitespace
                            size_t sp = token.find_first_of(" \t");
                            if (sp == std::string::npos) {
                                log_warn("Invalid set token (no value): " + token);
                                continue;
                            }
                            key = trim(token.substr(0, sp));
                            val = trim(token.substr(sp + 1));
                        }

                        std::string upper_key = to_upper_copy(key);
                        if (upper_key == "DOMNAME") {
                            options.dom_name = val;
                            a.ldap.base_dn = domain_to_base_dn(options.dom_name);
                            log_ok("DOMNAME set to " + options.dom_name);
                            connection_state_changed = true;
                            // Əgər DOMUSER artıq sadə ad olaraq yazılmışsa, bind_dn-i yenilə
                            if (!options.dom_user.empty() &&
                                options.dom_user.find('@') == std::string::npos &&
                                options.dom_user.find('\\') == std::string::npos)
                            {
                                a.ldap.bind_dn = options.dom_user + "@" + options.dom_name;
                                log_ok("bind DN yeniləndi: " + a.ldap.bind_dn);
                            }
                        }
                        else if (upper_key == "DCIP") {
                            options.dc_ip = val;
                            a.ldap.host = options.dc_ip;
                            log_ok("DCIP set to " + options.dc_ip);
                            connection_state_changed = true;
                        }
                        else if (upper_key == "CAIP") {
                            options.ca_ip = val;
                            log_ok("CAIP set to " + options.ca_ip);
                        }
                        else if (upper_key == "DCPORT") {
                            try { a.ldap.port = std::stoi(val); options.dc_port_set = true; } catch(...){ }
                            log_ok("DCPORT set to " + std::to_string(a.ldap.port));
                        }
                        else if (upper_key == "SSL") {
                            std::string v = to_upper_copy(val);
                            bool new_ssl = (v == "ON" || v == "TRUE");
                            a.ldap.use_tls = new_ssl;
                            // If user hasn't explicitly set DCPORT, switch to the
                            // conventional port for the selected protocol, but
                            // allow the user to override afterwards.
                            if (!options.dc_port_set) {
                                a.ldap.port = a.ldap.use_tls ? 636 : 389;
                            }
                            log_ok(std::string("ssl set to ") + (a.ldap.use_tls ? "TRUE" : "FALSE"));
                        }
                        else if (upper_key == "DOMUSER") {
                            options.dom_user = val;
                            connection_state_changed = true;
                            // Əgər istifadəçi sadə ad yazmışsa (@ və \ yoxdur),
                            // DOMNAME əsasında UPN formatına çevir: user@domain.local
                            if (val.find('@') == std::string::npos &&
                                val.find('\\') == std::string::npos)
                            {
                                if (!options.dom_name.empty()) {
                                    a.ldap.bind_dn = val + "@" + options.dom_name;
                                    log_ok("DOMUSER set to " + options.dom_user
                                           + "  →  bind DN: " + a.ldap.bind_dn);
                                } else {
                                    a.ldap.bind_dn = val;
                                    log_ok("DOMUSER set to " + options.dom_user
                                           + "  (DOMNAME hələ təyin edilməyib — tam format istifadə edin)");
                                }
                            } else {
                                // İstifadəçi artıq tam format yazıb (UPN və ya DOMAIN\user)
                                a.ldap.bind_dn = val;
                                log_ok("DOMUSER set to " + options.dom_user);
                            }
                        }
                        else if (upper_key == "DOMPASS") {
                            options.dom_pass = val;
                            a.ldap.password = options.dom_pass;
                            log_ok("DOMPASS set to " + options.dom_pass);
                            connection_state_changed = true;
                        }
                        else if (upper_key == "OUTPUT") { a.output_name = val; log_ok("output set to " + a.output_name); }
                        else if (upper_key == "FILETYPE") {
                            std::string ft = val;
                            for (char& c : ft) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                            if (ft == "json" || ft == "jsonl") {
                                options.file_type = ft;
                                log_ok("FILETYPE set to " + options.file_type);
                            } else {
                                log_warn("FILETYPE must be 'json' or 'jsonl' — keeping current value");
                            }
                        }
                        else if (upper_key == "SRVIP") { options.srv_ip = val; log_ok("SRVIP set to " + options.srv_ip); }
                        else if (upper_key == "SRVPORT") { try { int p = std::stoi(val); options.srv_port = std::to_string(p); } catch(...){} log_ok("SRVPORT set to " + options.srv_port); }
                        else { log_warn("Unknown set key: " + key); }
                    }

                    // If a connection is active, close it when credentials / target change.
                    if (engine && connected && connection_state_changed) {
                        engine->disconnect();
                        engine.reset();
                        connected = false;
                        log_warn("Connection closed because LDAP connection settings changed. Reconnect required.");
                    } else {
                        if (!options.dom_name.empty() && !options.dc_ip.empty()
                            && !options.dom_user.empty() && !options.dom_pass.empty())
                        {
                            // Intentionally silent when all options are set; user should run 'connect' manually.
                        }
                    }
                    continue;
                }
                else if (cmd == "show") {
                    std::string sub; iss >> sub;
                    if (sub == "config") {
                        const char* C_LINE = "\033[38;5;236m";
                        const char* C_KEY  = "\033[38;5;203m";
                        const char* C_VAL  = "\033[97m";
                        const char* C_NONE = "\033[38;5;240m";
                        const char* C_RST  = "\033[0m";
                        auto cfg_row = [&](const char* k, const std::string& v) {
                            std::string ks(k); while ((int)ks.size() < 8) ks += ' ';
                            bool empty = v.empty();
                            std::cout << C_LINE << "  │  " << C_RST
                                      << C_KEY << ks << C_RST
                                      << C_LINE << "  " << C_RST
                                      << (empty ? C_NONE : C_VAL)
                                      << (empty ? "<not set>" : v) << C_RST << "\n";
                        };
                        std::cout << "\n" << C_LINE
                                  << "  ┌──────────────────────────────────────┐\n"
                                  << "  │  \033[38;5;160m  LDAP Config State"
                                  << C_RST << C_LINE << "                    │\n"
                                  << "  ├──────────────────────────────────────┤\n" << C_RST;
                        cfg_row("host",   a.ldap.host);
                        cfg_row("port",   std::to_string(a.ldap.port));
                        cfg_row("ssl",    a.ldap.use_tls ? "TRUE" : "FALSE");
                        cfg_row("bind",   a.ldap.bind_dn);
                        cfg_row("base",   a.ldap.base_dn);
                        cfg_row("output", a.output_name);
                        std::cout << C_LINE << "  └──────────────────────────────────────┘\n" << C_RST;
                        std::cout << "\n";
                    } else if (sub == "modules") {
                        std::cout << "\033[38;5;244m" << "modules: user, group, computer, network, ou, gpo, certificate, acl, dominfo, all\n" << "\033[0m";
                    } else {
                        log_warn("Unknown show subcommand");
                    }
                    continue;
                }
                else if (cmd == "connect") {
                    sync_ldap_from_options();
                    engine.reset(new LDAPEngine(a.ldap));
                    if (!engine->connect()) {
                        log_err(std::string("Connect failed: ") + engine->last_error());
                        engine.reset();
                        connected = false;
                    }
                    else {
                        connected = true;
                        if (a.ldap.base_dn.empty()) {
                            if (engine->discover_base()) {
                                a.ldap.base_dn = engine->cfg_.base_dn;
                                log_ok("Discovered base DN: " + a.ldap.base_dn);
                            } else {
                                log_warn("Base DN discovery failed");
                            }
                        }
                    }
                    continue;
                }
                else if (cmd == "disconnect") {
                    if (engine && connected) { engine->disconnect(); engine.reset(); connected = false; log_ok("Disconnected"); }
                    else log_warn("Not connected");
                    continue;
                }
                else if (cmd == "run") {
                    std::string target; iss >> target; if (target.empty()) { log_err("run requires a module or 'all'"); continue; }
                    if (!engine || !connected) { log_err("Not connected — use 'connect' first"); continue; }

                    if (target == "all") {
                        DomainInfoCollector dic(*engine);
                        AceCollector ac(*engine);
                        TrustCollector tc(*engine);
                        GPOCollector gpc(*engine);
                        OUCollector oc(*engine);
                        GroupCollector gc(*engine);
                        ComputerCollector cc(*engine);
                        UserCollector uc(*engine);
                        CertificateCollector certc(*engine);

                        DomainInfoCollectorOptions dic_opts;
                        dic_opts.output_dir = "raw_cache";
                        if (dic.collect(dic_opts) < 0) { log_err("Domain info collection failed"); continue; }

                        if (ac.collect() < 0) { log_err("ACE collection failed"); continue; }

                        TrustCollectorOptions tc_opts;
                        tc_opts.output_dir = "raw_cache";
                        if (tc.collect(tc_opts) < 0) { log_warn("Trust collection failed or no trusts found"); }

                        if (gpc.collect() < 0) { log_err("GPO collection failed"); continue; }
                        if (oc.collect() < 0) { log_err("OU collection failed"); continue; }
                        if (gc.collect() < 0) { log_err("Group collection failed"); continue; }
                        if (cc.collect() < 0) { log_err("Computer collection failed"); continue; }
                        if (uc.collect() < 0) { log_err("User collection failed"); continue; }

                        CertificateCollectorOptions cert_opts;
                        cert_opts.output_dir = "raw_cache";
                        if (certc.collect(cert_opts) < 0) { log_err("Certificate collection failed"); continue; }

                        NetworkCollector netc;
                        NetworkCollectorOptions net_opts;
                        net_opts.output_dir = "raw_cache";
                        if (netc.collect(net_opts) < 0) { log_err("Network collection failed"); continue; }

                        OfflineProcessor op;
                        OfflineProcessorOptions opts;
                        opts.raw_dir    = "raw_cache";
                        opts.output_dir = domain_objects_root().string();
                        opts.output_ext = effective_ext(options.file_type);

                        // Offline processing nəticəsi (tam uğurlu/qismən uğursuz) ZIP-ləməyə
                        // mane olmasın. Tək bir modulun uğursuzluğu (məs. boş cert/pki faylları)
                        // digər modulların artıq yazılmış nəticələrinin ZIP-lənməsini bloklamamalıdır —
                        // Domain Objects/ qovluğunda nə qədər fayl varsa, hamısı qablaşdırılır.
                        bool process_ok = op.process(opts);
                        if (!process_ok) {
                            log_warn("Offline processing reported some failures — packaging available files anyway");
                        }

                        const std::string& ext = opts.output_ext;
                        log_ok("Saved " + (domain_objects_root() / ("domain_users."          + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_groups."         + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_aces."           + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_computers."      + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_ous."            + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_gpos."           + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_network."        + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_cert_templates." + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_pki_objects."    + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_info." + ext)).string());
                        log_ok("Saved " + (domain_objects_root() / ("domain_trusts." + ext)).string());

                        // ── Package whatever exists in Domain Objects/ into oxgen_<RANDOM_ID>.zip ────────
                        {
                            fs::path zip_dir = domain_objects_root().parent_path();
                            std::string zip_path = package_domain_objects(domain_objects_root(), zip_dir);
                            if (!zip_path.empty()) {
                                log_ok("Packaged → " + zip_path);
                            } else {
                                log_warn("ZIP packaging failed — raw files are still in Domain Objects/");
                            }
                            // run all tamamlandıqdan sonra tək-tək tracker-i
                            // ALL_TRACKABLE ilə sinxronlaşdır, sonra sıfırla
                            // ki, növbəti tək-tək run sessiyası sıfırdan başlasın.
                            completed_modules = ALL_TRACKABLE;
                            completed_modules.clear();
                        }

                        bool run_all_ok = process_ok;
                        if (!run_all_ok) continue;
                    } else {
                        Module m = Module::NONE;
                        if (target == "raw") {
                            std::string raw_target;
                            iss >> raw_target;
                            if (raw_target == "user") {
                                int rc = run_raw_user_passthrough(*engine);
                                if (rc < 0) log_err("Raw user run failed");
                            } else {
                                log_err("Only 'run raw user' is supported for now");
                            }
                            continue;
                        }

                        if (target == "user") m = Module::USERS;
                        else if (target == "group") m = Module::GROUPS;
                        else if (target == "computer") m = Module::COMPUTERS;
                        else if (target == "network" || target == "net") m = Module::NETWORK;
                        else if (target == "ou" || target == "organizational-unit") m = Module::OUS;
                        else if (target == "gpo" || target == "group-policy") m = Module::GPOS;
                        else if (target == "cert" || target == "certificate") m = Module::CERTS;
                        else if (target == "acl" || target == "access-control-list") m = Module::ACES;
                        else if (target == "dominfo" || target == "info") m = Module::DOMINFO;
                        else { log_err("Unknown module: " + target); continue; }

                        fs::path out = output_file_for(m, a.output_name);
                        int rc = run_single_module(m, *engine, out, options.file_type);
                        if (rc < 0) {
                            log_err("Module run failed");
                        } else {
                            log_ok("Saved " + out.string());
                            // Tamamlanan modulu izlə
                            if (ALL_TRACKABLE.count(m)) {
                                completed_modules.insert(m);
                                int done  = static_cast<int>(completed_modules.size());
                                int total = static_cast<int>(ALL_TRACKABLE.size());
                                log_ok("Progress: " + std::to_string(done) + "/" +
                                       std::to_string(total) + " modules complete");
                                try_autozip();
                            }
                        }
                    }
                    continue;
                }
                else if (lc_cmd == "raw") {
                    std::string target; iss >> target;
                    if (target.empty()) { log_err("raw requires a module, e.g. raw user"); continue; }
                    if (!engine || !connected) { log_err("Not connected — use 'connect' first"); continue; }

                    if (target == "user") {
                        int rc = run_raw_user_passthrough(*engine);
                        if (rc < 0) log_err("Raw user run failed");
                    } else {
                        log_err("Only 'raw user' is supported for now");
                    }
                    continue;
                }
                else {
                    std::cout << "\n";
                    std::cout << "\033[38;5;160m" << "  [-] " << "\033[0m"
                              << "\033[38;5;250m" << "Unknown command: "
                              << "\033[38;5;203m" << cmd << "\033[0m"
                              << "\033[38;5;244m" << "  —  type "
                              << "\033[38;5;203m" << "help"
                              << "\033[38;5;244m" << " for a command list.\n" << "\033[0m";
                    std::cout << "\n";
                    continue;
                }
            }
            if (engine && connected) engine->disconnect();
        };
        interactive_console();
        return 0;
    }
}