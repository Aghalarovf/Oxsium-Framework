#pragma once
#include "../../include/core.h"
#include <filesystem>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  NetworkCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct NetworkCollectorOptions {
    std::string output_dir       = "raw_cache";
    std::string target_cidr      = "";          // e.g. "192.168.1.0/24"  — auto-detect if empty
    int         ping_timeout_ms  = 1000;        // ICMP ping timeout per host
    int         arp_timeout_ms   = 500;         // ARP probe timeout per host
    int         port_timeout_ms  = 800;         // TCP connect timeout per port
    int         max_threads      = 64;          // parallel scan threads
    bool        skip_ping        = false;       // skip ICMP, use ARP-only discovery
    bool        skip_port_scan   = false;       // only discover hosts, no port scan
    bool        skip_version_det = false;       // skip banner grabbing / version detection
    bool        skip_os_fp       = false;       // skip OS fingerprinting
    // Port scan range — defaults cover well-known + common service ports
    std::vector<uint16_t> ports  = {};          // empty = use DEFAULT_PORTS table
};

// ─────────────────────────────────────────────────────────────────────────────
//  NetworkHost  — one discovered host (written to raw_network.jsonl)
// ─────────────────────────────────────────────────────────────────────────────
struct NetworkHost {
    // ── Discovery ────────────────────────────────────────────────────────────
    std::string ipv4;               // "192.168.1.10"
    std::string mac;                // "aa:bb:cc:dd:ee:ff"  (from ARP, empty if N/A)
    std::string mac_vendor;         // "Dell Inc."          (from OUI lookup)
    std::string hostname;           // rDNS name, empty if not resolved
    bool        ping_ok  = false;   // responded to ICMP echo
    bool        arp_ok   = false;   // responded to ARP probe

    // ── Open ports ───────────────────────────────────────────────────────────
    struct PortInfo {
        uint16_t    port        = 0;
        std::string protocol    = "tcp";    // "tcp" | "udp"
        std::string state       = "open";   // "open" | "filtered"
        std::string service_name;           // from DEFAULT_PORTS table
        std::string banner;                 // raw banner (first 256 bytes)
        std::string version;               // parsed version string
        std::string extra_info;            // e.g. "protocol 2.0"
    };
    std::vector<PortInfo> open_ports;
    int open_port_count = 0;

    // ── OS Fingerprint ────────────────────────────────────────────────────────
    std::string os_guess;           // "Windows", "Linux", "macOS", "IoT", "unknown"
    std::string os_detail;          // "Linux 4.x / 5.x"
    int         os_confidence = 0;  // 0-100

    // ── TTL-based heuristics ──────────────────────────────────────────────────
    int  ttl          = 0;          // last observed TTL from ICMP/TCP response
    bool ttl_windows  = false;      // TTL >= 100 && < 140  → likely Windows
    bool ttl_linux    = false;      // TTL >= 50 && < 70    → likely Linux/Unix
    bool ttl_cisco    = false;      // TTL == 255           → likely network device

    // ── TCP/IP Stack fingerprint fields (OS detection) ────────────────────────
    int  tcp_window_size  = 0;       // from SYN-ACK
    bool df_bit           = false;   // Don't Fragment bit observed
    int  ip_id_strategy   = 0;       // 0=zero, 1=sequential, 2=random (IPid probe)

    // ── Metadata ─────────────────────────────────────────────────────────────
    std::string generated_at;       // ISO-8601 scan timestamp
    std::string scan_duration_ms;   // time to scan this host
};

// ─────────────────────────────────────────────────────────────────────────────
//  NetworkCollector  — Phase 1 / Collect
//
//  Pipeline:
//    1. Discover active hosts  : ICMP ping sweep + ARP scan
//    2. Port scan              : TCP SYN-connect scan on discovered hosts
//    3. Service ID             : offline lookup in DEFAULT_PORTS table
//    4. Version detection      : banner grabbing / protocol negotiation
//    5. OS fingerprinting      : TTL + TCP-window + banner heuristics
//
//  Output: raw_network.jsonl  — one host object per line.
//
//  Output schema (raw_network.jsonl):
//
//  {
//    "ipv4"            : "192.168.1.10",
//    "mac"             : "aa:bb:cc:dd:ee:ff",
//    "mac_vendor"      : "Dell Inc.",
//    "hostname"        : "workstation01.corp.local",
//    "ping_ok"         : true,
//    "arp_ok"          : true,
//    "open_ports"      : [
//      {
//        "port"         : 22,
//        "protocol"     : "tcp",
//        "state"        : "open",
//        "service_name" : "ssh",
//        "banner"       : "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
//        "version"      : "OpenSSH 8.2p1",
//        "extra_info"   : "Ubuntu-4ubuntu0.5"
//      }, ...
//    ],
//    "open_port_count" : 3,
//    "os_guess"        : "Linux",
//    "os_detail"       : "Linux 4.x / 5.x",
//    "os_confidence"   : 80,
//    "ttl"             : 64,
//    "generated_at"    : "2026-06-01T10:00:00Z"
//  }
//
//  OfflineProcessor (network processor module) reads raw_network.jsonl and
//  produces domain_network.jsonl with enriched risk analysis.
// ─────────────────────────────────────────────────────────────────────────────
class NetworkCollector {
public:
    NetworkCollector() = default;

    // Main entry point
    int  collect(const NetworkCollectorOptions& opts = {});

    fs::path output_path() const { return output_path_; }

    // ── Exposed for testing / offline processor integration ──────────────────
    static std::string detect_os_from_host(const NetworkHost& h);
    static std::string service_name_for_port(uint16_t port, const std::string& proto = "tcp");

private:
    fs::path output_path_;

    // ── Stage 1 — Host discovery ──────────────────────────────────────────────
    // Returns list of active IPs (ping OR arp responded)
    std::vector<std::string> discover_hosts(const NetworkCollectorOptions& opts) const;
    bool                     ping_host     (const std::string& ip, int timeout_ms,
                                            int& out_ttl) const;
    bool                     arp_probe     (const std::string& ip, int timeout_ms,
                                            std::string& out_mac) const;
    // Expands CIDR to list of host IPs (excludes network + broadcast)
    static std::vector<std::string> cidr_to_ips(const std::string& cidr);
    // Auto-detect local network CIDR from default interface
    static std::string auto_detect_cidr();
    // Reverse DNS lookup — returns hostname or empty string
    static std::string rdns_lookup(const std::string& ip);
    // OUI → vendor (first 3 bytes of MAC → vendor string)
    static std::string mac_to_vendor(const std::string& mac);

    // ── Stage 2 — Port scan ───────────────────────────────────────────────────
    void scan_ports(NetworkHost& host, const NetworkCollectorOptions& opts) const;
    // Returns true if port is open/connectable within timeout
    bool tcp_connect_probe(const std::string& ip, uint16_t port, int timeout_ms,
                           std::string& out_banner) const;

    // ── Stage 3 — Service identification (offline) ────────────────────────────
    // Fills service_name from DEFAULT_PORTS table
    static void identify_services(NetworkHost& host);

    // ── Stage 4 — Version detection ───────────────────────────────────────────
    // Banner parsing: extracts version string from raw banner
    static void detect_versions(NetworkHost& host);
    static std::string parse_ssh_banner   (const std::string& banner);
    static std::string parse_http_banner  (const std::string& banner);
    static std::string parse_ftp_banner   (const std::string& banner);
    static std::string parse_smtp_banner  (const std::string& banner);
    static std::string parse_rdp_banner   (const std::string& banner);
    static std::string parse_smb_banner   (const std::string& banner);
    // Generic: tries to extract "Product/version" or "Product version x.y.z"
    static std::string parse_generic_banner(const std::string& banner);

    // ── Stage 5 — OS fingerprinting ───────────────────────────────────────────
    static void fingerprint_os(NetworkHost& host);
    // TTL-based guess: 64=Linux, 128=Windows, 255=Cisco/network device
    static std::string os_from_ttl(int ttl, int& out_confidence);
    // Banner-based override: SSH banner can reveal OS ("Ubuntu", "Debian", etc.)
    static std::string os_from_banners(const NetworkHost& host, int& out_confidence);
    // TCP window size heuristic
    static std::string os_from_window_size(int window_size, int& out_confidence);

    // ── Port list defaults ────────────────────────────────────────────────────
    static const std::vector<uint16_t>& default_ports();

    // ── DEFAULT_PORTS table ────────────────────────────────────────────────────
    // Maps port number → service name string
    // Very large static map covering 1000+ well-known ports
    struct PortDef { uint16_t port; const char* proto; const char* service; };
    static const PortDef DEFAULT_PORTS[];
    static const size_t  DEFAULT_PORTS_COUNT;

    // ── JSONL writer ─────────────────────────────────────────────────────────
    static std::string host_to_jsonl(const NetworkHost& h);

    // ── JSON helpers (same pattern as ComputerCollector / OfflineProcessor) ──
    static std::string je (const std::string& s);
    static std::string jb (bool v);
    static std::string ji (int v);
    static std::string jnull();
    static std::string ja (const std::vector<std::string>& v);
    static std::string now_iso8601();
};

// ─────────────────────────────────────────────────────────────────────────────
//  NetworkProcessorOptions  (for OfflineProcessor integration)
// ─────────────────────────────────────────────────────────────────────────────
struct NetworkProcessorOptions {
    std::string raw_dir    = "raw_cache";       // reads raw_network.jsonl
    std::string output_dir = "Domain Objects";  // writes domain_network.jsonl
};

// ─────────────────────────────────────────────────────────────────────────────
//  ProcessedNetworkHost  — enriched host for OfflineProcessor
//
//  OfflineProcessor reads raw_network.jsonl and produces domain_network.jsonl.
//  This struct carries the enriched/correlated fields.
// ─────────────────────────────────────────────────────────────────────────────
struct ProcessedNetworkHost {
    // ── Forwarded from raw ────────────────────────────────────────────────────
    std::string ipv4;
    std::string mac;
    std::string mac_vendor;
    std::string hostname;
    bool        ping_ok        = false;
    bool        arp_ok         = false;
    int         open_port_count= 0;
    std::string os_guess;
    std::string os_detail;
    int         os_confidence  = 0;
    int         ttl            = 0;

    // ── Open ports (forwarded) ────────────────────────────────────────────────
    std::vector<NetworkHost::PortInfo> open_ports;

    // ── Correlated with AD (from raw_computers.jsonl) ────────────────────────
    std::string ad_computer_name;       // matched computer_name from AD
    std::string ad_dn;                  // Distinguished Name in AD
    std::string ad_sid;                 // SID from AD
    std::string ad_os;                  // OS from AD record
    bool        ad_matched     = false; // true if this IP correlates to AD object

    // ── Risk analysis ─────────────────────────────────────────────────────────
    int                      risk_score   = 0;      // 0-100 composite
    bool                     high_risk    = false;
    std::vector<std::string> risk_factors;          // human-readable contributing factors

    // ── Notable service flags ─────────────────────────────────────────────────
    bool has_smb          = false;   // port 445 open
    bool has_rdp          = false;   // port 3389 open
    bool has_ssh          = false;   // port 22 open
    bool has_winrm        = false;   // port 5985 / 5986 open
    bool has_ldap         = false;   // port 389 / 636 open
    bool has_http         = false;   // port 80 / 443 / 8080 / 8443
    bool has_ftp          = false;   // port 21 open
    bool has_telnet       = false;   // port 23 open
    bool has_snmp         = false;   // port 161 / 162 open
    bool has_mssql        = false;   // port 1433 open
    bool has_mysql        = false;   // port 3306 open
    bool has_rdp_nla      = false;   // NLA status (from banner heuristic)

    // ── Gateway detection ─────────────────────────────────────────────────────
    bool        is_gateway         = false;  // true if host is likely a gateway/router
    int         gateway_confidence = 0;      // 0-100 composite confidence
    std::string gateway_reason;              // primary reason string (e.g. "Default route IP")
    std::vector<std::string> gateway_signals; // all contributing signals

    // ── Metadata ─────────────────────────────────────────────────────────────
    std::string generated_at;
};