// ─── offline_processor_network.cpp ───────────────────────────────────────────
// SECTION 30  NetworkProcessor — OfflineProcessor extension
//
//  Reads raw_network.ndjson (produced by NetworkCollector) and writes
//  domain_network.ndjson with:
//    - Notable service flags  (has_smb, has_rdp, has_ssh, etc.)
//    - AD correlation         (matches IP/hostname → raw_computers.ndjson)
//    - Risk scoring           (0-100 composite based on open ports + OS + AD)
//    - Risk factor labels     (human-readable contributing factors)
//
//  This module follows the exact same pattern as the other OfflineProcessor
//  "section" files (offline_processorp*.cpp).
//
//  Reading output (Python):
//    import json
//    with open("domain_network.ndjson") as f:
//        for line in f:
//            host = json.loads(line)
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include "../network/network_collector.h"
#include "oui_database.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <unordered_map>

// Platform headers needed for default-gateway detection
#ifndef _WIN32
#  include <arpa/inet.h>    // inet_ntop
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>     // inet_ntop, INET_ADDRSTRLEN
#  include <iphlpapi.h>     // GetIpForwardTable, MIB_IPFORWARDTABLE
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "ws2_32.lib")
#endif

// ─────────────────────────────────────────────────────────────────────────────
//  Forward declaration — network-specific helpers (local to this TU)
// ─────────────────────────────────────────────────────────────────────────────
static ProcessedNetworkHost parse_raw_network_host(const std::string& json_line);
static void                  analyze_network_risk  (ProcessedNetworkHost& h);
static void                  detect_gateway        (ProcessedNetworkHost& h,
                                                    const std::string& system_gw_ip,
                                                    const std::string& cidr);
static std::string           network_host_to_json  (const ProcessedNetworkHost& h,
                                                    const std::string& oui_vendor,
                                                    const std::string& oui_device_type);
static bool                  jp_bool_net(const std::string& j, const std::string& k,
                                          bool def = false);
static int                   jp_int_net (const std::string& j, const std::string& k,
                                          int def = 0);
static std::string           jp_str_net (const std::string& j, const std::string& k);

// ─────────────────────────────────────────────────────────────────────────────
//  Minimal JSON field extractors
//  (mirrors OfflineProcessor::jp_* — cannot call private methods from here)
// ─────────────────────────────────────────────────────────────────────────────
static std::string jp_str_net(const std::string& j, const std::string& k) {
    std::string key = "\"" + k + "\"";
    size_t pos = j.find(key);
    if (pos == std::string::npos) return "";
    pos += key.size();
    while (pos < j.size() && (j[pos] == ' ' || j[pos] == ':')) ++pos;
    if (pos >= j.size()) return "";
    if (j[pos] == '"') {
        ++pos;
        std::string val;
        while (pos < j.size() && j[pos] != '"') {
            if (j[pos] == '\\' && pos + 1 < j.size()) {
                ++pos;
                switch (j[pos]) {
                    case 'n': val += '\n'; break;
                    case 'r': val += '\r'; break;
                    case 't': val += '\t'; break;
                    case '"': val += '"';  break;
                    case '\\': val += '\\'; break;
                    default: val += j[pos]; break;
                }
            } else {
                val += j[pos];
            }
            ++pos;
        }
        return val;
    }
    // Non-string (number / bool / null)
    size_t end = j.find_first_of(",}]", pos);
    if (end == std::string::npos) end = j.size();
    std::string raw = j.substr(pos, end - pos);
    while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\n')) raw.pop_back();
    return raw;
}

static bool jp_bool_net(const std::string& j, const std::string& k, bool def) {
    std::string v = jp_str_net(j, k);
    if (v == "true")  return true;
    if (v == "false") return false;
    return def;
}

static int jp_int_net(const std::string& j, const std::string& k, int def) {
    std::string v = jp_str_net(j, k);
    if (v.empty()) return def;
    try { return std::stoi(v); } catch (...) { return def; }
}

// Extract array of port objects from "open_ports" key
static std::vector<NetworkHost::PortInfo> jp_ports_net(const std::string& j) {
    std::vector<NetworkHost::PortInfo> result;
    std::string key = "\"open_ports\"";
    size_t pos = j.find(key);
    if (pos == std::string::npos) return result;
    pos = j.find('[', pos);
    if (pos == std::string::npos) return result;

    // Parse array of objects manually
    int depth = 0;
    size_t obj_start = std::string::npos;
    for (size_t i = pos; i < j.size(); ++i) {
        if (j[i] == '{') {
            if (depth == 0) obj_start = i;
            ++depth;
        } else if (j[i] == '}') {
            --depth;
            if (depth == 0 && obj_start != std::string::npos) {
                std::string obj = j.substr(obj_start, i - obj_start + 1);
                NetworkHost::PortInfo pi;
                std::string port_str = jp_str_net(obj, "port");
                try { pi.port = static_cast<uint16_t>(std::stoul(port_str)); }
                catch (...) {}
                pi.protocol    = jp_str_net(obj, "protocol");
                pi.state       = jp_str_net(obj, "state");
                pi.service_name= jp_str_net(obj, "service_name");
                pi.banner      = jp_str_net(obj, "banner");
                pi.version     = jp_str_net(obj, "version");
                pi.extra_info  = jp_str_net(obj, "extra_info");
                result.push_back(std::move(pi));
                obj_start = std::string::npos;
            }
        } else if (j[i] == ']' && depth == 0) {
            break;
        }
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_raw_network_host — deserializes one NDJSON line
// ─────────────────────────────────────────────────────────────────────────────
static ProcessedNetworkHost parse_raw_network_host(const std::string& json_line) {
    ProcessedNetworkHost h;
    const std::string& j = json_line;

    h.ipv4           = jp_str_net(j, "ipv4");
    h.mac            = jp_str_net(j, "mac");
    h.mac_vendor     = jp_str_net(j, "mac_vendor");
    h.hostname       = jp_str_net(j, "hostname");
    h.ping_ok        = jp_bool_net(j, "ping_ok");
    h.arp_ok         = jp_bool_net(j, "arp_ok");
    h.open_port_count= jp_int_net(j, "open_port_count");
    h.os_guess       = jp_str_net(j, "os_guess");
    h.os_detail      = jp_str_net(j, "os_detail");
    h.os_confidence  = jp_int_net(j, "os_confidence");
    h.ttl            = jp_int_net(j, "ttl");
    h.generated_at   = jp_str_net(j, "generated_at");
    h.open_ports     = jp_ports_net(j);

    return h;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Gateway detection helpers
// ─────────────────────────────────────────────────────────────────────────────

// Returns the last octet of an IPv4 string, or -1 on parse error.
static int last_octet(const std::string& ip) {
    size_t pos = ip.rfind('.');
    if (pos == std::string::npos) return -1;
    try { return std::stoi(ip.substr(pos + 1)); } catch (...) { return -1; }
}

// Checks whether the MAC vendor string belongs to a known network-device brand.
// Returns the matched brand name or empty string.
static std::string gateway_vendor_match(const std::string& vendor) {
    // Lowercase comparison
    std::string v = vendor;
    std::transform(v.begin(), v.end(), v.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    static const std::pair<const char*, const char*> BRANDS[] = {
        { "cisco",      "Cisco"      },
        { "mikrotik",   "MikroTik"   },
        { "ubiquiti",   "Ubiquiti"   },
        { "juniper",    "Juniper"    },
        { "fortinet",   "Fortinet"   },
        { "palo alto",  "Palo Alto"  },
        { "checkpoint", "Check Point"},
        { "huawei",     "Huawei"     },
        { "aruba",      "Aruba"      },
        { "sonicwall",  "SonicWall"  },
        { "watchguard", "WatchGuard" },
        { "peplink",    "Peplink"    },
        { "zyxel",      "ZyXEL"      },
        { "netgear",    "Netgear"    },
        { "linksys",    "Linksys"    },
        { "tp-link",    "TP-Link"    },
        { "d-link",     "D-Link"     },
        { "draytek",    "DrayTek"    },
        { "opnsense",   "OPNsense"   },
        { "pfsense",    "pfSense"    },
        { "router",     "Router"     },
        { "gateway",    "Gateway"    },
        { "firewall",   "Firewall"   },
    };
    for (const auto& b : BRANDS) {
        if (v.find(b.first) != std::string::npos) return b.second;
    }
    return "";
}

// Checks whether any open port or banner indicates a router/gateway OS/service.
// Returns a descriptive signal string or empty.
static std::string gateway_port_signal(const ProcessedNetworkHost& h) {
    for (const auto& p : h.open_ports) {
        // BGP — only routers run this
        if (p.port == 179)
            return "BGP port 179 open (definite router)";
        // RIP/RIPng
        if (p.port == 520 || p.port == 521)
            return "RIP port " + std::to_string(p.port) + " open (router routing protocol)";
        // Quagga / FRRouting
        if (p.port == 2601 || p.port == 2602 || p.port == 2605)
            return "Quagga/FRR port " + std::to_string(p.port) + " open (software router)";
        // MikroTik Winbox
        if (p.port == 8291)
            return "Winbox port 8291 open (MikroTik RouterOS)";
        // MikroTik API
        if (p.port == 8728 || p.port == 8729)
            return "MikroTik API port " + std::to_string(p.port) + " open";
        // OSPF (IP proto 89 — won't appear as TCP port, but some mgmt UIs)
        // Cisco IOS HTTP/S management
        if ((p.port == 80 || p.port == 443) && !p.banner.empty()) {
            std::string bl = p.banner;
            std::transform(bl.begin(), bl.end(), bl.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            static const char* ROUTER_KEYWORDS[] = {
                "routeros", "ios", "fortigate", "pfsense", "opnsense",
                "sonicwall", "junos", "edgeos", "vyos", "ubnt", nullptr
            };
            for (int i = 0; ROUTER_KEYWORDS[i]; ++i) {
                if (bl.find(ROUTER_KEYWORDS[i]) != std::string::npos)
                    return std::string("HTTP banner contains router keyword: ") + ROUTER_KEYWORDS[i];
            }
        }
        // SSH banner check
        if (p.port == 22 && !p.banner.empty()) {
            std::string bl = p.banner;
            std::transform(bl.begin(), bl.end(), bl.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            static const char* SSH_KEYWORDS[] = {
                "routeros", "cisco", "junos", "fortigate", "edgeos",
                "vyos", "ubnt", nullptr
            };
            for (int i = 0; SSH_KEYWORDS[i]; ++i) {
                if (bl.find(SSH_KEYWORDS[i]) != std::string::npos)
                    return std::string("SSH banner contains router keyword: ") + SSH_KEYWORDS[i];
            }
        }
    }
    return "";
}

// ─────────────────────────────────────────────────────────────────────────────
//  detect_gateway
//
//  Fills h.is_gateway, h.gateway_confidence, h.gateway_reason,
//  and h.gateway_signals with all contributing evidence.
//
//  Parameters:
//    system_gw_ip  — the OS-reported default gateway IP (most reliable);
//                    pass empty string if not available.
//    cidr          — the scanned CIDR string (e.g. "192.168.1.0/24");
//                    used only for last-octet heuristic.
//
//  Confidence table:
//    Signal                          | Points
//    ─────────────────────────────── | ──────
//    IP == system default gateway    |  100  (short-circuits everything)
//    BGP / RIP / Quagga port open    |   90
//    MikroTik Winbox / API port      |   85
//    HTTP/SSH banner → router OS     |   80
//    MAC vendor → network brand      |   70
//    TTL == 255 (network device)     |   55
//    Last octet .1 / .254 / .253     |   25
//
//  Multiple signals are combined with diminishing returns:
//    total = first + (second * 0.5) + (third * 0.25) + ...
//  and capped at 99 (100 is reserved for the definite system-GW match).
// ─────────────────────────────────────────────────────────────────────────────
static void detect_gateway(ProcessedNetworkHost& h,
                            const std::string& system_gw_ip,
                            const std::string& /*cidr*/) {
    h.is_gateway         = false;
    h.gateway_confidence = 0;
    h.gateway_reason     = "";
    h.gateway_signals.clear();

    // ── Signal 1: OS-reported default gateway (highest authority) ─────────────
    if (!system_gw_ip.empty() && h.ipv4 == system_gw_ip) {
        h.is_gateway         = true;
        h.gateway_confidence = 100;
        h.gateway_reason     = "Default route IP match";
        h.gateway_signals.push_back("IP matches system default gateway (" + system_gw_ip + ")");
        return;  // definite — no need to accumulate further
    }

    // ── Collect weighted signals ──────────────────────────────────────────────
    struct Signal { std::string desc; int points; };
    std::vector<Signal> signals;

    // Signal 2: Router-specific port / banner
    std::string port_sig = gateway_port_signal(h);
    if (!port_sig.empty()) {
        int pts = (port_sig.find("BGP") != std::string::npos ||
                   port_sig.find("RIP") != std::string::npos ||
                   port_sig.find("Quagga") != std::string::npos) ? 90 : 80;
        if (port_sig.find("Winbox") != std::string::npos ||
            port_sig.find("MikroTik") != std::string::npos) pts = 85;
        signals.push_back({ port_sig, pts });
    }

    // Signal 3: MAC vendor → known network brand
    std::string brand = gateway_vendor_match(h.mac_vendor);
    if (!brand.empty())
        signals.push_back({ "MAC vendor matches network brand: " + brand, 70 });

    // Signal 4: TTL == 255 → Cisco / network device heuristic
    if (h.ttl >= 240)
        signals.push_back({ "TTL=" + std::to_string(h.ttl) + " (typical of network devices/Cisco)", 55 });

    // Signal 5: Last-octet heuristic (.1 / .254 / .253)
    int lo = last_octet(h.ipv4);
    if (lo == 1 || lo == 254 || lo == 253) {
        signals.push_back({ "Last IP octet is ." + std::to_string(lo) +
                            " (common gateway address pattern)", 25 });
    }

    if (signals.empty()) return;

    // ── Sort descending by points, then combine with diminishing returns ───────
    std::sort(signals.begin(), signals.end(),
              [](const Signal& a, const Signal& b){ return a.points > b.points; });

    double total = 0.0;
    double weight = 1.0;
    for (const auto& s : signals) {
        total  += s.points * weight;
        weight *= 0.5;
        h.gateway_signals.push_back(s.desc);
    }

    h.gateway_confidence = std::min(static_cast<int>(total), 99);
    h.gateway_reason     = signals.front().desc;  // strongest signal as primary reason
    h.is_gateway         = (h.gateway_confidence >= 50);
}

// ─────────────────────────────────────────────────────────────────────────────
//  analyze_network_risk — computes risk_score + notable service flags
// ─────────────────────────────────────────────────────────────────────────────
static void analyze_network_risk(ProcessedNetworkHost& h) {
    h.risk_score = 0;
    h.risk_factors.clear();

    // Check which services are open
    for (const auto& p : h.open_ports) {
        switch (p.port) {
            case 445: case 139: h.has_smb    = true; break;
            case 3389:          h.has_rdp    = true; break;
            case 22:            h.has_ssh    = true; break;
            case 5985: case 5986: h.has_winrm = true; break;
            case 389: case 636: h.has_ldap   = true; break;
            case 80: case 443:
            case 8080: case 8443:
            case 8000: case 8888: h.has_http = true; break;
            case 21:            h.has_ftp    = true; break;
            case 23:            h.has_telnet = true; break;
            case 161: case 162: h.has_snmp   = true; break;
            case 1433:          h.has_mssql  = true; break;
            case 3306:          h.has_mysql  = true; break;
        }
    }

    // ── Risk scoring rules ────────────────────────────────────────────────────

    // Telnet is unencrypted remote access — high risk
    if (h.has_telnet) {
        h.risk_score += 30;
        h.risk_factors.push_back("Telnet open (plaintext remote access)");
    }

    // SMB exposed — commonly exploited (EternalBlue, etc.)
    if (h.has_smb) {
        h.risk_score += 20;
        h.risk_factors.push_back("SMB port 445 open");
    }

    // Anonymous SNMP (v1/v2c) — info disclosure
    if (h.has_snmp) {
        h.risk_score += 15;
        h.risk_factors.push_back("SNMP port 161 open (potential info disclosure)");
    }

    // FTP — often anonymous or plaintext
    if (h.has_ftp) {
        h.risk_score += 15;
        h.risk_factors.push_back("FTP port 21 open (plaintext credentials)");
    }

    // WinRM — lateral movement vector
    if (h.has_winrm) {
        h.risk_score += 15;
        h.risk_factors.push_back("WinRM open (lateral movement vector)");
    }

    // RDP — brute force / BlueKeep surface
    if (h.has_rdp) {
        h.risk_score += 10;
        h.risk_factors.push_back("RDP port 3389 open");
    }

    // Database ports directly exposed
    if (h.has_mssql) {
        h.risk_score += 20;
        h.risk_factors.push_back("MSSQL port 1433 directly exposed");
    }
    if (h.has_mysql) {
        h.risk_score += 20;
        h.risk_factors.push_back("MySQL port 3306 directly exposed");
    }

    // LDAP open outside of DCs is unusual
    if (h.has_ldap && !h.ad_matched) {
        h.risk_score += 10;
        h.risk_factors.push_back("LDAP port 389 open on non-AD-correlated host");
    }

    // Many open ports is suspicious on a workstation
    if (h.open_port_count > 15) {
        h.risk_score += 10;
        h.risk_factors.push_back("High number of open ports (" +
                                   std::to_string(h.open_port_count) + ")");
    }

    // Check for dangerous/unusual services by banner content
    for (const auto& p : h.open_ports) {
        // Docker API exposed without TLS
        if (p.port == 2375 && p.service_name == "docker") {
            h.risk_score += 40;
            h.risk_factors.push_back("Docker API port 2375 exposed (unauthenticated)");
        }
        // Kubernetes API
        if (p.port == 6443 || p.port == 16443) {
            h.risk_score += 25;
            h.risk_factors.push_back("Kubernetes API port exposed");
        }
        // Redis without auth (typically no banner auth)
        if (p.port == 6379) {
            h.risk_score += 25;
            h.risk_factors.push_back("Redis port 6379 exposed (often unauthenticated)");
        }
        // Elasticsearch
        if (p.port == 9200) {
            h.risk_score += 25;
            h.risk_factors.push_back("Elasticsearch port 9200 exposed");
        }
        // MongoDB
        if (p.port == 27017) {
            h.risk_score += 25;
            h.risk_factors.push_back("MongoDB port 27017 exposed");
        }
        // Memcached
        if (p.port == 11211) {
            h.risk_score += 20;
            h.risk_factors.push_back("Memcached port 11211 exposed (no auth)");
        }
        // Metasploit/C2 indicator
        if (p.port == 4444) {
            h.risk_score += 50;
            h.risk_factors.push_back("Port 4444 open (potential Metasploit/C2)");
        }
    }

    // AD-correlated hosts with dangerous open ports are higher risk
    if (h.ad_matched && h.has_smb) {
        h.risk_score += 5;
        h.risk_factors.push_back("AD-joined machine with SMB exposed");
    }

    // Cap at 100
    if (h.risk_score > 100) h.risk_score = 100;
    h.high_risk = (h.risk_score >= 40);
}

// ─────────────────────────────────────────────────────────────────────────────
//  network_host_to_json — serializes ProcessedNetworkHost to NDJSON line
// ─────────────────────────────────────────────────────────────────────────────
static std::string je_n(const std::string& s) {
    std::ostringstream o;
    o << '"';
    for (unsigned char ch : s) {
        switch (ch) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (ch < 0x20)
                    o << "\\u00" << std::hex << std::setw(2)
                      << std::setfill('0') << static_cast<int>(ch) << std::dec;
                else
                    o << static_cast<char>(ch);
        }
    }
    o << '"';
    return o.str();
}
static std::string jb_n(bool v) { return v ? "true" : "false"; }
static std::string ji_n(int v)  { return std::to_string(v); }
static std::string ja_n(const std::vector<std::string>& v) {
    std::ostringstream o; o << '[';
    for (size_t i = 0; i < v.size(); ++i) { if (i) o << ','; o << je_n(v[i]); }
    o << ']'; return o.str();
}

static std::string network_host_to_json(const ProcessedNetworkHost& h,
                                        const std::string& oui_vendor,
                                        const std::string& oui_device_type) {
    // Build open_ports array
    std::ostringstream ports;
    ports << '[';
    for (size_t i = 0; i < h.open_ports.size(); ++i) {
        const auto& p = h.open_ports[i];
        if (i) ports << ',';
        ports << "{"
              << "\"port\":"          << p.port            << ","
              << "\"protocol\":"      << je_n(p.protocol)  << ","
              << "\"state\":"         << je_n(p.state)      << ","
              << "\"service_name\":"  << je_n(p.service_name) << ","
              << "\"banner\":"        << je_n(p.banner)     << ","
              << "\"version\":"       << je_n(p.version)    << ","
              << "\"extra_info\":"    << je_n(p.extra_info)
              << "}";
    }
    ports << ']';

    std::ostringstream o;
    o << "{"
      // ── Raw fields ───────────────────────────────────────────────────────
      << "\"ipv4\":"              << je_n(h.ipv4)            << ","
      << "\"mac\":"               << je_n(h.mac)             << ","
      << "\"mac_vendor\":"        << je_n(h.mac_vendor)      << ","
      << "\"hostname\":"          << je_n(h.hostname)        << ","
      << "\"ping_ok\":"           << jb_n(h.ping_ok)         << ","
      << "\"arp_ok\":"            << jb_n(h.arp_ok)          << ","
      << "\"open_ports\":"        << ports.str()             << ","
      << "\"open_port_count\":"   << ji_n(h.open_port_count) << ","
      << "\"os_guess\":"          << je_n(h.os_guess)        << ","
      << "\"os_detail\":"         << je_n(h.os_detail)       << ","
      << "\"os_confidence\":"     << ji_n(h.os_confidence)   << ","
      << "\"ttl\":"               << ji_n(h.ttl)             << ","
      // ── AD correlation ───────────────────────────────────────────────────
      << "\"ad_matched\":"        << jb_n(h.ad_matched)      << ","
      << "\"ad_computer_name\":"  << je_n(h.ad_computer_name)<< ","
      << "\"ad_dn\":"             << je_n(h.ad_dn)           << ","
      << "\"ad_sid\":"            << je_n(h.ad_sid)          << ","
      << "\"ad_os\":"             << je_n(h.ad_os)           << ","
      // ── Notable services ─────────────────────────────────────────────────
      << "\"has_smb\":"           << jb_n(h.has_smb)         << ","
      << "\"has_rdp\":"           << jb_n(h.has_rdp)         << ","
      << "\"has_ssh\":"           << jb_n(h.has_ssh)         << ","
      << "\"has_winrm\":"         << jb_n(h.has_winrm)       << ","
      << "\"has_ldap\":"          << jb_n(h.has_ldap)        << ","
      << "\"has_http\":"          << jb_n(h.has_http)        << ","
      << "\"has_ftp\":"           << jb_n(h.has_ftp)         << ","
      << "\"has_telnet\":"        << jb_n(h.has_telnet)      << ","
      << "\"has_snmp\":"          << jb_n(h.has_snmp)        << ","
      << "\"has_mssql\":"         << jb_n(h.has_mssql)       << ","
      << "\"has_mysql\":"         << jb_n(h.has_mysql)       << ","
      // ── Risk ─────────────────────────────────────────────────────────────
      << "\"risk_score\":"        << ji_n(h.risk_score)      << ","
      << "\"high_risk\":"         << jb_n(h.high_risk)       << ","
      << "\"risk_factors\":"      << ja_n(h.risk_factors)    << ","
      // ── Gateway detection ─────────────────────────────────────────────────
      << "\"is_gateway\":"        << jb_n(h.is_gateway)          << ","
      << "\"gateway_confidence\":" << ji_n(h.gateway_confidence)  << ","
      << "\"gateway_reason\":"    << je_n(h.gateway_reason)       << ","
      << "\"gateway_signals\":"   << ja_n(h.gateway_signals)      << ","
      // ── MAC vendor (OUI lookup) ───────────────────────────────────────────
      << "\"oui_vendor\":"        << je_n(oui_vendor)        << ","
      << "\"oui_device_type\":"   << je_n(oui_device_type)   << ","
      // ── Metadata ─────────────────────────────────────────────────────────
      << "\"generated_at\":"      << je_n(h.generated_at)
      << "}";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  OfflineProcessor::process_network
//  Called from OfflineProcessor::process() — same pattern as process_computers()
//
//  1. Reads raw_network.ndjson line by line
//  2. Parses each host
//  3. Correlates with AD computers (hostname / DNS name match)
//  4. Computes risk scores + service flags
//  5. Writes domain_network.ndjson
// ─────────────────────────────────────────────────────────────────────────────
bool OfflineProcessor::process_network(const OfflineProcessorOptions& opts) {
    const std::string raw_path = (fs::path(opts.raw_dir) / "raw_network.ndjson").string();
    const std::string& ext = opts.output_ext.empty() ? "ndjson" : opts.output_ext;
    const std::string out_path = (fs::path(opts.output_dir) / ("domain_network." + ext)).string();

    fs::create_directories(opts.output_dir);

    auto lines = read_ndjson_lines(raw_path);
    if (lines.empty()) {
        log_warn("[NetworkProcessor] raw_network.ndjson is empty or missing: " + raw_path);
        return false;
    }
    log_info("[NetworkProcessor] Processing " + std::to_string(lines.size())
             + " network hosts from " + raw_path);

    // ── Build AD lookup: hostname (lower) → computer info ────────────────────
    // We read raw_computers.ndjson if it exists for correlation
    std::unordered_map<std::string, std::tuple<std::string,std::string,std::string,std::string>>
        hostname_to_ad;  // hostname → (computer_name, dn, sid, os)

    const std::string raw_computers = (fs::path(opts.raw_dir) / "raw_computers.ndjson").string();
    auto comp_lines = read_ndjson_lines(raw_computers);
    for (const auto& cl : comp_lines) {
        std::string dns_name = jp_str(cl, "dns_name");
        std::string comp_name= jp_str(cl, "computer_name");
        std::string dn       = jp_str(cl, "dn");
        std::string sid      = jp_str(cl, "sid");
        std::string os       = jp_str(cl, "os");
        if (dns_name.empty() && comp_name.empty()) continue;
        // Index by lowercase hostname (FQDN) and by short name
        if (!dns_name.empty()) {
            std::string k = lower(dns_name);
            hostname_to_ad[k] = {comp_name, dn, sid, os};
            // Also index short name (before first dot)
            size_t dot = k.find('.');
            if (dot != std::string::npos) hostname_to_ad[k.substr(0, dot)] = {comp_name, dn, sid, os};
        }
        if (!comp_name.empty()) {
            // sAMAccountName includes '$' — strip it
            std::string cn = lower(comp_name);
            if (!cn.empty() && cn.back() == '$') cn.pop_back();
            hostname_to_ad[cn] = {comp_name, dn, sid, os};
        }
    }
    log_info("[NetworkProcessor] Loaded " + std::to_string(hostname_to_ad.size())
             + " AD computer entries for correlation");

    std::ofstream f(out_path, std::ios::out | std::ios::trunc);
    if (!f) {
        log_err("[NetworkProcessor] Failed to open output file: " + out_path);
        return false;
    }

    // ── Detect system default gateway IP ─────────────────────────────────────
    // This is the most reliable signal for gateway identification.
    // We read it once before the host loop and pass it to detect_gateway().
    std::string system_gw_ip;
    {
#ifndef _WIN32
        // Linux: parse /proc/net/route — find the entry where Destination == 0
        // Format: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        // All values are in little-endian hex.
        std::ifstream route_file("/proc/net/route");
        std::string rline;
        std::getline(route_file, rline); // skip header
        while (std::getline(route_file, rline)) {
            std::istringstream ss(rline);
            std::string iface, dest_hex, gw_hex;
            ss >> iface >> dest_hex >> gw_hex;
            if (dest_hex == "00000000" && !gw_hex.empty()) {
                // Gateway is a little-endian 32-bit hex value
                unsigned long gw_val = std::stoul(gw_hex, nullptr, 16);
                unsigned char b0 =  gw_val        & 0xFF;
                unsigned char b1 = (gw_val >>  8) & 0xFF;
                unsigned char b2 = (gw_val >> 16) & 0xFF;
                unsigned char b3 = (gw_val >> 24) & 0xFF;
                system_gw_ip = std::to_string(b0) + "." + std::to_string(b1) + "."
                             + std::to_string(b2) + "." + std::to_string(b3);
                break;
            }
        }
#else
        // Windows: use GetIpForwardTable to find the default route (dest == 0)
        ULONG size = 0;
        GetIpForwardTable(nullptr, &size, FALSE);
        std::vector<BYTE> buf(size);
        auto* table = reinterpret_cast<PMIB_IPFORWARDTABLE>(buf.data());
        if (GetIpForwardTable(table, &size, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];
                if (row.dwForwardDest == 0) {
                    // dwForwardNextHop is already in network-byte-order (big-endian)
                    struct in_addr gw{};
                    gw.s_addr = row.dwForwardNextHop;
                    char buf4[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, &gw, buf4, sizeof(buf4)))
                        system_gw_ip = buf4;
                    break;
                }
            }
        }
#endif
    }
    if (!system_gw_ip.empty())
        log_info("[NetworkProcessor] System default gateway: " + system_gw_ip);
    else
        log_info("[NetworkProcessor] System default gateway not detected; using heuristics only");

    int written    = 0;
    int correlated = 0;
    int high_risk  = 0;
    int gateways   = 0;
    int oui_resolved = 0;
    std::vector<std::string> rows;

    for (const auto& line : lines) {
        if (line.empty()) continue;

        ProcessedNetworkHost h = parse_raw_network_host(line);
        if (h.ipv4.empty()) continue;

        // ── AD correlation ────────────────────────────────────────────────────
        // Try hostname match first, then reverse-lookup match
        std::string key = lower(h.hostname);
        // Strip trailing dot from rDNS
        if (!key.empty() && key.back() == '.') key.pop_back();

        auto it = hostname_to_ad.find(key);
        if (it == hostname_to_ad.end() && !key.empty()) {
            // Try short name
            size_t dot = key.find('.');
            if (dot != std::string::npos)
                it = hostname_to_ad.find(key.substr(0, dot));
        }
        if (it != hostname_to_ad.end()) {
            h.ad_matched      = true;
            h.ad_computer_name= std::get<0>(it->second);
            h.ad_dn           = std::get<1>(it->second);
            h.ad_sid          = std::get<2>(it->second);
            h.ad_os           = std::get<3>(it->second);
            ++correlated;
        }

        // ── Risk analysis + service flags ─────────────────────────────────────
        analyze_network_risk(h);
        if (h.high_risk) ++high_risk;

        // ── Gateway detection ─────────────────────────────────────────────────
        detect_gateway(h, system_gw_ip, opts.target_cidr);
        if (h.is_gateway) ++gateways;

        // ── MAC vendor lookup (OUI) ───────────────────────────────────────────
        std::string oui_vendor;
        std::string oui_device_type = "Unknown";
        if (!h.mac.empty()) {
            OuiResult oui = oui_lookup(h.mac);
            if (oui.found()) {
                oui_vendor      = oui.vendor;
                oui_device_type = oui.type_str();
                ++oui_resolved;
            }
        }

        rows.push_back(network_host_to_json(h, oui_vendor, oui_device_type));
        ++written;
    }
    write_objects(f, rows, out_path, "[NetworkProcessor]");

    if (!f) {
        log_err("[NetworkProcessor] Write error — output may be incomplete: " + out_path);
        return false;
    }

    log_ok("[NetworkProcessor] domain_network written -> " + out_path);
    log_ok("[NetworkProcessor] "
           + std::to_string(written)       + " hosts | "
           + std::to_string(correlated)    + " AD-correlated | "
           + std::to_string(high_risk)     + " high-risk | "
           + std::to_string(gateways)      + " gateway(s) detected | "
           + std::to_string(oui_resolved)  + " OUI vendor resolved");
    return true;
}