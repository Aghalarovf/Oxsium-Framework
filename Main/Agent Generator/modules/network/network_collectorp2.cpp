// ─── network_collector_p2.cpp ────────────────────────────────────────────────
// SECTION 5  Port scan         — TCP connect probe with banner grab
// SECTION 6  Service ID        — offline DEFAULT_PORTS table lookup
// SECTION 7  Version detection — banner parsing per protocol
// ─────────────────────────────────────────────────────────────────────────────
#include "network_collector.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>

#ifndef _WIN32
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 5 — Port scan
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
//  tcp_connect_probe
//  Non-blocking TCP connect; on success reads up to 256 bytes as banner.
//  Returns true if port is open. out_banner may be empty (no data sent).
// ─────────────────────────────────────────────────────────────────────────────
bool NetworkCollector::tcp_connect_probe(const std::string& ip, uint16_t port,
                                          int timeout_ms,
                                          std::string& out_banner) const {
    out_banner.clear();

#ifndef _WIN32
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // Non-blocking mode
    int fl = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, fl | O_NONBLOCK);

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    int rc = connect(sock, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
    bool connected = (rc == 0);
    if (!connected && errno == EINPROGRESS) {
        fd_set wfds, efds;
        FD_ZERO(&wfds); FD_SET(sock, &wfds);
        FD_ZERO(&efds); FD_SET(sock, &efds);
        struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        int sel = select(sock + 1, nullptr, &wfds, &efds, &tv);
        if (sel > 0 && FD_ISSET(sock, &wfds)) {
            int err = 0; socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            connected = (err == 0);
        }
    }

    if (!connected) { close(sock); return false; }

    // Restore blocking for banner read
    fcntl(sock, F_SETFL, fl);
    struct timeval rtv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));

    // Some services need a probe to emit a banner
    // HTTP: send minimal GET request
    if (port == 80 || port == 443 || port == 8080 || port == 8443 ||
        port == 8000 || port == 8888) {
        const char* req = "HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n";
        send(sock, req, strlen(req), 0);
    }

    char buf[257]{};
    ssize_t n = recv(sock, buf, 256, 0);
    if (n > 0) out_banner = std::string(buf, static_cast<size_t>(n));

    close(sock);
    return true;
#else
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;

    u_long nb = 1;
    ioctlsocket(sock, FIONBIO, &nb);

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    connect(sock, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));

    fd_set wfds;
    FD_ZERO(&wfds); FD_SET(sock, &wfds);
    struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    bool connected = (select(0, nullptr, &wfds, nullptr, &tv) > 0);

    if (!connected) { closesocket(sock); return false; }

    nb = 0; ioctlsocket(sock, FIONBIO, &nb);
    DWORD rt = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&rt), sizeof(rt));

    if (port == 80 || port == 443 || port == 8080 || port == 8443) {
        const char* req = "HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n";
        send(sock, req, static_cast<int>(strlen(req)), 0);
    }

    char buf[257]{};
    int n = recv(sock, buf, 256, 0);
    if (n > 0) out_banner = std::string(buf, static_cast<size_t>(n));

    closesocket(sock);
    return true;
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
//  default_ports — the list of ports scanned when opts.ports is empty
// ─────────────────────────────────────────────────────────────────────────────
const std::vector<uint16_t>& NetworkCollector::default_ports() {
    static const std::vector<uint16_t> PORTS = {
        // Well-known
        21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137,
        138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 464, 465, 512, 513,
        514, 515, 554, 587, 593, 631, 636, 873, 902, 993, 995, 1080, 1194,
        1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
        2121, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4444, 4848,
        5000, 5432, 5800, 5900, 5984, 5985, 5986, 6379, 6443, 6881, 7000,
        7001, 7070, 7443, 7474, 8000, 8009, 8080, 8081, 8443, 8888, 8983,
        9000, 9090, 9200, 9300, 9418, 9999, 10000, 11211, 27017, 27018,
        27019, 50000, 50070, 61616
    };
    return PORTS;
}

// ─────────────────────────────────────────────────────────────────────────────
//  scan_ports — runs TCP probes on all target ports
// ─────────────────────────────────────────────────────────────────────────────
void NetworkCollector::scan_ports(NetworkHost& host,
                                   const NetworkCollectorOptions& opts) const {
    const auto& ports = opts.ports.empty() ? default_ports() : opts.ports;

    for (uint16_t port : ports) {
        std::string banner;
        if (tcp_connect_probe(host.ipv4, port, opts.port_timeout_ms, banner)) {
            NetworkHost::PortInfo pi;
            pi.port     = port;
            pi.protocol = "tcp";
            pi.state    = "open";
            pi.banner   = banner.substr(0, 256); // cap at 256 bytes
            // Clean non-printable chars from banner
            for (char& c : pi.banner) {
                if (static_cast<unsigned char>(c) < 0x20
                    && c != '\n' && c != '\r' && c != '\t')
                    c = '.';
            }
            host.open_ports.push_back(std::move(pi));
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 6 — Service identification (offline, no network)
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
//  service_name_for_port — lookup in DEFAULT_PORTS table
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::service_name_for_port(uint16_t port,
                                                      const std::string& proto) {
    for (size_t i = 0; i < DEFAULT_PORTS_COUNT; ++i) {
        if (DEFAULT_PORTS[i].port == port &&
            std::string(DEFAULT_PORTS[i].proto) == proto)
            return DEFAULT_PORTS[i].service;
    }
    return "";
}

void NetworkCollector::identify_services(NetworkHost& host) {
    for (auto& p : host.open_ports) {
        if (p.service_name.empty())
            p.service_name = service_name_for_port(p.port, p.protocol);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 7 — Version detection (banner parsing)
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
//  Helper: case-insensitive string search
// ─────────────────────────────────────────────────────────────────────────────
static bool ci_contains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    std::string h = haystack, n = needle;
    std::transform(h.begin(), h.end(), h.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    std::transform(n.begin(), n.end(), n.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return h.find(n) != std::string::npos;
}

// ─────────────────────────────────────────────────────────────────────────────
//  SSH banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
//  → version: "OpenSSH 8.2p1",  extra_info: "Ubuntu-4ubuntu0.5"
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::parse_ssh_banner(const std::string& banner) {
    // Format: SSH-<proto>-<software> [<comment>]\r\n
    if (banner.substr(0, 4) != "SSH-") return "";
    size_t dash2 = banner.find('-', 4);
    if (dash2 == std::string::npos) return "";
    std::string software = banner.substr(dash2 + 1);
    // Trim \r\n and trailing spaces
    while (!software.empty() &&
           (software.back() == '\r' || software.back() == '\n'
            || software.back() == ' '))
        software.pop_back();
    // Replace '_' with ' ' for readability: "OpenSSH_8.2p1" → "OpenSSH 8.2p1"
    std::replace(software.begin(), software.end(), '_', ' ');
    return software;
}

// ─────────────────────────────────────────────────────────────────────────────
//  HTTP banner: extract Server header value
//  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n..."
//  → version: "Apache/2.4.41 (Ubuntu)"
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::parse_http_banner(const std::string& banner) {
    std::string lower = banner;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    size_t pos = lower.find("server:");
    if (pos == std::string::npos) {
        // Try X-Powered-By
        pos = lower.find("x-powered-by:");
        if (pos == std::string::npos) return "";
        pos += 13;
    } else {
        pos += 7;
    }
    // Skip spaces
    while (pos < banner.size() && banner[pos] == ' ') ++pos;
    size_t end = banner.find("\r\n", pos);
    if (end == std::string::npos) end = banner.find('\n', pos);
    if (end == std::string::npos) end = banner.size();
    std::string val = banner.substr(pos, end - pos);
    while (!val.empty() && (val.back() == '\r' || val.back() == '\n'))
        val.pop_back();
    return val;
}

// ─────────────────────────────────────────────────────────────────────────────
//  FTP banner: "220 ProFTPD 1.3.7a Server"  or  "220 vsftpd 3.0.3"
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::parse_ftp_banner(const std::string& banner) {
    if (banner.substr(0, 3) != "220") return "";
    std::string line = banner.substr(0, banner.find('\n'));
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'
                               || line.back() == ' '))
        line.pop_back();
    // Strip leading "220 " or "220-"
    if (line.size() > 4) return line.substr(4);
    return line;
}

// ─────────────────────────────────────────────────────────────────────────────
//  SMTP banner: "220 mail.example.com ESMTP Postfix (Ubuntu)"
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::parse_smtp_banner(const std::string& banner) {
    if (banner.substr(0, 3) != "220") return "";
    std::string line = banner.substr(0, banner.find('\n'));
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    if (line.size() > 4) return line.substr(4);
    return line;
}

// ─────────────────────────────────────────────────────────────────────────────
//  RDP banner: RDP/STARTTLS — minimal; extract from first bytes if NTLM header
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::parse_rdp_banner(const std::string& banner) {
    // RDP does not send a plain-text banner; if we got something, check for
    // the TPKT header (0x03 0x00) or just return generic "RDP"
    if (banner.size() >= 2 &&
        static_cast<unsigned char>(banner[0]) == 0x03 &&
        static_cast<unsigned char>(banner[1]) == 0x00)
        return "RDP (TPKT)";
    return "";
}

// ─────────────────────────────────────────────────────────────────────────────
//  SMB banner: SMB negotiate response magic bytes
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::parse_smb_banner(const std::string& banner) {
    if (banner.size() >= 8) {
        // SMB2 magic: \xFESMB
        if (static_cast<unsigned char>(banner[4]) == 0xFE &&
            banner[5] == 'S' && banner[6] == 'M' && banner[7] == 'B')
            return "SMB2";
        // SMB1 magic: \xFFSMB
        if (static_cast<unsigned char>(banner[4]) == 0xFF &&
            banner[5] == 'S' && banner[6] == 'M' && banner[7] == 'B')
            return "SMB1";
    }
    return "";
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_generic_banner — tries to extract a product/version from raw text
//  Handles "Product/x.y.z" and "Product version x.y.z" patterns
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::parse_generic_banner(const std::string& banner) {
    if (banner.empty()) return "";
    // Take first line only
    std::string line = banner.substr(0, banner.find('\n'));
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'
                               || line.back() == ' '))
        line.pop_back();
    // Cap at 80 chars
    if (line.size() > 80) line = line.substr(0, 80);
    return line;
}

// ─────────────────────────────────────────────────────────────────────────────
//  detect_versions — dispatches banner to the right parser
// ─────────────────────────────────────────────────────────────────────────────
void NetworkCollector::detect_versions(NetworkHost& host) {
    for (auto& p : host.open_ports) {
        if (p.banner.empty()) continue;

        std::string ver;
        switch (p.port) {
            case 21:                         ver = parse_ftp_banner(p.banner);   break;
            case 22:                         ver = parse_ssh_banner(p.banner);   break;
            case 25: case 587: case 465:     ver = parse_smtp_banner(p.banner);  break;
            case 80: case 443:
            case 8080: case 8443:
            case 8000: case 8888:            ver = parse_http_banner(p.banner);  break;
            case 445: case 139:              ver = parse_smb_banner(p.banner);   break;
            case 3389:                       ver = parse_rdp_banner(p.banner);   break;
            default:                         ver = parse_generic_banner(p.banner); break;
        }

        if (!ver.empty()) p.version = ver;

        // Extract extra_info from SSH banner comment field
        if (p.port == 22 && !p.banner.empty()) {
            std::string sw = p.version;
            size_t sp = sw.find(' ');
            if (sp != std::string::npos) {
                // Check if there's a comment after the software field in the raw banner
                size_t dash2 = p.banner.find('-', 4);
                if (dash2 != std::string::npos) {
                    std::string after = p.banner.substr(dash2 + 1);
                    size_t space_pos  = after.find(' ');
                    if (space_pos != std::string::npos) {
                        std::string comment = after.substr(space_pos + 1);
                        while (!comment.empty() &&
                               (comment.back() == '\r' || comment.back() == '\n'
                                || comment.back() == ' '))
                            comment.pop_back();
                        if (!comment.empty()) p.extra_info = comment;
                    }
                }
            }
        }
    }
}