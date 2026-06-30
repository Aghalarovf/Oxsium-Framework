// ─── network_collector_p1.cpp ────────────────────────────────────────────────
// SECTION 1  Utility helpers  — JSON, CIDR expansion, ISO timestamp
// SECTION 2  Host discovery   — ICMP ping + ARP probe, rDNS, MAC vendor
// SECTION 3  collect()        — main entry point + JSONL writer
// SECTION 4  DEFAULT_PORTS    — large static port→service table (1000+ entries)
// ─────────────────────────────────────────────────────────────────────────────
#include "network_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <thread>
#include <mutex>
#include <atomic>
#include <future>

// POSIX / cross-platform network headers
#ifndef _WIN32
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <netinet/in.h>
#  include <netinet/ip_icmp.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <net/if.h>
#  include <sys/ioctl.h>
#  include <ifaddrs.h>
#  ifdef __linux__
#    include <netpacket/packet.h>
#    include <net/ethernet.h>
#    include <linux/if_arp.h>
#  endif
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <icmpapi.h>
#  include <winerror.h>
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "icmp.lib")
#  pragma comment(lib, "ws2_32.lib")
#endif

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 1 — Utility / JSON helpers
// ═════════════════════════════════════════════════════════════════════════════

std::string NetworkCollector::je(const std::string& s) {
    std::ostringstream o;
    o << '"';
    for (unsigned char ch : s) {
        switch (ch) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (ch < 0x20)
                    o << "\\u" << std::hex << std::setw(4)
                      << std::setfill('0') << static_cast<int>(ch) << std::dec;
                else
                    o << static_cast<char>(ch);
        }
    }
    o << '"';
    return o.str();
}
std::string NetworkCollector::jb(bool v)  { return v ? "true" : "false"; }
std::string NetworkCollector::ji(int v)   { return std::to_string(v); }
std::string NetworkCollector::jnull()     { return "null"; }

std::string NetworkCollector::ja(const std::vector<std::string>& v) {
    std::ostringstream o;
    o << '[';
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o << ',';
        o << je(v[i]);
    }
    o << ']';
    return o.str();
}

std::string NetworkCollector::now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream o;
    o << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSONL writer  — host_to_jsonl
//  One line per host; open_ports is an inline JSON array.
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::host_to_jsonl(const NetworkHost& h) {
    std::ostringstream o;

    // ── Build open_ports array ────────────────────────────────────────────────
    std::ostringstream ports_json;
    ports_json << '[';
    for (size_t i = 0; i < h.open_ports.size(); ++i) {
        const auto& p = h.open_ports[i];
        if (i) ports_json << ',';
        ports_json << "{"
            << "\"port\":"         << p.port                   << ","
            << "\"protocol\":"     << je(p.protocol)           << ","
            << "\"state\":"        << je(p.state)              << ","
            << "\"service_name\":" << je(p.service_name)       << ","
            << "\"banner\":"       << je(p.banner)             << ","
            << "\"version\":"      << je(p.version)            << ","
            << "\"extra_info\":"   << je(p.extra_info)
            << "}";
    }
    ports_json << ']';

    o << "{"
      << "\"ipv4\":"            << je(h.ipv4)              << ","
      << "\"mac\":"             << je(h.mac)               << ","
      << "\"mac_vendor\":"      << je(h.mac_vendor)        << ","
      << "\"hostname\":"        << je(h.hostname)          << ","
      << "\"ping_ok\":"         << jb(h.ping_ok)           << ","
      << "\"arp_ok\":"          << jb(h.arp_ok)            << ","
      << "\"open_ports\":"      << ports_json.str()        << ","
      << "\"open_port_count\":" << ji(h.open_port_count)   << ","
      << "\"os_guess\":"        << je(h.os_guess)          << ","
      << "\"os_detail\":"       << je(h.os_detail)         << ","
      << "\"os_confidence\":"   << ji(h.os_confidence)     << ","
      << "\"ttl\":"             << ji(h.ttl)               << ","
      << "\"ttl_windows\":"     << jb(h.ttl_windows)       << ","
      << "\"ttl_linux\":"       << jb(h.ttl_linux)         << ","
      << "\"ttl_cisco\":"       << jb(h.ttl_cisco)         << ","
      << "\"tcp_window_size\":" << ji(h.tcp_window_size)   << ","
      << "\"df_bit\":"          << jb(h.df_bit)            << ","
      << "\"generated_at\":"    << je(h.generated_at)      << ","
      << "\"scan_duration_ms\":" << je(h.scan_duration_ms)
      << "}";
    return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 2 — Host discovery helpers
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
//  cidr_to_ips — expands "192.168.1.0/24" to list of host IPs
//  Excludes network address (.0) and broadcast (.255 for /24)
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> NetworkCollector::cidr_to_ips(const std::string& cidr) {
    std::vector<std::string> result;

    size_t slash = cidr.find('/');
    if (slash == std::string::npos) {
        // Single IP
        result.push_back(cidr);
        return result;
    }

    std::string ip_str  = cidr.substr(0, slash);
    int prefix_len      = std::stoi(cidr.substr(slash + 1));
    if (prefix_len < 0 || prefix_len > 32) return result;

    // Parse base IP
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) return result;
    uint32_t base_ip = ntohl(addr.s_addr);

    uint32_t mask        = prefix_len == 0 ? 0u : (~0u << (32 - prefix_len));
    uint32_t network     = base_ip & mask;
    uint32_t broadcast   = network | ~mask;
    uint32_t host_count  = broadcast - network - 1;

    // Guard: avoid scanning /8 or larger by accident
    if (host_count > 65534) {
        log_warn("[NetworkCollector] CIDR /" + std::to_string(prefix_len)
                 + " yields " + std::to_string(host_count)
                 + " hosts — truncating to first 65534.");
        host_count = 65534;
    }

    result.reserve(host_count);
    for (uint32_t i = 1; i <= host_count; ++i) {
        uint32_t host_ip = network + i;
        struct in_addr ha{};
        ha.s_addr = htonl(host_ip);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ha, buf, sizeof(buf));
        result.push_back(buf);
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  auto_detect_cidr — detects local subnet from default interface
//  Returns e.g. "192.168.1.0/24". Falls back to "192.168.1.0/24" on failure.
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::auto_detect_cidr() {
#ifndef _WIN32
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return "192.168.1.0/24";

    std::string result;
    for (struct ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_netmask) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        // Skip loopback
        std::string name(ifa->ifa_name ? ifa->ifa_name : "");
        if (name == "lo" || name.find("lo") == 0) continue;

        auto* sa  = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        auto* nm  = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask);
        uint32_t ip   = ntohl(sa->sin_addr.s_addr);
        uint32_t mask = ntohl(nm->sin_addr.s_addr);
        uint32_t net  = ip & mask;

        // Count prefix bits
        int prefix = 0;
        uint32_t m = mask;
        while (m) { prefix += (m & 1); m >>= 1; }
        // Fix: count leading ones, not all ones
        prefix = 0;
        m = mask;
        for (int b = 31; b >= 0; --b) {
            if (m & (1u << b)) ++prefix;
            else break;
        }

        struct in_addr na{};
        na.s_addr = htonl(net);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &na, buf, sizeof(buf));
        result = std::string(buf) + "/" + std::to_string(prefix);
        break;
    }
    freeifaddrs(ifap);
    return result.empty() ? "192.168.1.0/24" : result;
#else
    // Windows: use GetAdaptersAddresses (preferred over GetAdaptersInfo —
    // handles multiple IPs per adapter and gives adapter type/flags).
    // Skip: loopback, tunnel, virtual VMware/VirtualBox/Hyper-V, VPN adapters.
    // Prefer: Ethernet > Wi-Fi > other.
    std::string result;

    ULONG outBufLen = 16 * 1024;
    std::vector<BYTE> buf(outBufLen);
    ULONG rc = GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()),
        &outBufLen);

    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(outBufLen);
        rc = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()),
            &outBufLen);
    }

    if (rc == NO_ERROR) {
        auto* adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());

        // Score adapters: higher = more preferred
        int best_score = -1;

        for (; adapter; adapter = adapter->Next) {
            // Skip: loopback, tunnel, down interfaces
            if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (adapter->IfType == IF_TYPE_TUNNEL)            continue;
            if (adapter->OperStatus != IfOperStatusUp)        continue;

            // Skip virtual/VPN adapters by description keyword
            // Convert wide description to narrow for simple keyword check
            std::string desc;
            if (adapter->Description) {
                std::wstring wd(adapter->Description);
                desc.resize(wd.size());
                for (size_t i = 0; i < wd.size(); ++i)
                    desc[i] = static_cast<char>(
                        std::tolower(static_cast<unsigned char>(wd[i] < 128 ? wd[i] : '?')));
            }
            // Skip known virtual adapter keywords
            bool is_virtual = (desc.find("vmware")    != std::string::npos ||
                                desc.find("virtualbox")!= std::string::npos ||
                                desc.find("hyper-v")   != std::string::npos ||
                                desc.find("vethernet") != std::string::npos ||
                                desc.find("tap-")      != std::string::npos ||
                                desc.find("tap adapter")!= std::string::npos ||
                                desc.find("vpn")       != std::string::npos ||
                                desc.find("loopback")  != std::string::npos ||
                                desc.find("pseudo")    != std::string::npos ||
                                desc.find("isatap")    != std::string::npos ||
                                desc.find("teredo")    != std::string::npos);
            if (is_virtual) continue;

            // Score: Ethernet=2, Wi-Fi=1, other=0
            int score = 0;
            if (adapter->IfType == IF_TYPE_ETHERNET_CSMACD) score = 2;
            else if (adapter->IfType == IF_TYPE_IEEE80211)  score = 1;

            for (auto* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                auto* sa = reinterpret_cast<struct sockaddr_in*>(
                    ua->Address.lpSockaddr);
                uint32_t ip = ntohl(sa->sin_addr.s_addr);
                // Skip link-local (169.254.x.x)
                if ((ip >> 16) == 0xA9FE) continue;
                // Skip 0.0.0.0
                if (ip == 0) continue;

                // Prefix length from OnLinkPrefixLength
                int prefix = static_cast<int>(ua->OnLinkPrefixLength);
                uint32_t mask = prefix == 0 ? 0u : (~0u << (32 - prefix));
                uint32_t net  = ip & mask;

                struct in_addr na{};
                na.s_addr = htonl(net);
                char cbuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &na, cbuf, sizeof(cbuf));

                if (score > best_score) {
                    best_score = score;
                    result = std::string(cbuf) + "/" + std::to_string(prefix);
                }
                break; // first IPv4 per adapter
            }
        }
    }

    // Fallback if GetAdaptersAddresses failed or found nothing
    if (result.empty()) {
        ULONG olen = sizeof(IP_ADAPTER_INFO);
        std::vector<BYTE> ibuf(olen);
        if (GetAdaptersInfo(reinterpret_cast<PIP_ADAPTER_INFO>(ibuf.data()), &olen)
            == ERROR_BUFFER_OVERFLOW)
            ibuf.resize(olen);
        PIP_ADAPTER_INFO pInfo = reinterpret_cast<PIP_ADAPTER_INFO>(ibuf.data());
        if (GetAdaptersInfo(pInfo, &olen) == NO_ERROR) {
            for (PIP_ADAPTER_INFO p = pInfo; p; p = p->Next) {
                std::string sip = p->IpAddressList.IpAddress.String;
                std::string smk = p->IpAddressList.IpMask.String;
                if (sip == "0.0.0.0" || sip.empty()) continue;
                struct in_addr ia{}, ma{};
                inet_pton(AF_INET, sip.c_str(), &ia);
                inet_pton(AF_INET, smk.c_str(), &ma);
                uint32_t net = ntohl(ia.s_addr) & ntohl(ma.s_addr);
                uint32_t m   = ntohl(ma.s_addr);
                int prefix = 0;
                for (int b = 31; b >= 0; --b) {
                    if (m & (1u << b)) ++prefix; else break;
                }
                struct in_addr na{};
                na.s_addr = htonl(net);
                char cbuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &na, cbuf, sizeof(cbuf));
                result = std::string(cbuf) + "/" + std::to_string(prefix);
                break;
            }
        }
    }

    return result.empty() ? "192.168.1.0/24" : result;
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
//  ping_host — sends a single ICMP echo request, waits timeout_ms
//  Returns true if echo reply received.
//  NOTE: raw sockets require root/CAP_NET_RAW on Linux.
//        Falls back to connect() probe (port 7/echo) if SOCK_RAW fails.
// ─────────────────────────────────────────────────────────────────────────────
bool NetworkCollector::ping_host(const std::string& ip, int timeout_ms,
                                  int& out_ttl) const {
    out_ttl = 0;  // default — will be set if we get an ICMP reply

#ifndef _WIN32
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        // No raw socket permission — fall back to TCP port 7 connect probe.
        // TTL cannot be retrieved in this path; out_ttl stays 0.
        int tsock = socket(AF_INET, SOCK_STREAM, 0);
        if (tsock < 0) return false;
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(7);
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        // Set non-blocking
        int flags = fcntl(tsock, F_GETFL, 0);
        fcntl(tsock, F_SETFL, flags | O_NONBLOCK);
        connect(tsock, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
        fd_set fds; FD_ZERO(&fds); FD_SET(tsock, &fds);
        struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        bool ok = (select(tsock + 1, nullptr, &fds, nullptr, &tv) > 0);
        close(tsock);
        return ok;
    }

    // Request that the kernel passes the IP header through to us so we can
    // read the TTL field from the incoming ICMP ECHO REPLY packet.
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // Build ICMP echo request
    struct {
        uint8_t  type, code;
        uint16_t checksum, id, seq;
    } icmp_pkt{};
    icmp_pkt.type = 8; // ECHO_REQUEST
    icmp_pkt.id   = static_cast<uint16_t>(getpid() & 0xffff);
    icmp_pkt.seq  = 1;
    // Checksum
    uint32_t sum = 0;
    auto* p = reinterpret_cast<uint16_t*>(&icmp_pkt);
    for (size_t i = 0; i < sizeof(icmp_pkt) / 2; ++i) sum += ntohs(p[i]);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    icmp_pkt.checksum = htons(static_cast<uint16_t>(~sum));

    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &dst.sin_addr);

    struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sendto(sock, &icmp_pkt, sizeof(icmp_pkt), 0,
           reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));

    // Receive full IP packet (IP header + ICMP reply).
    // With IP_HDRINCL the kernel includes the 20-byte IPv4 header, so we
    // can read the TTL field directly at byte offset 8.
    unsigned char recv_buf[1024];
    ssize_t n = recv(sock, recv_buf, sizeof(recv_buf), 0);
    close(sock);
    if (n < 20) return false;  // too short to contain an IP header

    // IPv4 header: TTL is at byte offset 8
    out_ttl = static_cast<int>(recv_buf[8]);
    return true;

#else
    // ── Windows ping strategy ─────────────────────────────────────────────────
    // 1) IcmpSendEcho — works without Administrator on Windows Vista+
    //    (icmp.dll is available to normal users)
    //    ICMP_ECHO_REPLY.Options.Ttl carries the TTL from the reply packet.
    // 2) TCP connect fallback — catches hosts that block ICMP but have open
    //    ports; TTL is not available in this path.
    // ─────────────────────────────────────────────────────────────────────────

    // IcmpSendEcho requires reply buffer = sizeof(ICMP_ECHO_REPLY) + data + 8
    const DWORD REPLY_BUF_SIZE = sizeof(ICMP_ECHO_REPLY) + 32 + 8;
    std::vector<BYTE> reply_buf(REPLY_BUF_SIZE);
    char send_data[] = "NetworkCollector";

    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp != INVALID_HANDLE_VALUE) {
        struct in_addr dst{};
        inet_pton(AF_INET, ip.c_str(), &dst);
        DWORD ret = IcmpSendEcho(
            hIcmp, dst.s_addr,
            send_data, static_cast<WORD>(sizeof(send_data)),
            nullptr,
            reply_buf.data(), REPLY_BUF_SIZE,
            static_cast<DWORD>(timeout_ms));
        IcmpCloseHandle(hIcmp);
        if (ret > 0) {
            auto* reply = reinterpret_cast<PICMP_ECHO_REPLY>(reply_buf.data());
            if (reply->Status == 0) {
                // Options.Ttl is the TTL value in the ICMP echo reply packet
                out_ttl = static_cast<int>(reply->Options.Ttl);
                return true;
            }
        }
    }

    // Fallback: TCP connect to common ports.
    // TTL cannot be retrieved here; out_ttl stays 0.
    static const uint16_t FALLBACK_PORTS[] = { 80, 443, 22, 445, 3389, 8080, 0 };
    for (int i = 0; FALLBACK_PORTS[i] != 0; ++i) {
        SOCKET tsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tsock == INVALID_SOCKET) continue;

        u_long nb = 1;
        ioctlsocket(tsock, FIONBIO, &nb);

        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(FALLBACK_PORTS[i]);
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        connect(tsock, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));

        fd_set wfds, efds;
        FD_ZERO(&wfds); FD_SET(tsock, &wfds);
        FD_ZERO(&efds); FD_SET(tsock, &efds);
        int per_port_ms = std::min(timeout_ms, 300);
        struct timeval tv{ per_port_ms / 1000, (per_port_ms % 1000) * 1000 };
        bool open = (select(0, nullptr, &wfds, &efds, &tv) > 0
                     && FD_ISSET(tsock, &wfds));
        closesocket(tsock);
        if (open) return true;
    }
    return false;
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
//  arp_probe — sends an ARP request, returns true if reply received.
//  out_mac is filled with the MAC address string on success.
//  Linux only (raw packet socket). On other platforms: stub returning false.
// ─────────────────────────────────────────────────────────────────────────────
bool NetworkCollector::arp_probe(const std::string& ip, int timeout_ms,
                                 std::string& out_mac) const {
    out_mac.clear();
#if defined(__linux__)
    // Use the kernel ARP cache via /proc/net/arp first (fast, no privileges)
    {
        std::ifstream arp_cache("/proc/net/arp");
        if (arp_cache) {
            std::string line;
            std::getline(arp_cache, line); // skip header
            while (std::getline(arp_cache, line)) {
                std::istringstream ss(line);
                std::string lip, hwtype, flags, mac, mask, iface;
                ss >> lip >> hwtype >> flags >> mac >> mask >> iface;
                if (lip == ip && mac != "00:00:00:00:00:00") {
                    out_mac = mac;
                    return true;
                }
            }
        }
    }
    // Not in cache — send a raw ARP request on the first non-loopback interface
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return false;

    // Find interface index + our MAC/IP
    struct ifreq ifr{};
    // Try to find a suitable interface
    struct ifaddrs* ifap = nullptr;
    std::string iface_name;
    if (getifaddrs(&ifap) == 0) {
        for (struct ifaddrs* ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            if (ifa->ifa_addr->sa_family != AF_INET) continue;
            std::string nm(ifa->ifa_name ? ifa->ifa_name : "");
            if (nm == "lo" || nm.find("lo") == 0) continue;
            iface_name = nm;
            break;
        }
        freeifaddrs(ifap);
    }
    if (iface_name.empty()) { close(sock); return false; }

    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { close(sock); return false; }
    int if_index = ifr.ifr_ifindex;

    // Get our MAC
    uint8_t src_mac[6]{};
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
        memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    // Get our IP
    struct ifreq ifr_ip{};
    strncpy(ifr_ip.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);
    uint8_t src_ip[4]{};
    if (ioctl(sock, SIOCGIFADDR, &ifr_ip) == 0) {
        auto* sa = reinterpret_cast<struct sockaddr_in*>(&ifr_ip.ifr_addr);
        memcpy(src_ip, &sa->sin_addr.s_addr, 4);
    }

    uint8_t dst_ip[4]{};
    inet_pton(AF_INET, ip.c_str(), dst_ip);

    // Build ARP request frame (Ethernet + ARP)
    uint8_t frame[42]{};
    // Ethernet header: destination = broadcast
    memset(frame, 0xff, 6);              // dst MAC = broadcast
    memcpy(frame + 6, src_mac, 6);      // src MAC
    frame[12] = 0x08; frame[13] = 0x06; // EtherType = ARP

    // ARP header
    frame[14] = 0x00; frame[15] = 0x01; // HTYPE = Ethernet
    frame[16] = 0x08; frame[17] = 0x00; // PTYPE = IPv4
    frame[18] = 6;                       // HLEN
    frame[19] = 4;                       // PLEN
    frame[20] = 0x00; frame[21] = 0x01; // OPER = request
    memcpy(frame + 22, src_mac, 6);     // Sender MAC
    memcpy(frame + 28, src_ip,  4);     // Sender IP
    memset(frame + 32, 0x00, 6);        // Target MAC (unknown)
    memcpy(frame + 38, dst_ip,  4);     // Target IP

    struct sockaddr_ll sa_ll{};
    sa_ll.sll_family   = AF_PACKET;
    sa_ll.sll_protocol = htons(ETH_P_ARP);
    sa_ll.sll_ifindex  = if_index;
    sa_ll.sll_halen    = 6;
    memset(sa_ll.sll_addr, 0xff, 6);

    sendto(sock, frame, sizeof(frame), 0,
           reinterpret_cast<struct sockaddr*>(&sa_ll), sizeof(sa_ll));

    // Wait for ARP reply
    struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t recv_buf[60]{};
    while (true) {
        ssize_t n = recv(sock, recv_buf, sizeof(recv_buf), 0);
        if (n < 42) break;
        // Check ARP reply (OPER=0x0002) from target IP
        if (recv_buf[12] != 0x08 || recv_buf[13] != 0x06) continue;
        if (recv_buf[20] != 0x00 || recv_buf[21] != 0x02) continue;
        if (memcmp(recv_buf + 28, dst_ip, 4) != 0) continue;
        // Extract sender MAC
        char mac_str[32];
        snprintf(mac_str, sizeof(mac_str),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 recv_buf[22], recv_buf[23], recv_buf[24],
                 recv_buf[25], recv_buf[26], recv_buf[27]);
        out_mac = mac_str;
        close(sock);
        return true;
    }
    close(sock);
#elif defined(_WIN32)
    // ── Windows ARP probe — no Administrator required ─────────────────────────
    // Strategy:
    //   1. Check Windows ARP cache via GetIpNetTable (no privileges needed)
    //   2. If not cached: send a TCP SYN to port 80/443 to trigger ARP
    //      resolution, then re-check the cache
    // ─────────────────────────────────────────────────────────────────────────

    struct in_addr target_addr{};
    if (inet_pton(AF_INET, ip.c_str(), &target_addr) != 1) return false;
    DWORD target_ip_net = target_addr.s_addr; // network byte order

    // Helper lambda: query ARP cache for target IP
    auto check_arp_cache = [&]() -> bool {
        ULONG size = 0;
        GetIpNetTable(nullptr, &size, FALSE);
        if (size == 0) return false;
        std::vector<BYTE> buf(size + 512); // extra margin
        auto* table = reinterpret_cast<PMIB_IPNETTABLE>(buf.data());
        DWORD rc = GetIpNetTable(table, &size, FALSE);
        if (rc != NO_ERROR && rc != ERROR_INSUFFICIENT_BUFFER) return false;

        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            // Skip invalid / incomplete entries
            if (row.dwType == MIB_IPNET_TYPE_INVALID) continue;
            if (row.dwAddr != target_ip_net) continue;

            // Check MAC is not all-zero
            bool nonzero = false;
            for (DWORD b = 0; b < row.dwPhysAddrLen; ++b)
                if (row.bPhysAddr[b] != 0) { nonzero = true; break; }
            if (!nonzero) continue;

            char mac_str[32];
            snprintf(mac_str, sizeof(mac_str),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     row.bPhysAddr[0], row.bPhysAddr[1], row.bPhysAddr[2],
                     row.bPhysAddr[3], row.bPhysAddr[4], row.bPhysAddr[5]);
            out_mac = mac_str;
            return true;
        }
        return false;
    };

    // First attempt — already in cache?
    if (check_arp_cache()) return true;

    // Not in cache: provoke ARP resolution by attempting a TCP connect.
    // Even a refused connection causes Windows to resolve the MAC.
    static const uint16_t ARP_TRIGGER_PORTS[] = { 80, 443, 445, 22, 3389, 0 };
    for (int i = 0; ARP_TRIGGER_PORTS[i] != 0; ++i) {
        SOCKET tsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tsock == INVALID_SOCKET) continue;
        u_long nb = 1;
        ioctlsocket(tsock, FIONBIO, &nb);
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(ARP_TRIGGER_PORTS[i]);
        sa.sin_addr   = target_addr;
        connect(tsock, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
        fd_set wfds, efds;
        FD_ZERO(&wfds); FD_SET(tsock, &wfds);
        FD_ZERO(&efds); FD_SET(tsock, &efds);
        int wait_ms = std::min(timeout_ms, 400);
        struct timeval tv{ wait_ms / 1000, (wait_ms % 1000) * 1000 };
        select(0, nullptr, &wfds, &efds, &tv);
        closesocket(tsock);
        // Give the stack a moment to update ARP table
        Sleep(20);
        if (check_arp_cache()) return true;
    }

    // Last resort: SendARP (requires no special privilege on modern Windows)
    {
        ULONG mac_buf = 0; // SendARP wants a ULONG for single MAC bytes? No:
        // SendARP signature: (DestIP, SrcIP, pMacAddr, PhyAddrLen)
        BYTE mac_bytes[6]{};
        ULONG mac_len = sizeof(mac_bytes);
        DWORD src_ip = 0; // 0 = let OS choose source IP
        if (SendARP(target_ip_net, src_ip, mac_bytes, &mac_len) == NO_ERROR
            && mac_len >= 6) {
            bool nonzero = false;
            for (int b = 0; b < 6; ++b) if (mac_bytes[b]) { nonzero = true; break; }
            if (nonzero) {
                char mac_str[32];
                snprintf(mac_str, sizeof(mac_str),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         mac_bytes[0], mac_bytes[1], mac_bytes[2],
                         mac_bytes[3], mac_bytes[4], mac_bytes[5]);
                out_mac = mac_str;
                return true;
            }
        }
    }
#else
    (void)timeout_ms;
#endif
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  rdns_lookup — reverse DNS for an IPv4 address
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::rdns_lookup(const std::string& ip) {
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) return "";
    char host[NI_MAXHOST];
    int rc = getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa),
                         host, sizeof(host), nullptr, 0, NI_NAMEREQD);
    return (rc == 0) ? std::string(host) : "";
}

// ─────────────────────────────────────────────────────────────────────────────
//  mac_to_vendor — first 3 bytes (OUI) → vendor name
//  Uses a compact built-in table of the most common OUI prefixes.
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::mac_to_vendor(const std::string& mac) {
    if (mac.size() < 8) return "";
    // Normalize first 8 chars (XX:XX:XX) to upper, strip colons
    std::string oui;
    for (char c : mac.substr(0, 8)) {
        if (c != ':' && c != '-')
            oui += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (oui.size() < 6) return "";
    oui = oui.substr(0, 6);

    // Compact OUI table (top vendors by frequency)
    static const std::pair<const char*, const char*> OUI_TABLE[] = {
        {"000C29", "VMware"},          {"000569", "VMware"},
        {"001C42", "Parallels"},       {"080027", "VirtualBox"},
        {"525400", "QEMU/KVM"},        {"001A11", "Google"},
        {"3C5AB4", "Google"},          {"70B3D5", "IEEE (Private)"},
        {"001B63", "Apple"},           {"002332", "Apple"},
        {"6C40B9", "Apple"},           {"A4C361", "Apple"},
        {"000D3A", "Microsoft"},       {"001DD8", "Microsoft"},
        {"7C1E52", "Microsoft"},       {"0050F2", "Microsoft"},
        {"001AA0", "Dell"},            {"002564", "Dell"},
        {"F04DA2", "Dell"},            {"3417EB", "Dell"},
        {"00D861", "Lenovo"},          {"485B39", "Lenovo"},
        {"70E2840", "HP"},             {"001708", "HP"},
        {"3C4A92", "HP"},              {"001CC4", "Cisco"},
        {"001AA2", "Cisco"},           {"001B53", "Cisco"},
        {"001E14", "Cisco"},           {"00E04C", "Realtek"},
        {"00055D", "Realtek"},         {"001CF0", "Realtek"},
        {"001B21", "Intel"},           {"001CC0", "Intel"},
        {"7085C2", "Intel"},           {"8C16456", "Intel"},
        {"000E2E", "Zyxel"},           {"001349", "Zyxel"},
        {"C4AD34", "Netgear"},         {"001E2A", "Netgear"},
        {"001B2F", "Ubiquiti"},        {"0418D6", "Ubiquiti"},
        {"DC9FDB", "Ubiquiti"},        {"041E64", "Raspberry Pi"},
        {"B827EB", "Raspberry Pi"},    {"DCA632", "Raspberry Pi"},
        {"002215", "TP-Link"},         {"50C7BF", "TP-Link"},
        {"881FA1", "TP-Link"},         {"000000", "Xerox (broadcast)"},
        {nullptr, nullptr}
    };

    for (int i = 0; OUI_TABLE[i].first != nullptr; ++i) {
        if (oui == OUI_TABLE[i].first) return OUI_TABLE[i].second;
    }
    return "";
}

// ─────────────────────────────────────────────────────────────────────────────
//  discover_hosts — runs parallel ping+ARP sweep
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> NetworkCollector::discover_hosts(
    const NetworkCollectorOptions& opts) const
{
    std::string cidr = opts.target_cidr.empty()
                       ? auto_detect_cidr()
                       : opts.target_cidr;
    log_info("[NetworkCollector] Scanning network: " + cidr);

    auto all_ips = cidr_to_ips(cidr);
    log_info("[NetworkCollector] Total IPs to probe: " + std::to_string(all_ips.size()));

    std::vector<std::string> active;
    std::mutex               active_mtx;
    std::atomic<size_t>      done{0};

    // Thread pool — process IPs in batches
    auto worker = [&](size_t start, size_t end) {
        for (size_t i = start; i < end; ++i) {
            const auto& ip = all_ips[i];
            bool alive = false;
            std::string mac;

            if (!opts.skip_ping) {
                int _unused_ttl = 0;
                alive = ping_host(ip, opts.ping_timeout_ms, _unused_ttl);
            }

            if (!alive) {
                // ARP probe regardless of ping result (ARP works even if ICMP blocked)
                bool arp_ok = arp_probe(ip, opts.arp_timeout_ms, mac);
                if (arp_ok) alive = true;
            }

            if (alive) {
                std::lock_guard<std::mutex> lk(active_mtx);
                active.push_back(ip);
            }
            ++done;
        }
    };

    size_t n     = all_ips.size();
    int    nthrd = std::max(1, std::min(opts.max_threads, static_cast<int>(n)));
    size_t chunk = (n + nthrd - 1) / nthrd;

    std::vector<std::thread> threads;
    for (int t = 0; t < nthrd; ++t) {
        size_t s = t * chunk;
        size_t e = std::min(s + chunk, n);
        if (s >= n) break;
        threads.emplace_back(worker, s, e);
    }
    for (auto& th : threads) th.join();

    // Sort results for deterministic output
    std::sort(active.begin(), active.end(), [](const std::string& a, const std::string& b) {
        struct in_addr ia{}, ib{};
        inet_pton(AF_INET, a.c_str(), &ia);
        inet_pton(AF_INET, b.c_str(), &ib);
        return ntohl(ia.s_addr) < ntohl(ib.s_addr);
    });

    log_ok("[NetworkCollector] Active hosts found: " + std::to_string(active.size()));
    return active;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 3 — collect()  — main entry point
// ═════════════════════════════════════════════════════════════════════════════
int NetworkCollector::collect(const NetworkCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);
    output_path_ = fs::path(opts.output_dir) / "raw_network.jsonl";

    std::ofstream f(output_path_, std::ios::out | std::ios::trunc);
    if (!f) {
        log_err("[NetworkCollector] Failed to open output file: "
                + output_path_.string());
        return -1;
    }

    const std::string generated_at = now_iso8601();
    log_info("[NetworkCollector] Scan started at " + generated_at);

    // ── Stage 1: Host discovery ───────────────────────────────────────────────
    auto active_ips = discover_hosts(opts);
    if (active_ips.empty()) {
        log_warn("[NetworkCollector] No active hosts discovered.");
        return 0;
    }

    int count = 0;
    std::mutex file_mtx;

    // ── Stages 2-5 per host (parallel) ───────────────────────────────────────
    auto process_host = [&](const std::string& ip) {
        auto t_start = std::chrono::steady_clock::now();

        NetworkHost host;
        host.ipv4         = ip;
        host.generated_at = generated_at;

        // Re-run ARP to get MAC (may have been found during discovery)
        std::string mac;
        arp_probe(ip, opts.arp_timeout_ms, mac);
        if (!mac.empty()) {
            host.mac        = mac;
            host.mac_vendor = mac_to_vendor(mac);
            host.arp_ok     = true;
        }
        int ping_ttl = 0;
        host.ping_ok = ping_host(ip, opts.ping_timeout_ms, ping_ttl);
        if (ping_ttl > 0) host.ttl = ping_ttl;

        // rDNS
        host.hostname = rdns_lookup(ip);

        // Stage 2: Port scan
        if (!opts.skip_port_scan)
            scan_ports(host, opts);

        // Stage 3: Service identification (offline)
        identify_services(host);

        // Stage 4: Version detection
        if (!opts.skip_version_det)
            detect_versions(host);

        // Stage 5: OS fingerprinting
        if (!opts.skip_os_fp)
            fingerprint_os(host);

        host.open_port_count = static_cast<int>(host.open_ports.size());

        auto t_end = std::chrono::steady_clock::now();
        auto ms    = std::chrono::duration_cast<std::chrono::milliseconds>(
                         t_end - t_start).count();
        host.scan_duration_ms = std::to_string(ms);

        {
            std::lock_guard<std::mutex> lk(file_mtx);
            f << host_to_jsonl(host) << "\n";
            ++count;
        }
    };

    // Parallel processing with thread pool
    int    nthrd = std::max(1, std::min(opts.max_threads,
                                        static_cast<int>(active_ips.size())));
    size_t n     = active_ips.size();
    size_t chunk = (n + nthrd - 1) / nthrd;

    std::vector<std::thread> threads;
    for (int t = 0; t < nthrd; ++t) {
        size_t s = t * chunk;
        size_t e = std::min(s + chunk, n);
        if (s >= n) break;
        threads.emplace_back([&, s, e]() {
            for (size_t i = s; i < e; ++i)
                process_host(active_ips[i]);
        });
    }
    for (auto& th : threads) th.join();

    f.flush();
    f.close();

    log_ok("[NetworkCollector] " + std::to_string(count)
           + " hosts -> " + output_path_.string());
    return count;
}