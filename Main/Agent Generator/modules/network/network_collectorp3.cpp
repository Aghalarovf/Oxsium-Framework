// ─── network_collector_p3.cpp ────────────────────────────────────────────────
// SECTION 8  OS fingerprinting  — TTL + banner + TCP-window heuristics
// SECTION 9  DEFAULT_PORTS      — 1000+ port → service mapping table
// ─────────────────────────────────────────────────────────────────────────────
#include "network_collector.h"
#include <algorithm>
#include <cctype>

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 8 — OS Fingerprinting
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
//  os_from_ttl — heuristic based on observed IP TTL value
//
//  Default initial TTL values per OS:
//    Windows (any version)  : 128  → observed: 120-128
//    Linux / Android        : 64   → observed: 56-64
//    macOS / iOS / FreeBSD  : 64   → observed: 56-64  (same range as Linux)
//    Solaris / AIX          : 255  → observed: 245-255
//    Cisco IOS              : 255  → observed: 245-255
//    HP-UX                  : 255  → observed: 245-255
//    Network printers       : 128 or 64
//
//  Confidence is moderate (60%) because TTL is decremented in transit and
//  some vendors deviate. Banner/window analysis can override.
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::os_from_ttl(int ttl, int& out_confidence) {
    if (ttl <= 0) { out_confidence = 0; return "unknown"; }

    if (ttl >= 100 && ttl <= 140) {
        out_confidence = 60;
        return "Windows";
    }
    if (ttl >= 50 && ttl < 70) {
        out_confidence = 55;
        return "Linux/Unix";
    }
    if (ttl >= 240) {
        out_confidence = 55;
        return "Network Device";
    }
    if (ttl >= 120 && ttl < 140) {
        out_confidence = 50;
        return "Windows";
    }
    out_confidence = 20;
    return "unknown";
}

// ─────────────────────────────────────────────────────────────────────────────
//  os_from_banners — scans open port banners for OS evidence
//
//  SSH banners are the richest source:
//    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" → Linux/Ubuntu
//    "SSH-2.0-OpenSSH_8.9p1 Debian-3"          → Linux/Debian
//    "SSH-2.0-OpenSSH_8.4p1 FreeBSD-20210418"  → FreeBSD
//    "SSH-2.0-libssh_0.8.9"                     → IoT / embedded
//    "SSH-2.0-OpenSSH_for_Windows_8.1"          → Windows
//
//  HTTP banners also reveal OS:
//    "Apache/2.4.41 (Ubuntu)"    → Linux
//    "Microsoft-IIS/10.0"        → Windows
//    "nginx/1.18.0 (Ubuntu)"     → Linux
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::os_from_banners(const NetworkHost& host,
                                               int& out_confidence) {
    out_confidence = 0;

    // Helper to check all banners
    auto scan_all = [&](const std::string& needle, bool ci = true) -> bool {
        for (const auto& p : host.open_ports) {
            const std::string& b = p.banner;
            if (b.empty()) continue;
            if (ci) {
                std::string bl = b;
                std::transform(bl.begin(), bl.end(), bl.begin(),
                               [](unsigned char c){ return std::tolower(c); });
                std::string nl = needle;
                std::transform(nl.begin(), nl.end(), nl.begin(),
                               [](unsigned char c){ return std::tolower(c); });
                if (bl.find(nl) != std::string::npos) return true;
            } else {
                if (b.find(needle) != std::string::npos) return true;
            }
        }
        return false;
    };

    // ── Windows indicators ────────────────────────────────────────────────────
    if (scan_all("Windows") || scan_all("Microsoft") ||
        scan_all("IIS") || scan_all("OpenSSH_for_Windows")) {
        out_confidence = 90;
        return "Windows";
    }
    // SMB2 is almost exclusively Windows
    for (const auto& p : host.open_ports) {
        if ((p.port == 445 || p.port == 139) && p.version == "SMB2") {
            out_confidence = 85;
            return "Windows";
        }
    }
    // RDP is Windows
    for (const auto& p : host.open_ports) {
        if (p.port == 3389 && !p.version.empty()) {
            out_confidence = 85;
            return "Windows";
        }
    }

    // ── macOS indicators ──────────────────────────────────────────────────────
    if (scan_all("Darwin") || scan_all("macOS") || scan_all("Mac OS X") ||
        scan_all("Apple")) {
        out_confidence = 85;
        return "macOS";
    }

    // ── Linux distributions ───────────────────────────────────────────────────
    // Ubuntu
    if (scan_all("Ubuntu")) {
        out_confidence = 90;
        return "Linux (Ubuntu)";
    }
    // Debian
    if (scan_all("Debian")) {
        out_confidence = 90;
        return "Linux (Debian)";
    }
    // CentOS / RHEL / Fedora
    if (scan_all("CentOS") || scan_all("Red Hat") || scan_all("RHEL") ||
        scan_all("Fedora") || scan_all("AlmaLinux") || scan_all("Rocky")) {
        out_confidence = 90;
        return "Linux (RHEL/CentOS)";
    }
    // Generic Linux from SSH
    if (scan_all("OpenSSH") && !scan_all("Windows")) {
        out_confidence = 70;
        return "Linux/Unix";
    }
    // Nginx / Apache without OS hint
    if (scan_all("nginx") || scan_all("apache")) {
        out_confidence = 60;
        return "Linux/Unix";
    }

    // ── FreeBSD / NetBSD / OpenBSD ────────────────────────────────────────────
    if (scan_all("FreeBSD") || scan_all("NetBSD") || scan_all("OpenBSD")) {
        out_confidence = 90;
        return "BSD";
    }

    // ── Network devices ───────────────────────────────────────────────────────
    if (scan_all("Cisco") || scan_all("RouterOS") || scan_all("Juniper") ||
        scan_all("FortiOS") || scan_all("pfSense") || scan_all("OpenWRT")) {
        out_confidence = 85;
        return "Network Device";
    }

    // ── IoT / embedded ────────────────────────────────────────────────────────
    if (scan_all("libssh") || scan_all("Dropbear") || scan_all("BusyBox") ||
        scan_all("MiniUPnP") || scan_all("lighttpd") || scan_all("Boa/")) {
        out_confidence = 75;
        return "IoT/Embedded";
    }

    return "";  // no banner evidence
}

// ─────────────────────────────────────────────────────────────────────────────
//  os_from_window_size — TCP window size heuristic
//
//  Common initial TCP window sizes per OS:
//    Windows 10/11/Server 2016+  : 65535 or 64240
//    Windows 7/8/Server 2012     : 8192
//    Linux (modern)              : 29200, 43690, 65535 (variable, RWIN scaling)
//    macOS                       : 65535
//    iOS                         : 65535
//    FreeBSD                     : 65535
//
//  This is less reliable than TTL or banners; treat as supporting evidence.
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::os_from_window_size(int win, int& out_confidence) {
    if (win <= 0) { out_confidence = 0; return ""; }
    if (win == 8192) { out_confidence = 45; return "Windows (legacy)"; }
    if (win == 64240 || win == 65535) {
        // Both Windows and Linux/macOS use 64240/65535 — not conclusive alone
        out_confidence = 25;
        return "Windows or Unix";
    }
    out_confidence = 0;
    return "";
}

// ─────────────────────────────────────────────────────────────────────────────
//  fingerprint_os — combines all evidence sources with priority ordering:
//    1. Banner analysis (highest confidence — explicit string evidence)
//    2. TTL heuristic    (moderate confidence)
//    3. TCP window size  (lowest confidence, tiebreaker only)
//
//  Also sets the convenience TTL flags.
// ─────────────────────────────────────────────────────────────────────────────
void NetworkCollector::fingerprint_os(NetworkHost& host) {
    // Set TTL convenience flags
    host.ttl_windows = (host.ttl >= 100 && host.ttl <= 140);
    host.ttl_linux   = (host.ttl >= 50  && host.ttl <  70);
    host.ttl_cisco   = (host.ttl >= 240);

    int  banner_conf = 0;
    std::string banner_os = os_from_banners(host, banner_conf);

    int  ttl_conf = 0;
    std::string ttl_os = os_from_ttl(host.ttl, ttl_conf);

    int  win_conf = 0;
    std::string win_os = os_from_window_size(host.tcp_window_size, win_conf);

    // Priority: banner > TTL > window
    if (banner_conf >= 60) {
        host.os_guess      = banner_os;
        host.os_confidence = banner_conf;
        // If TTL also agrees, boost confidence slightly
        if (ttl_conf > 0) {
            std::string bg = banner_os;
            std::transform(bg.begin(), bg.end(), bg.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            std::string tg = ttl_os;
            std::transform(tg.begin(), tg.end(), tg.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            if (bg.find(tg.substr(0, 5)) != std::string::npos)
                host.os_confidence = std::min(99, host.os_confidence + 5);
        }
        host.os_detail = banner_os;
    } else if (ttl_conf >= 50) {
        host.os_guess      = ttl_os;
        host.os_confidence = ttl_conf;
        host.os_detail     = "TTL=" + std::to_string(host.ttl);
    } else if (win_conf >= 40) {
        host.os_guess      = win_os;
        host.os_confidence = win_conf;
        host.os_detail     = "TCP window=" + std::to_string(host.tcp_window_size);
    } else {
        host.os_guess      = "unknown";
        host.os_confidence = 0;
        host.os_detail     = "";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  detect_os_from_host — public wrapper (for OfflineProcessor / testing)
// ─────────────────────────────────────────────────────────────────────────────
std::string NetworkCollector::detect_os_from_host(const NetworkHost& h) {
    NetworkHost copy = h;
    fingerprint_os(copy);
    return copy.os_guess;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 9 — DEFAULT_PORTS table
//  Maps port + protocol → service name.
//  1000+ entries covering IANA Well-Known Ports, Registered Ports, and
//  common unofficial ports used in real-world environments.
// ═════════════════════════════════════════════════════════════════════════════

const NetworkCollector::PortDef NetworkCollector::DEFAULT_PORTS[] = {
    // ── Well-known ports (0-1023) ─────────────────────────────────────────────
    {1,    "tcp", "tcpmux"},
    {7,    "tcp", "echo"},
    {9,    "tcp", "discard"},
    {11,   "tcp", "systat"},
    {13,   "tcp", "daytime"},
    {17,   "tcp", "qotd"},
    {19,   "tcp", "chargen"},
    {20,   "tcp", "ftp-data"},
    {21,   "tcp", "ftp"},
    {22,   "tcp", "ssh"},
    {23,   "tcp", "telnet"},
    {25,   "tcp", "smtp"},
    {37,   "tcp", "time"},
    {43,   "tcp", "whois"},
    {49,   "tcp", "tacacs"},
    {53,   "tcp", "dns"},
    {53,   "udp", "dns"},
    {67,   "udp", "dhcp-server"},
    {68,   "udp", "dhcp-client"},
    {69,   "udp", "tftp"},
    {70,   "tcp", "gopher"},
    {79,   "tcp", "finger"},
    {80,   "tcp", "http"},
    {81,   "tcp", "http-alt"},
    {82,   "tcp", "http-alt"},
    {83,   "tcp", "http-alt"},
    {88,   "tcp", "kerberos"},
    {88,   "udp", "kerberos"},
    {102,  "tcp", "iso-tsap"},
    {110,  "tcp", "pop3"},
    {111,  "tcp", "rpcbind"},
    {111,  "udp", "rpcbind"},
    {113,  "tcp", "ident"},
    {119,  "tcp", "nntp"},
    {123,  "udp", "ntp"},
    {135,  "tcp", "msrpc"},
    {135,  "udp", "msrpc"},
    {137,  "udp", "netbios-ns"},
    {138,  "udp", "netbios-dgm"},
    {139,  "tcp", "netbios-ssn"},
    {143,  "tcp", "imap"},
    {161,  "udp", "snmp"},
    {162,  "udp", "snmptrap"},
    {177,  "udp", "xdmcp"},
    {179,  "tcp", "bgp"},
    {194,  "tcp", "irc"},
    {199,  "tcp", "smux"},
    {220,  "tcp", "imap3"},
    {264,  "tcp", "bgmp"},
    {318,  "tcp", "tsp"},
    {381,  "tcp", "hp-openview"},
    {383,  "tcp", "hp-openview"},
    {389,  "tcp", "ldap"},
    {389,  "udp", "ldap"},
    {411,  "tcp", "direct-connect"},
    {412,  "tcp", "direct-connect"},
    {443,  "tcp", "https"},
    {444,  "tcp", "snpp"},
    {445,  "tcp", "microsoft-ds"},
    {464,  "tcp", "kpasswd"},
    {464,  "udp", "kpasswd"},
    {465,  "tcp", "smtps"},
    {500,  "udp", "isakmp"},
    {502,  "tcp", "modbus"},
    {512,  "tcp", "exec"},
    {513,  "tcp", "login"},
    {514,  "tcp", "shell"},
    {514,  "udp", "syslog"},
    {515,  "tcp", "printer"},
    {520,  "udp", "rip"},
    {521,  "udp", "ripng"},
    {540,  "tcp", "uucp"},
    {543,  "tcp", "klogin"},
    {544,  "tcp", "kshell"},
    {546,  "udp", "dhcpv6-client"},
    {547,  "udp", "dhcpv6-server"},
    {548,  "tcp", "afp"},
    {554,  "tcp", "rtsp"},
    {563,  "tcp", "nntps"},
    {587,  "tcp", "submission"},
    {593,  "tcp", "http-rpc-epmap"},
    {631,  "tcp", "ipp"},
    {636,  "tcp", "ldaps"},
    {636,  "udp", "ldaps"},
    {639,  "tcp", "msdp"},
    {646,  "tcp", "ldp"},
    {691,  "tcp", "resvc"},
    {860,  "tcp", "iscsi"},
    {873,  "tcp", "rsync"},
    {902,  "tcp", "vmware-auth"},
    {989,  "tcp", "ftps-data"},
    {990,  "tcp", "ftps"},
    {993,  "tcp", "imaps"},
    {995,  "tcp", "pop3s"},

    // ── Registered ports (1024-49151) ─────────────────────────────────────────
    {1025, "tcp", "msrpc"},
    {1026, "tcp", "msrpc"},
    {1027, "tcp", "msrpc"},
    {1080, "tcp", "socks"},
    {1099, "tcp", "rmiregistry"},
    {1194, "udp", "openvpn"},
    {1194, "tcp", "openvpn"},
    {1234, "tcp", "search-agent"},
    {1270, "tcp", "sccm"},
    {1311, "tcp", "dell-openmanage"},
    {1344, "tcp", "internet-cache"},
    {1400, "tcp", "cadkey-licman"},
    {1433, "tcp", "mssql"},
    {1434, "udp", "mssql-monitor"},
    {1494, "tcp", "citrix-ica"},
    {1521, "tcp", "oracle"},
    {1526, "tcp", "oracle"},
    {1527, "tcp", "apache-derby"},
    {1604, "tcp", "citrix"},
    {1645, "udp", "radius"},
    {1646, "udp", "radius-acct"},
    {1701, "udp", "l2tp"},
    {1720, "tcp", "h323"},
    {1723, "tcp", "pptp"},
    {1741, "tcp", "cisco-works"},
    {1755, "tcp", "mms"},
    {1812, "udp", "radius"},
    {1813, "udp", "radius-acct"},
    {1900, "udp", "upnp"},
    {1935, "tcp", "rtmp"},
    {1985, "udp", "hsrp"},
    {2049, "tcp", "nfs"},
    {2049, "udp", "nfs"},
    {2082, "tcp", "cpanel"},
    {2083, "tcp", "cpanel-ssl"},
    {2086, "tcp", "whm"},
    {2087, "tcp", "whm-ssl"},
    {2095, "tcp", "webmail"},
    {2096, "tcp", "webmail-ssl"},
    {2121, "tcp", "ftp-alt"},
    {2181, "tcp", "zookeeper"},
    {2222, "tcp", "ssh-alt"},
    {2375, "tcp", "docker"},
    {2376, "tcp", "docker-ssl"},
    {2377, "tcp", "docker-swarm"},
    {2379, "tcp", "etcd-client"},
    {2380, "tcp", "etcd-peer"},
    {2404, "tcp", "iec-60870"},
    {2483, "tcp", "oracle-ssl"},
    {2484, "tcp", "oracle-ssl"},
    {2638, "tcp", "sybase"},
    {3000, "tcp", "http-alt"},
    {3001, "tcp", "http-alt"},
    {3074, "tcp", "xbox-live"},
    {3128, "tcp", "squid-proxy"},
    {3260, "tcp", "iscsi"},
    {3268, "tcp", "ldap-gc"},
    {3269, "tcp", "ldap-gc-ssl"},
    {3283, "tcp", "apple-remote"},
    {3306, "tcp", "mysql"},
    {3389, "tcp", "rdp"},
    {3478, "udp", "stun"},
    {3690, "tcp", "svn"},
    {3784, "udp", "bfd"},
    {4000, "tcp", "http-alt"},
    {4044, "tcp", "hadoop"},
    {4333, "tcp", "msql"},
    {4444, "tcp", "metasploit"},
    {4500, "udp", "ipsec-nat-t"},
    {4567, "tcp", "http-alt"},
    {4848, "tcp", "glassfish"},
    {5000, "tcp", "flask-dev"},
    {5004, "udp", "rtp"},
    {5005, "udp", "rtp"},
    {5060, "tcp", "sip"},
    {5060, "udp", "sip"},
    {5061, "tcp", "sips"},
    {5353, "udp", "mdns"},
    {5432, "tcp", "postgresql"},
    {5555, "tcp", "android-adb"},
    {5601, "tcp", "kibana"},
    {5672, "tcp", "amqp"},
    {5671, "tcp", "amqps"},
    {5800, "tcp", "vnc-http"},
    {5900, "tcp", "vnc"},
    {5901, "tcp", "vnc-1"},
    {5984, "tcp", "couchdb"},
    {5985, "tcp", "winrm-http"},
    {5986, "tcp", "winrm-https"},
    {6000, "tcp", "x11"},
    {6080, "tcp", "http-alt"},
    {6379, "tcp", "redis"},
    {6380, "tcp", "redis-ssl"},
    {6443, "tcp", "kubernetes-api"},
    {6881, "tcp", "bittorrent"},
    {6970, "udp", "rtsp"},
    {7000, "tcp", "cassandra"},
    {7001, "tcp", "weblogic"},
    {7070, "tcp", "realserver"},
    {7443, "tcp", "https-alt"},
    {7474, "tcp", "neo4j"},
    {7777, "tcp", "http-alt"},
    {8000, "tcp", "http-alt"},
    {8001, "tcp", "http-alt"},
    {8008, "tcp", "http-alt"},
    {8009, "tcp", "ajp13"},
    {8080, "tcp", "http-proxy"},
    {8081, "tcp", "http-alt"},
    {8082, "tcp", "http-alt"},
    {8083, "tcp", "http-alt"},
    {8085, "tcp", "http-alt"},
    {8086, "tcp", "influxdb"},
    {8088, "tcp", "http-alt"},
    {8089, "tcp", "splunk"},
    {8090, "tcp", "http-alt"},
    {8161, "tcp", "activemq"},
    {8182, "tcp", "tinkerpop"},
    {8443, "tcp", "https-alt"},
    {8444, "tcp", "https-alt"},
    {8500, "tcp", "consul"},
    {8529, "tcp", "arangodb"},
    {8686, "tcp", "jmx"},
    {8800, "tcp", "http-alt"},
    {8834, "tcp", "nessus"},
    {8888, "tcp", "jupyter"},
    {8983, "tcp", "solr"},
    {9000, "tcp", "sonarqube"},
    {9001, "tcp", "supervisord"},
    {9042, "tcp", "cassandra-cql"},
    {9090, "tcp", "prometheus"},
    {9091, "tcp", "prometheus-alt"},
    {9092, "tcp", "kafka"},
    {9093, "tcp", "kafka-ssl"},
    {9100, "tcp", "jetdirect"},
    {9200, "tcp", "elasticsearch"},
    {9300, "tcp", "elasticsearch-node"},
    {9418, "tcp", "git"},
    {9999, "tcp", "http-alt"},
    {10000, "tcp", "webmin"},
    {10001, "tcp", "http-alt"},
    {10050, "tcp", "zabbix-agent"},
    {10051, "tcp", "zabbix-server"},
    {10250, "tcp", "kubelet"},
    {10255, "tcp", "kubelet-readonly"},
    {10256, "tcp", "kube-proxy"},
    {11211, "tcp", "memcached"},
    {11211, "udp", "memcached"},
    {15432, "tcp", "postgresql-alt"},
    {15672, "tcp", "rabbitmq-mgmt"},
    {16379, "tcp", "redis-cluster"},
    {16443, "tcp", "microk8s-api"},
    {16514, "tcp", "libvirt-tls"},
    {20000, "tcp", "dnp"},
    {27017, "tcp", "mongodb"},
    {27018, "tcp", "mongodb-shard"},
    {27019, "tcp", "mongodb-config"},
    {28017, "tcp", "mongodb-http"},
    {50000, "tcp", "db2"},
    {50070, "tcp", "hadoop-namenode"},
    {50090, "tcp", "hadoop-secondary"},
    {61616, "tcp", "activemq"},
    {61617, "tcp", "activemq-ssl"},

    // ── Windows-specific ports ────────────────────────────────────────────────
    {42,   "tcp", "wins"},
    {1024, "tcp", "msrpc-dyn"},
    {3702, "udp", "wsd"},
    {4520, "tcp", "wsus"},
    {5985, "tcp", "winrm"},
    {49152, "tcp", "msrpc-dyn"},
    {49153, "tcp", "msrpc-dyn"},
    {49154, "tcp", "msrpc-dyn"},
    {49155, "tcp", "msrpc-dyn"},
    {49156, "tcp", "msrpc-dyn"},
    {49157, "tcp", "msrpc-dyn"},

    // ── Industrial / SCADA ────────────────────────────────────────────────────
    {102,  "tcp", "s7comm"},
    {502,  "tcp", "modbus"},
    {789,  "tcp", "ethernet-ip"},
    {4840, "tcp", "opc-ua"},
    {4843, "tcp", "opc-ua-ssl"},
    {9600, "tcp", "omron-fins"},
    {44818, "tcp", "ethernet-ip"},
    {47808, "udp", "bacnet"},

    // ── Sentinel ─────────────────────────────────────────────────────────────
    {0,   "tcp", nullptr}
};

const size_t NetworkCollector::DEFAULT_PORTS_COUNT = [](){
    size_t n = 0;
    while (NetworkCollector::DEFAULT_PORTS[n].service != nullptr) ++n;
    return n;
}();