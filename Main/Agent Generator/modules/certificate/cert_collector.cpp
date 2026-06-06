// ─── certificate_collector.cpp ───────────────────────────────────────────────
//  Phase 1 — AD CS Certificate Template & PKI Object Collector
//
//  Two LDAP queries only (minimum possible):
//    (1) All pKICertificateTemplate objects under the Configuration NC
//    (2) Five PKI infrastructure containers under Public Key Services
//
//  No RPC / SMB contact. CA-side properties (EditFlags, InterfaceFlags,
//  CA Security Descriptor) are collected by a separate RPC stage.
//
//  Offline analysis: CertOfflineProcessor (offline_processorp_cert.cpp)
// ─────────────────────────────────────────────────────────────────────────────
#include "cert_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
//  PKI infrastructure bases — mirrors template_enumeration.py ESC5_PKI_OBJECT_BASES
//  label, DN suffix under CN=Public Key Services,CN=Services,<config_nc>, scope
//  scope: "ONE" = LDAP_SCOPE_ONELEVEL (direct children), "BASE" = single object
// ─────────────────────────────────────────────────────────────────────────────
struct PkiBase {
    const char* label;
    const char* dn_suffix;   // appended after "CN=Public Key Services,CN=Services,<config_nc>"
    bool        one_level;   // true = ONELEVEL, false = BASE
};

static const PkiBase PKI_BASES[] = {
    { "Enrollment Services",   "CN=Enrollment Services",   true  },
    { "NTAuthCertificates",    "CN=NTAuthCertificates",    false },
    { "Certification Authorities","CN=Certification Authorities", true },
    { "AIA",                   "CN=AIA",                   true  },
    { "CDP",                   "CN=CDP",                   true  },
    { nullptr, nullptr, false }
};

// ─────────────────────────────────────────────────────────────────────────────
//  Constructor
// ─────────────────────────────────────────────────────────────────────────────
CertificateCollector::CertificateCollector(LDAPEngine& engine) : engine_(engine) {}

// ─────────────────────────────────────────────────────────────────────────────
//  template_attrs  — mirrors TEMPLATE_ATTRIBUTES from template_enumeration.py
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> CertificateCollector::template_attrs() {
    return {
        // Identity & metadata
        "objectClass",
        "cn",
        "distinguishedName",
        "instanceType",
        "whenCreated",
        "whenChanged",
        "name",
        "displayName",
        "objectGUID",
        "flags",
        "revision",
        "nTSecurityDescriptor",
        // Core PKI attributes
        "pKIDefaultKeySpec",
        "pKIKeyUsage",
        "pKIMaxIssuingDepth",
        "pKICriticalExtensions",
        "pKIExpirationPeriod",
        "pKIOverlapPeriod",
        "pKIExtendedKeyUsage",
        "pKIDefaultCSPs",
        // msPKI-* attributes (ESC relevant)
        "msPKI-Key-Usage",
        "msPKI-RA-Signature",
        "msPKI-Enrollment-Flag",
        "msPKI-Private-Key-Flag",
        "msPKI-Certificate-Name-Flag",
        "msPKI-Minimal-Key-Size",
        "msPKI-Subject-Name",
        "msPKI-OID-Localizedname",
        "msPKI-Template-Schema-Version",
        "msPKI-Template-Minor-Revision",
        "msPKI-Cert-Template-OID",
        "msPKI-Certificate-Application-Policy",
        "msPKI-RA-Application-Policies",
        "msPKI-Supersede-Templates",
        "msPKI-RA-Auth-Descriptor",
        "msPKI-Auto-Enrollment-Flag",
        "msPKI-RA-Policies",
        "msPKI-Asymmetric-Key-Usage",
        "msPKI-Site-Enrollment-Servers",
        // ESC10: weak certificate mapping
        "altSecurityIdentities",
    };
}

// ─────────────────────────────────────────────────────────────────────────────
//  pki_object_attrs  — mirrors PKI_OBJECT_ATTRIBUTES from template_enumeration.py
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> CertificateCollector::pki_object_attrs() {
    return {
        "objectClass",
        "cn",
        "distinguishedName",
        "instanceType",
        "whenCreated",
        "whenChanged",
        "name",
        "displayName",
        "objectGUID",
        "nTSecurityDescriptor",
        "flags",
        "revision",
        "cACertificate",
        "cACertificateDN",
        "certificateTemplates",
        "dNSHostName",
        "pKIExpirationPeriod",
        "pKIOverlapPeriod",
    };
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect — entry point
// ─────────────────────────────────────────────────────────────────────────────
int CertificateCollector::collect(const CertificateCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);

    // Derive Configuration NC from the base DN set in the engine config.
    // e.g. "DC=corp,DC=local" -> "CN=Configuration,DC=corp,DC=local"
    const std::string& base_dn = engine_.cfg_.base_dn;
    if (base_dn.empty()) {
        log_err("[CertCollector] base_dn is empty — connect and set DOMNAME first.");
        return -1;
    }
    const std::string config_nc = "CN=Configuration," + base_dn;

    log_info("[CertCollector] Configuration NC : " + config_nc);

    const std::string generated_at = now_iso8601();

    int template_count = collect_templates(
        config_nc, opts.output_dir, generated_at, opts.max_results);
    if (template_count < 0) return -1;

    int pki_count = collect_pki_objects(
        config_nc, opts.output_dir, generated_at);
    if (pki_count < 0) return -1;

    log_ok("[CertCollector] Done — "
        + std::to_string(template_count) + " template(s), "
        + std::to_string(pki_count)      + " PKI object(s)");

    return template_count + pki_count;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_templates
//  LDAP query #1: all pKICertificateTemplate objects
// ─────────────────────────────────────────────────────────────────────────────
int CertificateCollector::collect_templates(
    const std::string& config_nc,
    const std::string& output_dir,
    const std::string& generated_at,
    int max_results)
{
    templates_output_path_ = fs::path(output_dir) / "raw_cert_templates.ndjson";

    std::ofstream f(templates_output_path_, std::ios::binary);
    if (!f) {
        log_err("[CertCollector] Failed to open: " + templates_output_path_.string());
        return -1;
    }

    const std::string base =
        "CN=Certificate Templates,CN=Public Key Services,CN=Services," + config_nc;

    const std::string filter = "(objectClass=pKICertificateTemplate)";

    log_info("[CertCollector] Template query base : " + base);

    int count = 0;
    // Temporarily set base DN to the templates container, then restore.
    const std::string saved_base = engine_.cfg_.base_dn;
    engine_.cfg_.base_dn = base;
    bool ok = engine_.search(filter, template_attrs(),
        [&](const LDAPEngine::AttrMap& entry) {
            if (max_results > 0 && count >= max_results) return;
            f << template_to_ndjson(entry, generated_at) << "\n";
            ++count;
        });
    engine_.cfg_.base_dn = saved_base;

    if (!ok) {
        log_info("[CertCollector] Template LDAP search returned 0 results — AD CS likely not deployed.");
    }

    log_ok("[CertCollector] raw_cert_templates.ndjson <- "
        + std::to_string(count) + " template(s)");
    return count;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_pki_objects
//  LDAP query #2 (actually 5 searches, one per PKI container)
// ─────────────────────────────────────────────────────────────────────────────
int CertificateCollector::collect_pki_objects(
    const std::string& config_nc,
    const std::string& output_dir,
    const std::string& generated_at)
{
    pki_objects_output_path_ = fs::path(output_dir) / "raw_pki_objects.ndjson";

    std::ofstream f(pki_objects_output_path_, std::ios::binary);
    if (!f) {
        log_err("[CertCollector] Failed to open: " + pki_objects_output_path_.string());
        return -1;
    }

    const std::string pks_base =
        "CN=Public Key Services,CN=Services," + config_nc;

    // ── Pre-flight: probe whether Public Key Services container exists at all.
    //   If even this root is missing, AD CS is not deployed — skip all 5 queries
    //   and emit a single informational message instead of 5 warnings.
    bool ca_deployed = false;
    {
        const std::string saved = engine_.cfg_.base_dn;
        engine_.cfg_.base_dn = "CN=Enrollment Services," + pks_base;
        engine_.search("(objectClass=*)", {"cn"},
            [&](const LDAPEngine::AttrMap&) { ca_deployed = true; });
        engine_.cfg_.base_dn = saved;
    }

    if (!ca_deployed) {
        log_info("[CertCollector] AD CS (Enrollment Services) not found — "
                 "CA role not deployed in this domain. PKI collection skipped.");
        log_ok("[CertCollector] raw_pki_objects.ndjson <- 0 PKI object(s)");
        return 0;
    }

    int total = 0;

    for (const PkiBase* pb = PKI_BASES; pb->label != nullptr; ++pb) {
        const std::string base = std::string(pb->dn_suffix) + "," + pks_base;

        int count = 0;
        if (!pb->one_level) {
            engine_.search_base(base, pki_object_attrs(),
                [&](const LDAPEngine::AttrMap& entry) {
                    f << pki_object_to_ndjson(entry, pb->label, generated_at) << "\n";
                    ++count;
                    ++total;
                });
        } else {
            const std::string saved_base = engine_.cfg_.base_dn;
            engine_.cfg_.base_dn = base;
            engine_.search("(objectClass=*)", pki_object_attrs(),
                [&](const LDAPEngine::AttrMap& entry) {
                    f << pki_object_to_ndjson(entry, pb->label, generated_at) << "\n";
                    ++count;
                    ++total;
                });
            engine_.cfg_.base_dn = saved_base;
        }

        if (count > 0) {
            log_ok(std::string("[CertCollector]   [") + pb->label + "] "
                + std::to_string(count) + " object(s)");
        }
        // Silently skip empty containers — normal when CA has no objects there
    }

    log_ok("[CertCollector] raw_pki_objects.ndjson <- "
        + std::to_string(total) + " PKI object(s)");
    return total;
}

// ─────────────────────────────────────────────────────────────────────────────
//  template_to_ndjson
// ─────────────────────────────────────────────────────────────────────────────
std::string CertificateCollector::template_to_ndjson(
    const LDAPEngine::AttrMap& e,
    const std::string& generated_at) const
{
    auto str  = [&](const std::string& k) -> std::string {
        auto it = e.find(k);
        return (it != e.end() && !it->second.empty()) ? it->second[0] : "";
    };
    auto strs = [&](const std::string& k) -> std::vector<std::string> {
        auto it = e.find(k);
        return (it != e.end()) ? it->second : std::vector<std::string>{};
    };
    auto int_val = [&](const std::string& k, int def = 0) -> int {
        const std::string v = str(k);
        if (v.empty()) return def;
        try { return std::stoi(v); } catch (...) { return def; }
    };

    // Raw SD bytes stored as binary by LDAPEngine — surfaced as hex
    std::string sd_hex;
    {
        auto it = e.find("nTSecurityDescriptor");
        if (it != e.end() && !it->second.empty()) {
            const std::string& raw = it->second[0];
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (unsigned char c : raw) oss << std::setw(2) << (int)c;
            sd_hex = oss.str();
        }
    }

    // pKIKeyUsage — raw bytes as hex
    std::string pki_key_usage_hex;
    {
        auto it = e.find("pKIKeyUsage");
        if (it != e.end() && !it->second.empty()) {
            const std::string& raw = it->second[0];
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (unsigned char c : raw) oss << std::setw(2) << (int)c;
            pki_key_usage_hex = oss.str();
        }
    }

    // pKIExpirationPeriod / pKIOverlapPeriod — binary FILETIME → human string
    const std::string expiry  = parse_pki_period(str("pKIExpirationPeriod"));
    const std::string overlap = parse_pki_period(str("pKIOverlapPeriod"));

    // objectGUID → formatted GUID string
    const std::string guid = format_guid(str("objectGUID"));

    // Timestamps
    const std::string when_created = generalized_time_to_iso(str("whenCreated"));
    const std::string when_changed = generalized_time_to_iso(str("whenChanged"));

    std::ostringstream row;
    row << "{"
        // Identity
        << "\"dn\":"               << je(str("distinguishedName"))          << ","
        << "\"cn\":"               << je(str("cn"))                         << ","
        << "\"display_name\":"     << je(str("displayName"))                << ","
        << "\"object_guid\":"      << je(guid)                              << ","
        << "\"when_created\":"     << je(when_created)                      << ","
        << "\"when_changed\":"     << je(when_changed)                      << ","
        // General flags
        << "\"flags_raw\":"        << ji(int_val("flags"))                  << ","
        << "\"revision\":"         << ji(int_val("revision"))               << ","
        // Core msPKI integers
        << "\"mspki_ra_signature\":"            << ji(int_val("msPKI-RA-Signature"))           << ","
        << "\"mspki_enrollment_flag\":"         << ji(int_val("msPKI-Enrollment-Flag"))        << ","
        << "\"mspki_private_key_flag\":"        << ji(int_val("msPKI-Private-Key-Flag"))       << ","
        << "\"mspki_certificate_name_flag\":"   << ji(int_val("msPKI-Certificate-Name-Flag")) << ","
        << "\"mspki_minimal_key_size\":"        << ji(int_val("msPKI-Minimal-Key-Size"))       << ","
        << "\"mspki_template_schema_version\":" << ji(int_val("msPKI-Template-Schema-Version")) << ","
        << "\"mspki_template_minor_revision\":" << ji(int_val("msPKI-Template-Minor-Revision")) << ","
        << "\"mspki_cert_template_oid\":"       << je(str("msPKI-Cert-Template-OID"))         << ","
        << "\"mspki_subject_name\":"            << ji(int_val("msPKI-Subject-Name", -1))       << ","
        << "\"mspki_auto_enrollment_flag\":"    << ji(int_val("msPKI-Auto-Enrollment-Flag"))   << ","
        << "\"mspki_asymmetric_key_usage\":"    << ji(int_val("msPKI-Asymmetric-Key-Usage"))   << ","
        << "\"mspki_oid_localizedname\":"       << je(str("msPKI-OID-Localizedname"))          << ","
        << "\"mspki_ra_auth_descriptor\":"      << je(str("msPKI-RA-Auth-Descriptor"))         << ","
        // Core PKI
        << "\"pki_default_key_spec\":"      << ji(int_val("pKIDefaultKeySpec"))  << ","
        << "\"pki_max_issuing_depth\":"     << ji(int_val("pKIMaxIssuingDepth")) << ","
        << "\"pki_key_usage_hex\":"         << je(pki_key_usage_hex)             << ","
        << "\"pki_expiration_period\":"     << je(expiry)                        << ","
        << "\"pki_overlap_period\":"        << je(overlap)                       << ","
        // Arrays
        << "\"pki_extended_key_usage\":"               << ja(strs("pKIExtendedKeyUsage"))              << ","
        << "\"pki_default_csps\":"                     << ja(strs("pKIDefaultCSPs"))                   << ","
        << "\"pki_critical_extensions\":"              << ja(strs("pKICriticalExtensions"))            << ","
        << "\"mspki_certificate_application_policy\":" << ja(strs("msPKI-Certificate-Application-Policy")) << ","
        << "\"mspki_ra_application_policies\":"        << ja(strs("msPKI-RA-Application-Policies"))   << ","
        << "\"mspki_ra_policies\":"                    << ja(strs("msPKI-RA-Policies"))               << ","
        << "\"mspki_supersede_templates\":"            << ja(strs("msPKI-Supersede-Templates"))       << ","
        << "\"mspki_site_enrollment_servers\":"        << ja(strs("msPKI-Site-Enrollment-Servers"))   << ","
        << "\"alt_security_identities\":"              << ja(strs("altSecurityIdentities"))           << ","
        // Raw security descriptor
        << "\"nt_security_descriptor_hex\":" << je(sd_hex) << ","
        << "\"generated_at\":"               << je(generated_at)
        << "}";

    return row.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  pki_object_to_ndjson
// ─────────────────────────────────────────────────────────────────────────────
std::string CertificateCollector::pki_object_to_ndjson(
    const LDAPEngine::AttrMap& e,
    const std::string& category,
    const std::string& generated_at) const
{
    auto str  = [&](const std::string& k) -> std::string {
        auto it = e.find(k);
        return (it != e.end() && !it->second.empty()) ? it->second[0] : "";
    };
    auto strs = [&](const std::string& k) -> std::vector<std::string> {
        auto it = e.find(k);
        return (it != e.end()) ? it->second : std::vector<std::string>{};
    };
    auto int_opt = [&](const std::string& k) -> std::string {
        // Returns JSON null if absent, else integer
        const std::string v = str(k);
        if (v.empty()) return "null";
        try { return std::to_string(std::stoi(v)); } catch (...) { return "null"; }
    };

    // Raw SD as hex
    std::string sd_hex;
    {
        auto it = e.find("nTSecurityDescriptor");
        if (it != e.end() && !it->second.empty()) {
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (unsigned char c : it->second[0]) oss << std::setw(2) << (int)c;
            sd_hex = oss.str();
        }
    }

    // cACertificate as hex (DER bytes)
    std::string ca_cert_hex;
    {
        auto it = e.find("cACertificate");
        if (it != e.end() && !it->second.empty()) {
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (unsigned char c : it->second[0]) oss << std::setw(2) << (int)c;
            ca_cert_hex = oss.str();
        }
    }

    const std::string guid        = format_guid(str("objectGUID"));
    const std::string when_created = generalized_time_to_iso(str("whenCreated"));
    const std::string when_changed = generalized_time_to_iso(str("whenChanged"));
    const std::string expiry  = parse_pki_period(str("pKIExpirationPeriod"));
    const std::string overlap = parse_pki_period(str("pKIOverlapPeriod"));

    std::ostringstream row;
    row << "{"
        << "\"category\":"           << je(category)                  << ","
        << "\"dn\":"                  << je(str("distinguishedName"))  << ","
        << "\"cn\":"                  << je(str("cn"))                 << ","
        << "\"display_name\":"        << je(str("displayName"))        << ","
        << "\"object_guid\":"         << je(guid)                      << ","
        << "\"object_class\":"        << ja(strs("objectClass"))       << ","
        << "\"dns_host_name\":"        << je(str("dNSHostName"))        << ","
        << "\"flags_raw\":"           << int_opt("flags")              << ","
        << "\"revision\":"            << int_opt("revision")           << ","
        << "\"ca_certificate_hex\":"  << je(ca_cert_hex)               << ","
        << "\"ca_certificate_dn\":"   << je(str("cACertificateDN"))    << ","
        << "\"certificate_templates\":" << ja(strs("certificateTemplates")) << ","
        << "\"pki_expiration_period\":" << je(expiry)                  << ","
        << "\"pki_overlap_period\":"    << je(overlap)                 << ","
        << "\"nt_security_descriptor_hex\":" << je(sd_hex)             << ","
        << "\"when_created\":"        << je(when_created)              << ","
        << "\"when_changed\":"        << je(when_changed)              << ","
        << "\"generated_at\":"        << je(generated_at)
        << "}";

    return row.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_pki_period
//  pKIExpirationPeriod / pKIOverlapPeriod are stored as 8-byte little-endian
//  FILETIME values representing a negative time offset (100-nanosecond ticks).
//  Mirrors template_enumeration.py parse_filetime().
// ─────────────────────────────────────────────────────────────────────────────
std::string CertificateCollector::parse_pki_period(const std::string& raw) {
    if (raw.size() < 8) return "";

    // Read 8-byte little-endian int64
    long long val = 0;
    for (int i = 7; i >= 0; --i)
        val = (val << 8) | (unsigned char)raw[i];

    if (val == 0) return "0";
    if (val > 0) return std::to_string(val); // unexpected positive — surface raw

    // Negative = relative time offset (100-ns ticks)
    long long ticks   = -val;
    long long seconds = ticks / 10000000LL;
    long long days    = seconds / 86400;
    long long hours   = (seconds % 86400) / 3600;
    long long weeks   = days / 7;
    long long rem_days = days % 7;
    long long years   = weeks / 52;
    long long rem_weeks = weeks % 52;

    std::ostringstream out;
    if (years)     { out << years     << "y"; }
    if (rem_weeks) { out << rem_weeks << "w"; }
    if (rem_days)  { out << rem_days  << "d"; }
    if (hours)     { out << hours     << "h"; }
    if (out.str().empty()) out << "0";
    return out.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  format_guid  — 16 raw bytes → "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
//  Windows mixed-endian GUID format (first 3 components are LE).
// ─────────────────────────────────────────────────────────────────────────────
std::string CertificateCollector::format_guid(const std::string& raw) {
    if (raw.size() < 16) return "";
    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    char buf[39];
    std::snprintf(buf, sizeof(buf),
        "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        b[3], b[2], b[1], b[0],
        b[5], b[4],
        b[7], b[6],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15]);
    return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
//  generalized_time_to_iso  — "YYYYMMDDHHmmss.0Z" → "YYYY-MM-DDTHH:MM:SSZ"
// ─────────────────────────────────────────────────────────────────────────────
std::string CertificateCollector::generalized_time_to_iso(const std::string& gt) {
    if (gt.size() < 14) return gt;
    return gt.substr(0,4)  + "-" + gt.substr(4,2)  + "-" + gt.substr(6,2)
         + "T" + gt.substr(8,2) + ":" + gt.substr(10,2) + ":" + gt.substr(12,2) + "Z";
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSON helpers — mirrors ComputerCollector conventions
// ─────────────────────────────────────────────────────────────────────────────
std::string CertificateCollector::je(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) {
                    char esc[8];
                    std::snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char)c);
                    out += esc;
                } else {
                    out += c;
                }
        }
    }
    out += "\"";
    return out;
}
std::string CertificateCollector::jb(bool v)  { return v ? "true" : "false"; }
std::string CertificateCollector::ji(int v)   { return std::to_string(v); }
std::string CertificateCollector::jnull()     { return "null"; }

std::string CertificateCollector::ja(const std::vector<std::string>& v) {
    std::string out = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += ",";
        out += je(v[i]);
    }
    out += "]";
    return out;
}

std::string CertificateCollector::now_iso8601() {
    auto now   = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &t);
#else
    gmtime_r(&t, &utc);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buf;
}