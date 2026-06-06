#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  CertificateCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct CertificateCollectorOptions {
    std::string output_dir  = "raw_cache";
    int         max_results = 0;          // 0 = no limit
};

// ─────────────────────────────────────────────────────────────────────────────
//  CertificateCollector  — Phase 1 / Extract
//
//  Two targeted LDAP queries only:
//    (1) Certificate Templates
//          base : CN=Certificate Templates,CN=Public Key Services,
//                 CN=Services,<configNC>
//          filter: (objectClass=pKICertificateTemplate)
//          output: raw_cert_templates.ndjson
//
//    (2) PKI Infrastructure Objects (Enrollment Services, NTAuthCertificates,
//          Certification Authorities, AIA, CDP)
//          base : five separate sub-trees under
//                 CN=Public Key Services,CN=Services,<configNC>
//          output: raw_pki_objects.ndjson
//
//  No SMB / RPC contact at collection time.
//  CA RPC properties (EditFlags, InterfaceFlags, CA Security Descriptor)
//  are collected separately by a future RPC stage and stored in
//  raw_ca_rpc.ndjson — offline analysis reads all three files.
//
//  Output schema — raw_cert_templates.ndjson (one template per line):
//  {
//    "dn"                        : "CN=User,CN=Certificate Templates,...",
//    "cn"                        : "User",
//    "display_name"              : "User",
//    "object_guid"               : "{...}",
//    "when_created"              : "2024-01-01T00:00:00Z",
//    "when_changed"              : "2024-06-01T00:00:00Z",
//    "flags_raw"                 : 131680,
//    "revision"                  : 4,
//    "schema_version"            : 1,
//    "mspki_ra_signature"        : 0,
//    "mspki_enrollment_flag"     : 41,
//    "mspki_private_key_flag"    : 16,
//    "mspki_certificate_name_flag": 402653184,
//    "mspki_minimal_key_size"    : 2048,
//    "mspki_template_schema_version": 1,
//    "mspki_cert_template_oid"   : "1.3.6.1.4.1.311.21.8...",
//    "pki_default_key_spec"      : 1,
//    "pki_key_usage"             : "a0",          // hex of raw bytes
//    "pki_max_issuing_depth"     : 0,
//    "pki_expiration_period"     : "1y",
//    "pki_overlap_period"        : "6w",
//    "pki_extended_key_usage"    : ["1.3.6.1.5.5.7.3.2", ...],
//    "pki_default_csps"          : [],
//    "mspki_certificate_application_policy": [],
//    "mspki_ra_application_policies": [],
//    "mspki_supersede_templates" : [],
//    "mspki_subject_name"        : null,
//    "mspki_oid_localizedname"   : "",
//    "mspki_ra_policies"         : [],
//    "nt_security_descriptor_hex": "0400...",      // raw SD bytes as hex
//    "generated_at"              : "2026-05-29T07:50:43Z"
//  }
//
//  Output schema — raw_pki_objects.ndjson (one PKI object per line):
//  {
//    "category"              : "Enrollment Services",
//    "dn"                    : "CN=CORP-CA,CN=Enrollment Services,...",
//    "cn"                    : "CORP-CA",
//    "display_name"          : "",
//    "object_guid"           : "{...}",
//    "object_class"          : ["top","pKIEnrollmentService"],
//    "dns_host_name"         : "ca01.corp.local",
//    "flags_raw"             : null,
//    "revision"              : null,
//    "ca_certificate_hex"    : "3082...",         // DER bytes as hex (NTAuthCerts / CA)
//    "ca_certificate_dn"     : "CN=CORP-CA,...",
//    "certificate_templates" : ["User","Machine",...],
//    "pki_expiration_period" : "1y",
//    "pki_overlap_period"    : "6w",
//    "nt_security_descriptor_hex": "0400...",
//    "when_created"          : "...",
//    "when_changed"          : "...",
//    "generated_at"          : "..."
//  }
//
//  Offline analysis (CertOfflineProcessor) reads both files and emits:
//    domain_cert_templates.ndjson  — enriched templates with ESC flag summary
//    domain_pki_objects.ndjson     — enriched PKI objects with ACE analysis
// ─────────────────────────────────────────────────────────────────────────────
class CertificateCollector {
public:
    explicit CertificateCollector(LDAPEngine& engine);

    // Main entry: runs both template + PKI object queries.
    // Returns total objects written (templates + pki objects), or -1 on error.
    int collect(const CertificateCollectorOptions& opts = {});

    fs::path templates_output_path()   const { return templates_output_path_; }
    fs::path pki_objects_output_path() const { return pki_objects_output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    templates_output_path_;
    fs::path    pki_objects_output_path_;

    // ── Sub-collectors ────────────────────────────────────────────────────────
    int collect_templates  (const std::string& config_nc,
                            const std::string& output_dir,
                            const std::string& generated_at,
                            int max_results);

    int collect_pki_objects(const std::string& config_nc,
                            const std::string& output_dir,
                            const std::string& generated_at);

    // ── LDAP attribute lists ──────────────────────────────────────────────────
    static std::vector<std::string> template_attrs();
    static std::vector<std::string> pki_object_attrs();

    // ── NDJSON serializers ────────────────────────────────────────────────────
    std::string template_to_ndjson   (const LDAPEngine::AttrMap& entry,
                                      const std::string& generated_at) const;

    std::string pki_object_to_ndjson (const LDAPEngine::AttrMap& entry,
                                      const std::string& category,
                                      const std::string& generated_at) const;

    // ── Period helpers (pKIExpirationPeriod / pKIOverlapPeriod) ──────────────
    // Converts raw bytes (little-endian FILETIME negative offset) to a
    // human-readable string like "1y", "6w", "2d 4h".
    static std::string parse_pki_period(const std::string& raw_bytes);

    // ── GUID helpers ──────────────────────────────────────────────────────────
    static std::string format_guid(const std::string& raw_bytes);

    // ── Timestamp helpers ─────────────────────────────────────────────────────
    static std::string generalized_time_to_iso(const std::string& gt);

    // ── JSON helpers (same convention as ComputerCollector / OfflineProcessor) ─
    static std::string je (const std::string& s);
    static std::string jb (bool v);
    static std::string ji (int v);
    static std::string jnull();
    static std::string ja (const std::vector<std::string>& v);
    static std::string now_iso8601();
};