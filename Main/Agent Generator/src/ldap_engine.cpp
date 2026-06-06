#include "../include/ldap_engine.h"

#include "../include/ldap.h"
#include <ctime>
#include <stdexcept>

// ─────────────────────────────────────────────────────────────────────────────
//  BER-encode a 32-bit integer for use as an LDAP control value.
//
//  The SD_FLAGS control (OID 1.2.840.113556.1.4.801) carries a BER-encoded
//  INTEGER specifying which parts of the security descriptor to return:
//    0x01 = OWNER_SECURITY_INFORMATION
//    0x02 = GROUP_SECURITY_INFORMATION
//    0x04 = DACL_SECURITY_INFORMATION   ← we request only this
//    0x08 = SACL_SECURITY_INFORMATION   (requires SeSecurityPrivilege)
//
//  BER encoding of INTEGER 4 (0x04):
//    0x30 0x03        — SEQUENCE { length 3 }
//    0x02 0x01 0x04   — INTEGER  { length 1, value 4 }
//
//  This is a minimal hand-rolled BER encoder for the single-integer case;
//  no external BER library is required.
// ─────────────────────────────────────────────────────────────────────────────
static std::string ber_encode_sd_flags(unsigned int flags) {
    // Determine how many bytes the integer value needs (big-endian, no leading
    // zero unless the high bit is set to signal positive for BER signed int).
    std::vector<unsigned char> int_bytes;
    if (flags == 0) {
        int_bytes.push_back(0x00);
    } else {
        // Write big-endian bytes, stripping leading zeros
        bool started = false;
        for (int shift = 24; shift >= 0; shift -= 8) {
            unsigned char byte = static_cast<unsigned char>((flags >> shift) & 0xFF);
            if (byte != 0 || started) {
                // Prepend 0x00 if the high bit would make the value appear negative
                if (!started && (byte & 0x80)) int_bytes.push_back(0x00);
                int_bytes.push_back(byte);
                started = true;
            }
        }
        if (!started) int_bytes.push_back(0x00); // flags == 0 handled above
    }

    // INTEGER TLV: 0x02, length, value bytes
    std::vector<unsigned char> int_tlv;
    int_tlv.push_back(0x02);
    int_tlv.push_back(static_cast<unsigned char>(int_bytes.size()));
    int_tlv.insert(int_tlv.end(), int_bytes.begin(), int_bytes.end());

    // SEQUENCE TLV: 0x30, length, integer TLV
    std::vector<unsigned char> seq_tlv;
    seq_tlv.push_back(0x30);
    seq_tlv.push_back(static_cast<unsigned char>(int_tlv.size()));
    seq_tlv.insert(seq_tlv.end(), int_tlv.begin(), int_tlv.end());

    return std::string(reinterpret_cast<const char*>(seq_tlv.data()), seq_tlv.size());
}

// ─────────────────────────────────────────────
//  Internal error diagnosis
//  Maps every common LDAP/WinLDAP result code
//  to a plain-English cause + fix hint.
// ─────────────────────────────────────────────
static std::string diagnose(int rc,
                             const std::string& host,
                             int                port,
                             const std::string& bind_dn,
                             bool               use_tls)
{
    switch (rc) {

    // ── Stub / loader errors ──────────────────────────────────────────────
    case -1: // LDAP_LOCAL_ERROR  (returned by ldap_stub when wldap32 missing)
        return "wldap32.dll could not be loaded or a required symbol "
               "(ldap_initW / ldap_simple_bind_sW / ldap_search_ext_sW) is "
               "missing. Ensure you are running on Windows and that "
               "wldap32.dll is present in System32.";

    case -2: // LDAP_PARAM_ERROR  (returned by ldap_stub for null args)
        return "A null or invalid argument was passed to the LDAP stub. "
               "This is an internal error — please report it.";

    // ── Network / transport ───────────────────────────────────────────────
    case 0x51: // LDAP_SERVER_DOWN
        return "Cannot reach the Domain Controller at " + host + ":" +
               std::to_string(port) + ". "
               "Check that the host is correct, the DC is online, and that "
               "TCP port " + std::to_string(port) + " is not blocked by a "
               "firewall. (Run: Test-NetConnection -ComputerName " + host +
               " -Port " + std::to_string(port) + ")";

    case 0x55: // LDAP_TIMEOUT
        return "The connection to " + host + " timed out. "
               "The DC may be overloaded or unreachable over the network. "
               "Try increasing the timeout value or check network latency.";

    case 0x52: // LDAP_LOCAL_ERROR
        return "A local WinLDAP error occurred before the connection was "
               "established. This usually means ldap_init() failed to "
               "allocate the session handle. Verify the host string is "
               "a valid hostname or IP address.";

    // ── TLS / SSL ─────────────────────────────────────────────────────────
    case 0x5a: // LDAP_CONNECT_ERROR
        if (use_tls)
            return "TLS handshake failed connecting to " + host + ":636. "
                   "Possible causes: (1) the DC's certificate is self-signed "
                   "and not trusted — set SSL=FALSE to use plain LDAP on 389 "
                   "for testing; (2) port 636 is not open; (3) LDAPS is not "
                   "enabled on the DC.";
        return "Connection was refused or reset by " + host + ":" +
               std::to_string(port) + ". "
               "Ensure the LDAP service is running on the DC.";

    // ── Authentication ────────────────────────────────────────────────────
    case 0x31: // LDAP_INVALID_CREDENTIALS
        return "Authentication failed for '" + bind_dn + "'. "
               "Possible causes: (1) wrong password; (2) account is locked "
               "or disabled in Active Directory; (3) the bind DN format is "
               "wrong — use  user@domain.local  or  DOMAIN\\user.";

    case 0x32: // LDAP_INSUFFICIENT_ACCESS
        return "The account '" + bind_dn + "' authenticated successfully "
               "but does not have permission to perform this operation. "
               "Use a Domain Admin or an account with read access to the "
               "directory.";

    case 0x31 + 0x10: // LDAP_UNWILLING_TO_PERFORM (0x35)  — also auth-related
        return "The Domain Controller refused the operation (unwilling to "
               "perform). This can happen when trying to bind without "
               "encryption on a DC that requires signing/sealing. "
               "Try enabling SSL (set SSL=TRUE) or check DC LDAP policies.";

    // ── DN / filter errors ────────────────────────────────────────────────
    case 0x22: // LDAP_INVALID_DN_SYNTAX
        return "The bind DN '" + bind_dn + "' has invalid syntax. "
               "Expected format: CN=User,CN=Users,DC=domain,DC=local  "
               "or UPN: user@domain.local";

    case 0x20: // LDAP_NO_SUCH_OBJECT
        return "The base DN or the object does not exist in the directory. "
               "Check that DOMNAME is set correctly and that the base DN "
               "(DC=...) matches the actual domain.";

    case 0x04: // LDAP_SIZELIMIT_EXCEEDED
        return "The server returned a partial result because the size limit "
               "was exceeded. The data seen so far is still usable.";

    case 0x03: // LDAP_TIMELIMIT_EXCEEDED
        return "The server-side time limit was exceeded during the search. "
               "Try narrowing the search filter or increasing the timeout.";

    // ── Referral / misc ───────────────────────────────────────────────────
    case 0x0a: // LDAP_REFERRAL
        return "The DC returned a referral to another server. "
               "Set DCIP to the correct Domain Controller IP for this domain.";

    case 0x01: // LDAP_OPERATIONS_ERROR
        return "The DC reported a general operations error. "
               "Check the Windows Event Log on the DC for more details "
               "(Event Viewer → Windows Logs → Directory Service).";

    case 0x02: // LDAP_PROTOCOL_ERROR
        return "LDAP protocol error — the server did not understand the "
               "request. Ensure LDAP v3 is supported by the DC "
               "(all modern Windows Server versions support it).";

    default:
        return "LDAP error code 0x" +
               []( int v ) {
                   char buf[16];
                   std::snprintf(buf, sizeof(buf), "%02X", v);
                   return std::string(buf);
               }(rc) +
               " — " + ldap_err2string(rc) +
               ". Check the DC event log for further details.";
    }
}

// ─────────────────────────────────────────────
//  Constructor / Destructor
// ─────────────────────────────────────────────
LDAPEngine::LDAPEngine(const LDAPConfig& cfg) : cfg_(cfg) {}

LDAPEngine::~LDAPEngine() {
    disconnect();
}

// ─────────────────────────────────────────────
//  connect()
// ─────────────────────────────────────────────
bool LDAPEngine::connect() {
    // ── Pre-flight validation ─────────────────────────────────────────────
    if (cfg_.host.empty()) {
        last_error_ = "No host configured. Set DCIP before connecting.";
        log_err(last_error_);
        return false;
    }
    if (cfg_.bind_dn.empty()) {
        last_error_ = "No bind DN configured. Set DOMUSER before connecting.";
        log_err(last_error_);
        return false;
    }
    if (cfg_.password.empty()) {
        last_error_ = "No password configured. Set DOMPASS before connecting.";
        log_err(last_error_);
        return false;
    }
    if (cfg_.port <= 0 || cfg_.port > 65535) {
        last_error_ = "Invalid port: " + std::to_string(cfg_.port) +
                      ". Use 389 (LDAP) or 636 (LDAPS).";
        log_err(last_error_);
        return false;
    }

    // ── TLS / port mismatch warning ───────────────────────────────────────
    if (cfg_.use_tls && cfg_.port == 389)
        log_warn("SSL=TRUE but port is 389. LDAPS normally runs on 636. "
                 "Use 'set port 636' unless the DC is configured otherwise.");
    if (!cfg_.use_tls && cfg_.port == 636)
        log_warn("SSL=FALSE but port is 636. "
                 "Consider enabling SSL with 'set ssl true'.");

    std::string uri = (cfg_.use_tls ? "ldaps://" : "ldap://")
                    + cfg_.host + ":" + std::to_string(cfg_.port);

    // ── Initialize handle ─────────────────────────────────────────────────
    LDAP* ld = nullptr;
    int rc = ldap_initialize(&ld, uri.c_str());
    if (rc != LDAP_SUCCESS || !ld) {
        last_error_ = diagnose(rc != LDAP_SUCCESS ? rc : 0x52,
                               cfg_.host, cfg_.port,
                               cfg_.bind_dn, cfg_.use_tls);
        log_err("[ldap_initialize] " + last_error_);
        return false;
    }

    // ── Protocol version ──────────────────────────────────────────────────
    int version = LDAP_VERSION3;
    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
        log_warn("Could not set LDAP protocol version to v3 — "
                 "the DC may use an older dialect.");
    }

    // ── Network timeout ───────────────────────────────────────────────────
    struct timeval tv { cfg_.timeout, 0 };
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);

    // ── TLS certificate policy ────────────────────────────────────────────
    if (cfg_.use_tls) {
        int tls_demand = LDAP_OPT_X_TLS_ALLOW;
        ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &tls_demand);
    }

    // ── Simple bind ───────────────────────────────────────────────────────
    struct berval cred;
    cred.bv_val = const_cast<char*>(cfg_.password.c_str());
    cred.bv_len = cfg_.password.size();

    rc = ldap_sasl_bind_s(ld,
                          cfg_.bind_dn.c_str(),
                          LDAP_SASL_SIMPLE,
                          &cred,
                          nullptr, nullptr, nullptr);

    if (rc != LDAP_SUCCESS) {
        last_error_ = diagnose(rc, cfg_.host, cfg_.port,
                               cfg_.bind_dn, cfg_.use_tls);
        log_err("[ldap_sasl_bind_s] " + last_error_);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return false;
    }

    ld_        = static_cast<void*>(ld);
    connected_ = true;
    log_ok("Bound to " + uri + " as " + cfg_.bind_dn);
    return true;
}

// ─────────────────────────────────────────────
//  discover_base()
// ─────────────────────────────────────────────
bool LDAPEngine::discover_base() {
    if (!connected_ || !ld_) {
        log_err("discover_base() called while not connected.");
        return false;
    }
    LDAP* ld = static_cast<LDAP*>(ld_);

    char* attrs[] = { const_cast<char*>("defaultNamingContext"),
                      const_cast<char*>("namingContexts"),
                      const_cast<char*>("rootDomainNamingContext"),
                      nullptr };

    LDAPMessage* result = nullptr;
    struct timeval tv { cfg_.timeout, 0 };

    int rc = ldap_search_ext_s(
        ld, "", LDAP_SCOPE_BASE, "(objectClass=*)",
        attrs, 0, nullptr, nullptr, &tv, 0, &result);

    if (rc != LDAP_SUCCESS) {
        if (result) ldap_msgfree(result);
        last_error_ = diagnose(rc, cfg_.host, cfg_.port,
                               cfg_.bind_dn, cfg_.use_tls);
        log_err("[discover_base] " + last_error_);
        return false;
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
        ldap_msgfree(result);
        last_error_ = "RootDSE query returned no entries. "
                      "The DC may restrict anonymous/unauthenticated "
                      "RootDSE access. Try setting DOMNAME manually.";
        log_warn(last_error_);
        return false;
    }

    // Collect all three candidate attributes in one pass, then pick by
    // priority: defaultNamingContext > rootDomainNamingContext > namingContexts.
    std::string dn_default;
    std::string dn_root_domain;
    std::string dn_naming_ctx;

    BerElement* ber      = nullptr;
    char*       attr_name = ldap_first_attribute(ld, entry, &ber);

    while (attr_name) {
        struct berval** bvals = ldap_get_values_len(ld, entry, attr_name);
        if (bvals && bvals[0]) {
            std::string aname(attr_name);
            std::string val(bvals[0]->bv_val, bvals[0]->bv_len);
            if      (aname == "defaultNamingContext"    && dn_default.empty())     dn_default     = val;
            else if (aname == "rootDomainNamingContext" && dn_root_domain.empty()) dn_root_domain = val;
            else if (aname == "namingContexts"          && dn_naming_ctx.empty())  dn_naming_ctx  = val;
        }
        if (bvals) ldap_value_free_len(bvals);
        ldap_memfree(attr_name);
        attr_name = ldap_next_attribute(ld, entry, ber);
    }
    if (ber) ber_free(ber, 0);
    ldap_msgfree(result);

    // Pick the best available value
    bool found = false;
    if (!dn_default.empty()) {
        cfg_.base_dn = dn_default;
        found = true;
    } else if (!dn_root_domain.empty()) {
        cfg_.base_dn = dn_root_domain;
        log_warn("defaultNamingContext not found; using rootDomainNamingContext.");
        found = true;
    } else if (!dn_naming_ctx.empty()) {
        cfg_.base_dn = dn_naming_ctx;
        log_warn("defaultNamingContext not found; using first namingContexts value.");
        found = true;
    }

    if (!found) {
        last_error_ = "RootDSE did not expose a naming context. "
                      "Set DOMNAME manually (e.g. set DOMNAME example.local).";
        log_warn(last_error_);
    }
    return found;
}

// ─────────────────────────────────────────────
//  search()
// ─────────────────────────────────────────────
bool LDAPEngine::search(const std::string&              filter,
                        const std::vector<std::string>& attrs,
                        EntryCallback                   callback)
{
    if (!connected_) {
        last_error_ = "Not connected. Call connect() first.";
        log_err(last_error_);
        return false;
    }
    if (cfg_.base_dn.empty()) {
        last_error_ = "Base DN is not set. "
                      "Set DOMNAME or wait for discover_base() to complete.";
        log_err(last_error_);
        return false;
    }
    if (filter.empty()) {
        last_error_ = "Search filter is empty.";
        log_err(last_error_);
        return false;
    }

    LDAP* ld = static_cast<LDAP*>(ld_);

    std::vector<char*> attr_ptrs;
    for (const auto& a : attrs)
        attr_ptrs.push_back(const_cast<char*>(a.c_str()));
    attr_ptrs.push_back(nullptr);

    // ── SD_FLAGS control — same as search_base() ─────────────────────────────
    // AD only returns the full ntSecurityDescriptor (owner + DACL) when the
    // client sends SD_FLAGS with OWNER|DACL bits.  Without it the subtree
    // search returns an empty blob → owner_sid / isaclprotected stay blank.
    bool needs_sd_s = false;
    for (const auto& a : attrs) {
        std::string al = a;
        for (char& c : al) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (al == "ntsecuritydescriptor") { needs_sd_s = true; break; }
    }
    std::string    sd_ber_s;
    LDAPControl    sd_ctrl_s{};
    LDAPControl*   sd_list_s[2] = { nullptr, nullptr };
    void*          sctrls_s     = nullptr;
    if (needs_sd_s) {
        // OWNER_SECURITY_INFORMATION (0x01) | DACL_SECURITY_INFORMATION (0x04) = 0x05
        sd_ber_s = ber_encode_sd_flags(0x05);
        sd_ctrl_s.ldctl_oid             = const_cast<char*>(LDAP_SERVER_SD_FLAGS_OID);
        sd_ctrl_s.ldctl_value.bv_val    = const_cast<char*>(sd_ber_s.data());
        sd_ctrl_s.ldctl_value.bv_len    = sd_ber_s.size();
        sd_ctrl_s.ldctl_iscritical      = 0;
        sd_list_s[0]                    = &sd_ctrl_s;
        sctrls_s                        = static_cast<void*>(sd_list_s);
    }
    // ─────────────────────────────────────────────────────────────────────────

    LDAPMessage*   result = nullptr;
    struct timeval tv { cfg_.timeout, 0 };

    int rc = ldap_search_ext_s(
        ld,
        cfg_.base_dn.c_str(),
        LDAP_SCOPE_SUBTREE,
        filter.c_str(),
        attr_ptrs.data(),
        0,
        sctrls_s, nullptr,
        &tv,
        0,
        &result);

    // LDAP_SIZELIMIT_EXCEEDED (0x04) is non-fatal — partial results are usable
    if (rc != LDAP_SUCCESS && rc != 0x04) {
        last_error_ = diagnose(rc, cfg_.host, cfg_.port,
                               cfg_.bind_dn, cfg_.use_tls);
        log_err("[search] " + last_error_);
        if (result) ldap_msgfree(result);
        return false;
    }
    if (rc == 0x04) {
        log_warn("Server size limit reached — results may be incomplete. "
                 "Consider paginating or narrowing the search filter.");
    }

    for (LDAPMessage* entry = ldap_first_entry(ld, result);
         entry != nullptr;
         entry = ldap_next_entry(ld, entry))
    {
        AttrMap    entry_map;
        BerElement* ber = nullptr;

        for (char* attr_name = ldap_first_attribute(ld, entry, &ber);
             attr_name != nullptr;
             attr_name = ldap_next_attribute(ld, entry, ber))
        {
            struct berval** bvals =
                ldap_get_values_len(ld, entry, attr_name);
            if (bvals) {
                std::vector<std::string> vals;
                for (int i = 0; bvals[i] != nullptr; ++i)
                    vals.emplace_back(bvals[i]->bv_val, bvals[i]->bv_len);
                entry_map[std::string(attr_name)] = std::move(vals);
                ldap_value_free_len(bvals);
            }
            ldap_memfree(attr_name);
        }
        if (ber) ber_free(ber, 0);

        try {
            callback(entry_map);
        } catch (const std::exception& ex) {
            log_err(std::string("Exception in search callback: ") + ex.what());
            ldap_msgfree(result);
            return false;
        } catch (...) {
            log_err("Unknown exception in search callback.");
            ldap_msgfree(result);
            return false;
        }
    }

    ldap_msgfree(result);
    return true;
}


// ─────────────────────────────────────────────
//  search_base()
//  Single-object base-scope lookup by DN.
//  Used for constructed attributes (e.g. tokenGroups) that AD only
//  returns when the search base IS the object and scope = BASE.
// ─────────────────────────────────────────────
bool LDAPEngine::search_base(const std::string&              dn,
                              const std::vector<std::string>& attrs,
                              EntryCallback                   callback)
{
    if (!connected_) {
        last_error_ = "Not connected. Call connect() first.";
        log_err(last_error_);
        return false;
    }
    if (dn.empty()) {
        last_error_ = "search_base: DN is empty.";
        log_err(last_error_);
        return false;
    }

    LDAP* ld = static_cast<LDAP*>(ld_);

    std::vector<char*> attr_ptrs;
    for (const auto& a : attrs)
        attr_ptrs.push_back(const_cast<char*>(a.c_str()));
    attr_ptrs.push_back(nullptr);

    // ── SD_FLAGS control ─────────────────────────────────────────────────────
    // AD only returns nTSecurityDescriptor (DACL included) when the client
    // sends the SD_FLAGS server control with DACL_SECURITY_INFORMATION (0x04).
    // Without it the DC returns only the owner/group portions, leaving the
    // DACL empty — which causes all ACE-based admin rules (3, 4, 6, 7) to
    // produce false negatives for every user.
    //
    // We attach this control only when the caller actually requests the
    // nTSecurityDescriptor attribute, so routine base-scope lookups
    // (e.g. tokenGroups) are not affected.
    bool needs_sd = false;
    for (const auto& a : attrs) {
        // Case-insensitive match for "nTSecurityDescriptor"
        std::string al = a;
        for (char& c : al) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (al == "ntsecuritydescriptor") { needs_sd = true; break; }
    }

    // BER-encoded value storage and control structs must outlive the
    // ldap_search_ext_s call — keep them on the stack here.
    std::string sd_ber_value;
    LDAPControl  sd_ctrl{};
    LDAPControl* sd_ctrl_list[2] = { nullptr, nullptr };
    void*        sctrls           = nullptr;

    if (needs_sd) {
        // OWNER_SECURITY_INFORMATION (0x01) | DACL_SECURITY_INFORMATION (0x04) = 0x05
        sd_ber_value            = ber_encode_sd_flags(0x05);
        sd_ctrl.ldctl_oid       = const_cast<char*>(LDAP_SERVER_SD_FLAGS_OID);
        sd_ctrl.ldctl_value.bv_val = const_cast<char*>(sd_ber_value.data());
        sd_ctrl.ldctl_value.bv_len = sd_ber_value.size();
        sd_ctrl.ldctl_iscritical   = 0;  // non-critical: proceed even if DC ignores it
        sd_ctrl_list[0]            = &sd_ctrl;
        sctrls                     = static_cast<void*>(sd_ctrl_list);
    }
    // ─────────────────────────────────────────────────────────────────────────

    LDAPMessage*   result = nullptr;
    struct timeval tv { cfg_.timeout, 0 };

    int rc = ldap_search_ext_s(
        ld,
        dn.c_str(),           // base = the object itself
        LDAP_SCOPE_BASE,      // scope = base (single object only)
        "(objectClass=*)",    // filter must match everything
        attr_ptrs.data(),
        0,
        sctrls,               // SD_FLAGS control (or nullptr)
        nullptr,              // client controls
        &tv,
        0,
        &result);

    if (rc != LDAP_SUCCESS) {
        // Non-fatal: tokenGroups / nTSecurityDescriptor may simply be absent
        last_error_ = diagnose(rc, cfg_.host, cfg_.port,
                               cfg_.bind_dn, cfg_.use_tls);
        log_warn("[search_base] " + last_error_);
        if (result) ldap_msgfree(result);
        return false;
    }

    for (LDAPMessage* entry = ldap_first_entry(ld, result);
         entry != nullptr;
         entry = ldap_next_entry(ld, entry))
    {
        AttrMap     entry_map;
        BerElement* ber = nullptr;

        for (char* attr_name = ldap_first_attribute(ld, entry, &ber);
             attr_name != nullptr;
             attr_name = ldap_next_attribute(ld, entry, ber))
        {
            struct berval** bvals =
                ldap_get_values_len(ld, entry, attr_name);
            if (bvals) {
                std::vector<std::string> vals;
                for (int i = 0; bvals[i] != nullptr; ++i)
                    vals.emplace_back(bvals[i]->bv_val, bvals[i]->bv_len);
                entry_map[std::string(attr_name)] = std::move(vals);
                ldap_value_free_len(bvals);
            }
            ldap_memfree(attr_name);
        }
        if (ber) ber_free(ber, 0);

        try {
            callback(entry_map);
        } catch (const std::exception& ex) {
            log_err(std::string("Exception in search_base callback: ") + ex.what());
            ldap_msgfree(result);
            return false;
        } catch (...) {
            log_err("Unknown exception in search_base callback.");
            ldap_msgfree(result);
            return false;
        }
    }

    ldap_msgfree(result);
    return true;
}
// ─────────────────────────────────────────────
//  disconnect()
// ─────────────────────────────────────────────
void LDAPEngine::disconnect() {
    if (connected_ && ld_) {
        ldap_unbind_ext_s(static_cast<LDAP*>(ld_), nullptr, nullptr);
        ld_        = nullptr;
        connected_ = false;
    }
}

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────
std::string LDAPEngine::ldap_err_str(int rc) {
    const char* s = ldap_err2string(rc);
    return s ? std::string(s)
             : "unknown error (0x" + [](int v){
                   char b[16];
                   std::snprintf(b,sizeof(b),"%02X",v);
                   return std::string(b);
               }(rc) + ")";
}

std::string LDAPEngine::filetime_to_str(const std::string& ft_raw) {
    if (ft_raw.empty() || ft_raw == "0" || ft_raw == "9223372036854775807")
        return "Never";
    try {
        long long ft = std::stoll(ft_raw);
        if (ft == 0) return "Never";
        long long unix_ts = ft / 10000000LL - 11644473600LL;
        if (unix_ts <= 0) return "Never";
        std::time_t t = static_cast<std::time_t>(unix_ts);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S",
                      std::gmtime(&t));
        return std::string(buf) + " UTC";
    } catch (...) {
        return ft_raw;
    }
}