// WinLDAP dynamic loader shim
//
// ldap.h must be included BEFORE windows.h.  windows.h pulls in winldap.h
// which redefines berval, LDAPMessage, BerElement, and LDAPControl.
// By including our ldap.h first we establish our own definitions; the
// LDAPControl struct in ldap.h is guarded with #ifndef so winldap.h's
// later definition does not cause a redefinition error.
#include "../include/ldap.h"
#include <windows.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>

// PortableLDAPControl: type alias so the sctrls conversion code below can
// refer to our ldap.h LDAPControl by a name that is unambiguous even after
// windows.h/winldap.h has been pulled in.
using PortableLDAPControl = LDAPControl;

// Provide missing LDAP constants/types that our shim expects when the
// portable `include/ldap.h` does not define them (avoid pulling in
// platform headers at top level to keep build portable).
#ifndef LDAP_LOCAL_ERROR
#define LDAP_LOCAL_ERROR (-1)
#endif
#ifndef LDAP_PARAM_ERROR
#define LDAP_PARAM_ERROR (-2)
#endif
#ifndef LDAP_SERVER_DOWN
#define LDAP_SERVER_DOWN 81
#endif
#ifndef LDAP_PORT
#define LDAP_PORT 389
#endif
#ifndef LDAP_SSL_PORT
#define LDAP_SSL_PORT 636
#endif

// Ensure l_timeval exists for WinLDAP calls that use it.
#if !defined(_L_TIMEVAL_DEFINED) && !defined(__L_TIMEVAL_DEFINED)
struct l_timeval { long tv_sec; long tv_usec; };
#define _L_TIMEVAL_DEFINED
#endif

static HMODULE g_wldap = nullptr;

// Function pointer types we need
using PF_ldap_initW = LDAP* (WINAPI*)(PWCHAR, ULONG);
using PF_ldap_sslinitW = LDAP* (WINAPI*)(PWCHAR, ULONG, ULONG);
using PF_ldap_simple_bind_sW = ULONG (WINAPI*)(LDAP*, PWCHAR, PWCHAR);
using PF_ldap_unbind_s = ULONG (WINAPI*)(LDAP*);
using PF_ldap_search_ext_sW = ULONG (WINAPI*)(LDAP*, PWCHAR, ULONG, PWCHAR, PWCHAR*, ULONG, void*, void*, void*, ULONG, LDAPMessage**);
using PF_ldap_first_entry = LDAPMessage* (WINAPI*)(LDAP*, LDAPMessage*);
using PF_ldap_next_entry = LDAPMessage* (WINAPI*)(LDAP*, LDAPMessage*);
using PF_ldap_first_attributeW = PWCHAR (WINAPI*)(LDAP*, LDAPMessage*, BerElement**);
using PF_ldap_next_attributeW = PWCHAR (WINAPI*)(LDAP*, LDAPMessage*, BerElement*);
using PF_ldap_get_values_lenW = struct berval** (WINAPI*)(LDAP*, LDAPMessage*, PWCHAR);
using PF_ldap_value_free_lenW = void (WINAPI*)(struct berval**);
using PF_ldap_memfreeW = void (WINAPI*)(void*);
using PF_ldap_msgfree = void (WINAPI*)(LDAPMessage*);
using PF_ldap_err2stringW = PWCHAR (WINAPI*)(ULONG);
using PF_ldap_set_optionW = ULONG (WINAPI*)(LDAP*, int, const void*);

static PF_ldap_initW p_initW = nullptr;
static PF_ldap_sslinitW p_sslinitW = nullptr;
static PF_ldap_simple_bind_sW p_simple_bind_sW = nullptr;
static PF_ldap_unbind_s p_unbind_s = nullptr;
static PF_ldap_search_ext_sW p_search_ext_sW = nullptr;
static PF_ldap_first_entry p_first_entry = nullptr;
static PF_ldap_next_entry p_next_entry = nullptr;
static PF_ldap_first_attributeW p_first_attributeW = nullptr;
static PF_ldap_next_attributeW p_next_attributeW = nullptr;
static PF_ldap_get_values_lenW p_get_values_lenW = nullptr;
static PF_ldap_value_free_lenW p_value_free_lenW = nullptr;
static PF_ldap_memfreeW p_memfreeW = nullptr;
static PF_ldap_msgfree p_msgfree = nullptr;
static PF_ldap_err2stringW p_err2stringW = nullptr;
static PF_ldap_set_optionW p_set_optionW = nullptr;

// WLDAP_PROC: two-step cast through void* to silence -Wcast-function-type.
// FARPROC is 'long long int (*)()', which is incompatible with every concrete
// function pointer type.  Routing through void* is the standard Windows idiom
// for dynamic loading and is well-defined for data/function pointer round-trips
// on all ABI-stable Windows targets.
#define WLDAP_PROC(T, sym) \
    reinterpret_cast<T>(reinterpret_cast<void*>(GetProcAddress(g_wldap, (sym))))

static bool load_wldap()
{
    if (g_wldap) return true;
    g_wldap = LoadLibraryA("wldap32.dll");
    if (!g_wldap) return false;

    p_initW            = WLDAP_PROC(PF_ldap_initW,            "ldap_initW");
    p_sslinitW         = WLDAP_PROC(PF_ldap_sslinitW,         "ldap_sslinitW");
    p_simple_bind_sW   = WLDAP_PROC(PF_ldap_simple_bind_sW,   "ldap_simple_bind_sW");
    p_unbind_s         = WLDAP_PROC(PF_ldap_unbind_s,         "ldap_unbind_s");
    p_search_ext_sW    = WLDAP_PROC(PF_ldap_search_ext_sW,    "ldap_search_ext_sW");
    p_first_entry      = WLDAP_PROC(PF_ldap_first_entry,      "ldap_first_entry");
    p_next_entry       = WLDAP_PROC(PF_ldap_next_entry,       "ldap_next_entry");
    p_first_attributeW = WLDAP_PROC(PF_ldap_first_attributeW, "ldap_first_attributeW");
    p_next_attributeW  = WLDAP_PROC(PF_ldap_next_attributeW,  "ldap_next_attributeW");
    p_get_values_lenW  = WLDAP_PROC(PF_ldap_get_values_lenW,  "ldap_get_values_lenW");
    p_value_free_lenW  = WLDAP_PROC(PF_ldap_value_free_lenW,  "ldap_value_free_lenW");
    p_memfreeW         = WLDAP_PROC(PF_ldap_memfreeW,         "ldap_memfreeW");
    p_msgfree          = WLDAP_PROC(PF_ldap_msgfree,          "ldap_msgfree");
    p_err2stringW      = WLDAP_PROC(PF_ldap_err2stringW,      "ldap_err2stringW");
    p_set_optionW      = WLDAP_PROC(PF_ldap_set_optionW,      "ldap_set_optionW");

    // Not all symbols are critical. If core ones exist, consider loaded.
    return p_initW && p_simple_bind_sW && p_unbind_s && p_search_ext_sW;
}

#undef WLDAP_PROC

static std::wstring to_wide_local(const char* s) {
    if (!s) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], len);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

static std::string to_utf8_local(const wchar_t* w) {
    if (!w) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], len, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

// ── WinLDAP option codes (not in our portable ldap.h) ────────────────────────
#ifndef LDAP_OPT_VERSION
#define LDAP_OPT_VERSION       0x11
#endif
#ifndef LDAP_OPT_SSL
#define LDAP_OPT_SSL           0x0A
#endif
#ifndef LDAP_OPT_TIMELIMIT
#define LDAP_OPT_TIMELIMIT     0x04
#endif

// ── Portable TLS demand values (from OpenLDAP / ldap_engine.h) ───────────────
#ifndef LDAP_OPT_X_TLS_NEVER
#define LDAP_OPT_X_TLS_NEVER   0
#endif
#ifndef LDAP_OPT_X_TLS_DEMAND
#define LDAP_OPT_X_TLS_DEMAND  2
#endif
#ifndef LDAP_OPT_X_TLS_ALLOW
#define LDAP_OPT_X_TLS_ALLOW   3
#endif

extern "C" int ldap_initialize(LDAP** ldp, const char* uri) {
    if (!load_wldap()) return LDAP_LOCAL_ERROR;
    if (!ldp || !uri) return LDAP_PARAM_ERROR;

    std::string u(uri);
    bool use_ssl = (u.rfind("ldaps://", 0) == 0);

    // Accept both ldap:// and ldaps://; anything else is malformed.
    if (!use_ssl && u.rfind("ldap://", 0) != 0) return LDAP_PARAM_ERROR;

    std::string rest = use_ssl ? u.substr(8) : u.substr(7);
    std::string host;
    ULONG port = use_ssl ? LDAP_SSL_PORT : LDAP_PORT;

    size_t colon = rest.rfind(':');
    if (colon != std::string::npos) {
        host = rest.substr(0, colon);
        try { port = static_cast<ULONG>(std::stoul(rest.substr(colon + 1))); } catch(...){ }
    } else {
        host = rest;
    }

    std::wstring whost = to_wide_local(host.c_str());
    LDAP* ld = nullptr;

    if (use_ssl) {
        // ldap_sslinitW(host, port, secure=1) — opens the SSL connection.
        // The third argument 1 means "use SSL"; 0 would mean plain LDAP.
        if (!p_sslinitW) return LDAP_LOCAL_ERROR;
        ld = p_sslinitW(const_cast<PWCHAR>(whost.c_str()), port, 1);
        if (!ld) return LDAP_SERVER_DOWN;

        // Explicitly enable SSL on the session handle so that subsequent
        // ldap_set_optionW(LDAP_OPT_SSL) calls are consistent.
        ULONG ssl_on = 1;
        if (p_set_optionW) p_set_optionW(ld, LDAP_OPT_SSL, &ssl_on);
    } else {
        if (!p_initW) return LDAP_LOCAL_ERROR;
        ld = p_initW(const_cast<PWCHAR>(whost.c_str()), port);
        if (!ld) return LDAP_SERVER_DOWN;
    }

    *ldp = ld;
    return LDAP_SUCCESS;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ldap_set_option
//
//  Maps the portable OpenLDAP option codes used by ldap_engine.cpp to their
//  WinLDAP equivalents and forwards the call to ldap_set_optionW.
//
//  Option mapping table:
//   LDAP_OPT_PROTOCOL_VERSION  (17 / 0x11)  → LDAP_OPT_VERSION          (0x11)
//   LDAP_OPT_NETWORK_TIMEOUT   (18 / 0x12)  → converted timeval→LDAP_TIMEVAL
//   LDAP_OPT_X_TLS_REQUIRE_CERT(24582/0x6006)→ LDAP_OPT_SSL             (0x0A)
//     value LDAP_OPT_X_TLS_NEVER (0)  → SSL off  (not used in our engine)
//     value LDAP_OPT_X_TLS_ALLOW (3)  → SSL on, certificate not verified
//     value LDAP_OPT_X_TLS_DEMAND(2)  → SSL on, certificate required (our CA case)
//
//  WinLDAP LDAP_OPT_SSL constants: 0 = off, 1 = on (no cert check intent
//  encoded here; cert verification is controlled by the Windows trust store,
//  not by this option).  Domain CA certs must be installed in the Windows
//  "Trusted Root Certification Authorities" or "Intermediate CA" store.
// ─────────────────────────────────────────────────────────────────────────────

extern "C" int ldap_set_option(LDAP* ld, int option, const void* invalue) {
    if (!load_wldap() || !p_set_optionW) return LDAP_SUCCESS; // non-fatal

    switch (option) {

    // ── Protocol version ──────────────────────────────────────────────────
    case LDAP_OPT_PROTOCOL_VERSION: {           // 0x11
        // WinLDAP uses the same option code (LDAP_OPT_VERSION = 0x11)
        ULONG rc = p_set_optionW(ld, LDAP_OPT_VERSION, invalue);
        return static_cast<int>(rc);
    }

    // ── Network / connection timeout ──────────────────────────────────────
    case LDAP_OPT_NETWORK_TIMEOUT: {            // 0x12
        // OpenLDAP passes a struct timeval*; WinLDAP expects LDAP_TIMEVAL*
        // which is layout-compatible (both are {long tv_sec, long tv_usec}).
        // We also set LDAP_OPT_TIMELIMIT (search time limit) to the same value.
        if (!invalue) return LDAP_SUCCESS;
        const struct timeval* tv = static_cast<const struct timeval*>(invalue);
        l_timeval ltv{ static_cast<long>(tv->tv_sec),
                       static_cast<long>(tv->tv_usec) };
        p_set_optionW(ld, LDAP_OPT_TIMELIMIT, &ltv);
        // WinLDAP does not have a direct "network connect timeout" option;
        // LDAP_OPT_TIMELIMIT is the closest approximation.
        return LDAP_SUCCESS;
    }

    // ── TLS / certificate verification ───────────────────────────────────
    case LDAP_OPT_X_TLS_REQUIRE_CERT: {         // 0x6006
        // WinLDAP LDAP_OPT_SSL: 0 = plaintext, 1 = SSL/TLS.
        // Certificate trust is enforced by the Windows certificate store —
        // the Domain CA cert must be in the machine's Trusted Root or
        // Intermediate CA store (certlm.msc → Trusted Root Certification
        // Authorities).  We enable SSL here; Windows handles chain validation.
        if (!invalue) return LDAP_SUCCESS;
        int req = *static_cast<const int*>(invalue);
        ULONG ssl_on  = 1;
        ULONG ssl_off = 0;
        ULONG rc;
        if (req == LDAP_OPT_X_TLS_NEVER) {
            rc = p_set_optionW(ld, LDAP_OPT_SSL, &ssl_off);
        } else {
            // LDAP_OPT_X_TLS_ALLOW (3) or LDAP_OPT_X_TLS_DEMAND (2):
            // both enable SSL; certificate trust comes from Windows store.
            rc = p_set_optionW(ld, LDAP_OPT_SSL, &ssl_on);
        }
        return static_cast<int>(rc);
    }

    default:
        // Unknown / unsupported option — silently succeed so the engine
        // does not abort the connection attempt for optional hints.
        return LDAP_SUCCESS;
    }
}

extern "C" int ldap_sasl_bind_s(LDAP* ld, const char* dn, const char* /*mechanism*/, const struct berval* cred, void* /*sctrls*/, void* /*cctrls*/, void* /*servercredp*/) {
    if (!load_wldap()) return LDAP_LOCAL_ERROR;
    std::wstring wdn = to_wide_local(dn);
    std::wstring wpass;
    if (cred && cred->bv_val && cred->bv_len > 0) wpass = to_wide_local(cred->bv_val);
    ULONG rc = p_simple_bind_sW(ld, wdn.empty() ? nullptr : const_cast<PWCHAR>(wdn.c_str()), wpass.empty() ? nullptr : const_cast<PWCHAR>(wpass.c_str()));
    return static_cast<int>(rc);
}

extern "C" int ldap_unbind_ext_s(LDAP* ld, void* /*sctrls*/, void* /*cctrls*/) {
    if (!load_wldap()) return LDAP_LOCAL_ERROR;
    if (!p_unbind_s) return LDAP_SUCCESS;
    ULONG rc = p_unbind_s(ld);
    return static_cast<int>(rc);
}

// WinLDAP LDAPControlW — mirrors winldap.h layout.
// We declare it locally to avoid pulling in winldap.h (which conflicts with
// our portable ldap.h on some SDK versions).
struct WinLDAPControlW {
    PWCHAR  ldctl_oid;
    berval  ldctl_value;
    BOOLEAN ldctl_iscritical;
};

extern "C" int ldap_search_ext_s(LDAP* ld, const char* base, int scope, const char* filter,
                                  char* const* attrs, int attrsonly,
                                  void* sctrls, void* /*cctrls*/,
                                  const struct timeval* timeout, int sizelimit,
                                  LDAPMessage** res)
{
    if (!load_wldap()) return LDAP_LOCAL_ERROR;

    std::wstring wbase   = to_wide_local(base   ? base   : "");
    std::wstring wfilter = to_wide_local(filter ? filter : "(objectClass=*)");

    // ── Attribute list ────────────────────────────────────────────────────────
    std::vector<std::wstring> wattr_store;
    std::vector<PWCHAR> wattrs;
    if (attrs) {
        for (int i = 0; attrs[i]; ++i) {
            wattr_store.push_back(to_wide_local(attrs[i]));
            wattrs.push_back(const_cast<PWCHAR>(wattr_store.back().c_str()));
        }
    }
    wattrs.push_back(nullptr);

    // ── Convert portable LDAPControl** → WinLDAP LDAPControlW** ─────────────
    // sctrls is passed as void* from ldap_engine.cpp; it actually points to a
    // PortableLDAPControl** (our ldap.h layout).  We rebuild each entry as a
    // WinLDAPControlW with a wide OID and pass the result to WinLDAP.
    PortableLDAPControl** src_ctrls = static_cast<PortableLDAPControl**>(sctrls);

    std::vector<WinLDAPControlW>   win_ctrl_store;
    std::vector<std::wstring>      win_oid_store;
    std::vector<WinLDAPControlW*>  win_ctrl_ptrs;

    if (src_ctrls) {
        for (int i = 0; src_ctrls[i] != nullptr; ++i) {
            WinLDAPControlW wc{};
            win_oid_store.push_back(to_wide_local(src_ctrls[i]->ldctl_oid
                                                   ? src_ctrls[i]->ldctl_oid
                                                   : ""));
            wc.ldctl_oid          = const_cast<PWCHAR>(win_oid_store.back().c_str());
            wc.ldctl_value.bv_len = src_ctrls[i]->ldctl_value.bv_len;
            wc.ldctl_value.bv_val = src_ctrls[i]->ldctl_value.bv_val;
            wc.ldctl_iscritical   = src_ctrls[i]->ldctl_iscritical ? TRUE : FALSE;
            win_ctrl_store.push_back(wc);
        }
        for (auto& wc : win_ctrl_store)
            win_ctrl_ptrs.push_back(&wc);
        win_ctrl_ptrs.push_back(nullptr);
    }

    WinLDAPControlW** psctrls = win_ctrl_ptrs.empty()
                                ? nullptr
                                : win_ctrl_ptrs.data();

    // ── Timeout ───────────────────────────────────────────────────────────────
    void*    plv = nullptr;
    l_timeval ltv{0, 0};
    if (timeout) {
        ltv.tv_sec  = static_cast<long>(timeout->tv_sec);
        ltv.tv_usec = static_cast<long>(timeout->tv_usec);
        plv = &ltv;
    }

    ULONG rc = p_search_ext_sW(
        ld,
        wbase.empty() ? nullptr : const_cast<PWCHAR>(wbase.c_str()),
        static_cast<ULONG>(scope),
        const_cast<PWCHAR>(wfilter.c_str()),
        wattrs.data(),
        static_cast<ULONG>(attrsonly),
        reinterpret_cast<void**>(psctrls),   // server controls
        nullptr,                              // client controls
        plv,
        static_cast<ULONG>(sizelimit),
        res);

    return static_cast<int>(rc);
}

extern "C" LDAPMessage* ldap_first_entry(LDAP* ld, LDAPMessage* res) { if (!load_wldap()) return nullptr; return p_first_entry(ld, res); }
extern "C" LDAPMessage* ldap_next_entry(LDAP* ld, LDAPMessage* entry) { if (!load_wldap()) return nullptr; return p_next_entry(ld, entry); }

// ldap_first_attribute / ldap_next_attribute
// -------------------------------------------------
// WinLDAP returns a PWCHAR that must be freed with ldap_memfreeW.
// Our portable API returns a plain char* that callers free with ldap_memfree.
// We copy the wide string into a malloc-allocated UTF-8 buffer, release the
// original PWCHAR via p_memfreeW immediately, and hand the malloc'd copy to
// the caller.  ldap_memfree() below therefore only needs std::free().
extern "C" char* ldap_first_attribute(LDAP* ld, LDAPMessage* entry, BerElement** berptr) {
    if (!load_wldap() || !p_first_attributeW) return nullptr;
    PWCHAR wattr = p_first_attributeW(ld, entry, berptr);
    if (!wattr) return nullptr;
    std::string s = to_utf8_local(wattr);
    p_memfreeW(wattr);                         // release WinLDAP-owned PWCHAR
    char* ret = static_cast<char*>(std::malloc(s.size() + 1));
    if (!ret) return nullptr;
    std::memcpy(ret, s.c_str(), s.size() + 1);
    return ret;
}

extern "C" char* ldap_next_attribute(LDAP* ld, LDAPMessage* entry, BerElement* ber) {
    if (!load_wldap() || !p_next_attributeW) return nullptr;
    PWCHAR wattr = p_next_attributeW(ld, entry, ber);
    if (!wattr) return nullptr;
    std::string s = to_utf8_local(wattr);
    p_memfreeW(wattr);                         // release WinLDAP-owned PWCHAR
    char* ret = static_cast<char*>(std::malloc(s.size() + 1));
    if (!ret) return nullptr;
    std::memcpy(ret, s.c_str(), s.size() + 1);
    return ret;
}

// ldap_memfree: frees the malloc-allocated UTF-8 char* returned by
// ldap_first_attribute / ldap_next_attribute above.  The WinLDAP PWCHAR
// has already been released inside those wrappers, so std::free is correct.
extern "C" void ldap_memfree(void* p) { std::free(p); }

extern "C" struct berval** ldap_get_values_len(LDAP* ld, LDAPMessage* entry, const char* attr) {
    if (!load_wldap() || !p_get_values_lenW) return nullptr;
    std::wstring wattr = to_wide_local(attr ? attr : "");
    return p_get_values_lenW(ld, entry, const_cast<PWCHAR>(wattr.c_str()));
}

extern "C" void ldap_value_free_len(struct berval** vals) { if (load_wldap() && p_value_free_lenW) p_value_free_lenW(vals); }

extern "C" void ldap_msgfree(LDAPMessage* msg) { if (load_wldap() && p_msgfree) p_msgfree(msg); }

extern "C" const char* ldap_err2string(int err) {
    if (!load_wldap() || !p_err2stringW) return "Unknown LDAP error";
    PWCHAR w = p_err2stringW(static_cast<ULONG>(err));
    if (!w) return "Unknown LDAP error";
    static thread_local std::string buf;
    buf = to_utf8_local(w);
    return buf.c_str();
}