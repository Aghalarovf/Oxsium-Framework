#pragma once

#include <cstddef>

// ─────────────────────────────────────────────────────────────────────────────
//  Portable LDAP type declarations.
//
//  On Windows this header is included BEFORE <windows.h> (see ldap_helper.cpp).
//  winldap.h (pulled in by windows.h) redefines LDAP, LDAPMessage, BerElement,
//  and berval.  Every declaration here is guarded with #ifndef so the second
//  definition from winldap.h is silently skipped — no redefinition errors.
//
//  LDAPControl is NOT defined by winldap.h under the same name (WinLDAP uses
//  LDAPControlW / LDAPControlA), so our struct LDAPControl is safe to define
//  unconditionally; it is our own portable type used only by ldap_engine.cpp.
// ─────────────────────────────────────────────────────────────────────────────

#ifndef LDAP_TYPEDEF_LDAP
#define LDAP_TYPEDEF_LDAP
typedef struct ldap LDAP;
#endif

#ifndef LDAP_TYPEDEF_LDAPMESSAGE
#define LDAP_TYPEDEF_LDAPMESSAGE
typedef struct ldap_msg LDAPMessage;
#endif

#ifndef LDAP_TYPEDEF_BERELEMENT
#define LDAP_TYPEDEF_BERELEMENT
typedef struct berelement BerElement;
#endif

#ifndef LDAP_STRUCT_BERVAL
#define LDAP_STRUCT_BERVAL
struct berval {
    std::size_t bv_len;
    char*       bv_val;
};
#endif

#define LDAP_SUCCESS 0
#define LDAP_VERSION3 3
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_SCOPE_BASE 0

#define LDAP_OPT_PROTOCOL_VERSION 17
#define LDAP_OPT_NETWORK_TIMEOUT 18
#define LDAP_OPT_X_TLS_REQUIRE_CERT 24582
#define LDAP_OPT_X_TLS_ALLOW 3

// ── Server control (passed to ldap_search_ext_s sctrls) ──────────────────────
// WinLDAP defines LDAPControlW/LDAPControlA but not plain LDAPControl, so
// this struct is safe to define without a guard.
struct LDAPControl {
    char*         ldctl_oid;        // OID string (not freed by the engine)
    struct berval ldctl_value;      // BER-encoded value (bv_val may be nullptr)
    char          ldctl_iscritical; // non-zero → server must honor or return error
};

// SD_FLAGS_OID — request only DACL when fetching nTSecurityDescriptor.
// Without this control AD returns only owner/group and omits the DACL.
// Value 0x04 = DACL_SECURITY_INFORMATION.
#define LDAP_SERVER_SD_FLAGS_OID  "1.2.840.113556.1.4.801"

#define LDAP_SASL_SIMPLE "SIMPLE"

extern "C" {
int ldap_initialize(LDAP** ldp, const char* uri);
int ldap_set_option(LDAP* ld, int option, const void* invalue);
int ldap_sasl_bind_s(LDAP* ld,
                     const char* dn,
                     const char* mechanism,
                     const struct berval* cred,
                     void* sctrls,
                     void* cctrls,
                     void* servercredp);
int ldap_unbind_ext_s(LDAP* ld, void* sctrls, void* cctrls);
int ldap_search_ext_s(LDAP* ld,
                      const char* base,
                      int scope,
                      const char* filter,
                      char* const* attrs,
                      int attrsonly,
                      void* sctrls,
                      void* cctrls,
                      const struct timeval* timeout,
                      int sizelimit,
                      LDAPMessage** res);
LDAPMessage* ldap_first_entry(LDAP* ld, LDAPMessage* res);
LDAPMessage* ldap_next_entry(LDAP* ld, LDAPMessage* entry);
char* ldap_first_attribute(LDAP* ld, LDAPMessage* entry, BerElement** berptr);
char* ldap_next_attribute(LDAP* ld, LDAPMessage* entry, BerElement* ber);
struct berval** ldap_get_values_len(LDAP* ld, LDAPMessage* entry, const char* attr);
void ldap_value_free_len(struct berval** vals);
void ldap_memfree(void* p);
int ber_free(BerElement* ber, int freebuf);
const char* ldap_err2string(int err);
void ldap_msgfree(LDAPMessage* msg);
}