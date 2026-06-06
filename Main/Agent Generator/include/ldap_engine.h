#pragma once

#include "core.h"
#include <vector>
#include <functional>

// ─────────────────────────────────────────────
//  LDAPEngine
//  Thin wrapper around the system libldap.
//  Handles: bind, search, attribute parsing.
// ─────────────────────────────────────────────
class LDAPEngine {
public:
    explicit LDAPEngine(const LDAPConfig& cfg);
    ~LDAPEngine();

    // Connect + bind to the DC
    bool connect();

    // Discover base DN from RootDSE (defaultNamingContext / namingContexts)
    bool discover_base();

    // Run a raw LDAP search and return attribute maps
    // filter   : LDAP filter string  e.g. "(objectClass=user)"
    // attrs    : attributes to fetch, empty = all
    // callback : called once per entry found
    using AttrMap = std::map<std::string, std::vector<std::string>>;
    using EntryCallback = std::function<void(const AttrMap&)>;

    bool search(const std::string& filter,
                const std::vector<std::string>& attrs,
                EntryCallback callback);

    // Base-scope search -- fetches a single object by DN.
    // Required for constructed attributes like tokenGroups that AD only
    // returns for LDAP_SCOPE_BASE (single-object) queries.
    bool search_base(const std::string& dn,
                     const std::vector<std::string>& attrs,
                     EntryCallback callback);

    // Disconnect + free resources
    void disconnect();

    bool is_connected() const { return connected_; }

    // Last error string from the engine (useful for diagnostics)
    const std::string& last_error() const { return last_error_; }

private:
    std::string last_error_;
public:
    LDAPConfig cfg_;
    void*      ld_   = nullptr; // opaque LDAP* handle
    bool       connected_ = false;

    // Convert LDAP error code to readable string
    std::string ldap_err_str(int rc);

    // Parse a raw Windows FILETIME (string of int64) to readable date
public:
    static std::string filetime_to_str(const std::string& ft_raw);

    friend class UserEnumerator; // allow direct handle access if needed
};