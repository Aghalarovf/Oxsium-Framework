#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/* ══════════════════════════════════════════════════════════════════════
 * Minimal SQLite3 C API declarations.
 * libsqlite3-dev headers are not available in this build environment,
 * but the runtime library (libsqlite3.so.0) is present, so we declare
 * just the subset of the stable C ABI we need and link against it
 * directly (see build command in the usage banner / README).
 * ══════════════════════════════════════════════════════════════════════ */
extern "C" {
    typedef struct sqlite3 sqlite3;
    typedef struct sqlite3_stmt sqlite3_stmt;

    int sqlite3_open(const char* filename, sqlite3** ppDb);
    int sqlite3_close(sqlite3*);
    int sqlite3_prepare_v2(sqlite3*, const char* zSql, int nByte,
                            sqlite3_stmt** ppStmt, const char** pzTail);
    int sqlite3_step(sqlite3_stmt*);
    int sqlite3_finalize(sqlite3_stmt*);
    int sqlite3_column_count(sqlite3_stmt*);
    const char* sqlite3_column_name(sqlite3_stmt*, int N);
    int sqlite3_column_type(sqlite3_stmt*, int iCol);
    const unsigned char* sqlite3_column_text(sqlite3_stmt*, int iCol);
    long long sqlite3_column_int64(sqlite3_stmt*, int iCol);
    double sqlite3_column_double(sqlite3_stmt*, int iCol);
    int sqlite3_column_bytes(sqlite3_stmt*, int iCol);
    const char* sqlite3_errmsg(sqlite3*);
}

#define SQLITE_OK      0
#define SQLITE_ROW   100
#define SQLITE_DONE  101
#define SQLITE_INTEGER 1
#define SQLITE_FLOAT   2
#define SQLITE_TEXT    3
#define SQLITE_BLOB    4
#define SQLITE_NULL    5

struct JsonVal;
using JsonArr = std::vector<JsonVal>;
using JsonObj = std::vector<std::pair<std::string, JsonVal>>;

struct JsonVal {
    enum class T { Null, Bool, Number, String, Array, Object } type = T::Null;
    bool        b   = false;
    double      n   = 0;
    std::string s;
    JsonArr     arr;
    JsonObj     obj;

    bool        isNull()   const { return type == T::Null;   }
    bool        isBool()   const { return type == T::Bool;   }
    bool        isNum()    const { return type == T::Number; }
    bool        isStr()    const { return type == T::String; }
    bool        isArr()    const { return type == T::Array;  }
    bool        isObj()    const { return type == T::Object; }

    const std::string& str() const { return s; }

    const JsonVal* find(const std::string& key) const {
        if (!isObj()) return nullptr;
        for (auto& p : obj)
            if (p.first == key) return &p.second;
        return nullptr;
    }
    const JsonVal& operator[](const std::string& key) const {
        auto* v = find(key);
        if (!v) throw std::runtime_error("JSON key not found: " + key);
        return *v;
    }
};

static void skipWs(const char*& p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
}

static std::string parseString(const char*& p) {
    ++p;
    std::string res;
    while (*p && *p != '"') {
        if (*p == '\\') {
            ++p;
            switch (*p) {
                case '"':  res += '"';  break;
                case '\\': res += '\\'; break;
                case '/':  res += '/';  break;
                case 'n':  res += '\n'; break;
                case 'r':  res += '\r'; break;
                case 't':  res += '\t'; break;
                default:   res += *p;  break;
            }
        } else {
            res += *p;
        }
        ++p;
    }
    if (*p == '"') ++p;
    return res;
}

static JsonVal parseValue(const char*& p);

static JsonArr parseArray(const char*& p) {
    ++p;
    JsonArr arr;
    skipWs(p);
    if (*p == ']') { ++p; return arr; }
    while (true) {
        skipWs(p);
        arr.push_back(parseValue(p));
        skipWs(p);
        if (*p == ']') { ++p; break; }
        if (*p == ',') ++p;
    }
    return arr;
}

static JsonObj parseObject(const char*& p) {
    ++p;
    JsonObj obj;
    skipWs(p);
    if (*p == '}') { ++p; return obj; }
    while (true) {
        skipWs(p);
        if (*p != '"') throw std::runtime_error("Expected quote in object key");
        std::string key = parseString(p);
        skipWs(p);
        if (*p != ':') throw std::runtime_error("Expected colon after key");
        ++p;
        skipWs(p);
        JsonVal val = parseValue(p);
        obj.push_back({key, std::move(val)});
        skipWs(p);
        if (*p == '}') { ++p; break; }
        if (*p == ',') ++p;
    }
    return obj;
}

static JsonVal parseValue(const char*& p) {
    skipWs(p);
    JsonVal v;
    if (*p == '"') {
        v.type = JsonVal::T::String;
        v.s    = parseString(p);
    } else if (*p == '[') {
        v.type = JsonVal::T::Array;
        v.arr  = parseArray(p);
    } else if (*p == '{') {
        v.type = JsonVal::T::Object;
        v.obj  = parseObject(p);
    } else if (std::strncmp(p, "true", 4) == 0) {
        v.type = JsonVal::T::Bool; v.b = true;  p += 4;
    } else if (std::strncmp(p, "false", 5) == 0) {
        v.type = JsonVal::T::Bool; v.b = false; p += 5;
    } else if (std::strncmp(p, "null", 4) == 0) {
        v.type = JsonVal::T::Null; p += 4;
    } else {
        char* end;
        v.n    = std::strtod(p, &end);
        v.type = JsonVal::T::Number;
        p      = end;
    }
    return v;
}

static JsonVal parseJson(const std::string& src) {
    const char* p = src.c_str();
    skipWs(p);
    return parseValue(p);
}

static std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string jsonEsc(const std::string& s) {
    std::string r;
    r.reserve(s.size() + 4);
    for (char c : s) {
        if      (c == '"')  r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else if (c == '\n') r += "\\n";
        else if (c == '\r') r += "\\r";
        else if (c == '\t') r += "\\t";
        else                r += c;
    }
    return r;
}

static std::string strArrToJson(const std::vector<std::string>& v) {
    std::string r = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) r += ", ";
        r += "\"" + jsonEsc(v[i]) + "\"";
    }
    r += "]";
    return r;
}

struct AceStep {
    std::string              target_name;
    std::string              target_sid;
    std::string              target_dn;
    std::string              target_type;
    std::string              principal_sid;
    std::string              principal_name;
    std::string              principal_type;
    std::string              object_acetype;
    std::string              ace_qualifier;
    std::vector<std::string> rights;
    std::string              rights_display;
    std::vector<std::string> edge_rights;
    std::string              source_file;
    std::vector<AceStep>     next_step;   /* Recursive chain — populated until empty */
    std::vector<std::pair<std::string, JsonVal>> target_attributes; /* enriched from domain JSON */
};

struct AceRecord {
    std::string              target_name;
    std::string              target_sid;
    std::string              target_dn;
    std::string              target_type;
    std::string              principal_sid;
    std::string              principal_name;
    std::string              object_acetype;
    std::string              ace_qualifier;
    std::vector<std::string> rights;
    std::string              rights_display;
    std::vector<std::string> edge_rights;
    std::vector<AceStep>     next_step;    /* Level-2 chain */
    std::string              source_file;
    std::vector<std::pair<std::string, JsonVal>> target_attributes;    /* enriched from domain JSON — target node */
    std::vector<std::pair<std::string, JsonVal>> principal_attributes; /* enriched from domain JSON — principal node (attack vectors) */
    /* special_edge: populated only for attack-vector entry points (e.g. kerberoasting) */
    std::string              special_edge;
};

static JsonVal loadAcls(const std::string& path) {
    std::string raw;
    try {
        raw = readFile(path);
    } catch (const std::exception& e) {
        std::cerr << "[WARN] " << e.what() << " — skipping.\n";
        return JsonVal{};
    }
    try {
        return parseJson(raw);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Parse error in " << path << ": " << e.what() << "\n";
        return JsonVal{};
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * SQLite → JsonVal loading layer.
 *
 * This replaces the old "read domain_*.json from disk" mechanism with
 * "run a SQL query against domain_data.db and build the identical
 * JsonVal tree". Every function below feeds into exactly the same
 * downstream machinery (extractMatching, extractAttrs, lookupAttrs,
 * buildSidLookup, ...) that used to consume parsed JSON files, so
 * nothing past this loading layer needs to change.
 * ══════════════════════════════════════════════════════════════════════ */

static sqlite3* openDomainDb(const std::string& path) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        std::string msg = db ? sqlite3_errmsg(db) : "unknown error";
        if (db) sqlite3_close(db);
        throw std::runtime_error("Cannot open database: " + path + " (" + msg + ")");
    }
    return db;
}

/* Columns whose SQL value should be interpreted as a JSON-array-of-strings
 * (or JSON-array-of-objects) that was stored as serialized TEXT. */
static bool isJsonArrayColumn(const std::string& table, const std::string& col) {
    static const std::map<std::string, std::set<std::string>> map = {
        {"dangerous_ace",   {"rights", "edge_rights"}},
        {"extended_rights", {"rights", "edge_rights"}},
        {"aces",            {"rights", "edge_rights"}},
        {"users", {
            "spn", "msds_supportedencryptiontypesname",
            "msds_supportedencryptiontypes_name", "key_credential_link",
            "msds_allowedtodelegateto_structurized"
        }},
        {"computers", {
            "rbcd_principals", "rbcd_principal_names", "ipv4_addresses",
            "ipv6_addresses", "sid_history", "token_group_sids",
            "risk_factors", "risk_controls",
            "allowed_to_delegate_to_structured", "laps_attributes"
        }},
        {"groups", {}},
    };
    auto it = map.find(table);
    if (it == map.end()) return false;
    return it->second.count(col) != 0;
}

/* Columns whose 0/1 (or "0"/"1"/NULL) SQL value should become a real
 * JSON boolean, matching how the original domain_*.json files encoded
 * these flags (the rest of the code checks isBool() on them). */
static bool isBooleanColumn(const std::string& table, const std::string& col) {
    static const std::map<std::string, std::set<std::string>> map = {
        {"users", {
            "disabled", "normal_account", "pwd_not_required", "is_admin",
            "is_direct_admin", "is_nested_admin", "dcsync", "asrep",
            "kerberoastable", "unconstrained_delegation",
            "has_key_credential_link", "locked_out", "must_change_pwd",
            "smartcard_required", "pwd_never_expires", "pwd_cant_change",
            "preauth_required", "trusted_for_delegation",
            "constrained_delegation", "trusted_to_auth_for_delegation",
            "protocol_transition_delegation", "not_delegated",
            "account_never_expires", "deleted", "enc_implicit_rc4"
        }},
        {"computers", {
            "disabled", "is_workstation", "is_server",
            "is_domain_controller", "potential_privileged", "is_stale",
            "stale_by_pwd", "stale_by_logon", "has_spn",
            "trusted_for_delegation", "trusted_to_auth_for_delegation",
            "unconstrained_delegation", "constrained_delegation",
            "rbcd_enabled", "has_laps", "haslaps", "isaclprotected",
            "kerberoastable", "asrep", "has_shadow_credential"
        }},
        {"groups", {
            "is_empty", "is_privileged", "is_protected", "is_nested",
            "isaclprotected"
        }},
    };
    auto it = map.find(table);
    if (it == map.end()) return false;
    return it->second.count(col) != 0;
}

static JsonVal boolJson(bool b) {
    JsonVal v; v.type = JsonVal::T::Bool; v.b = b; return v;
}

/* Converts one SQLite column value (for row `stmt`, column `i`) into a
 * JsonVal, honoring the boolean / json-array column overrides above. */
static JsonVal sqliteColumnToJson(sqlite3_stmt* stmt, int i,
                                   const std::string& table,
                                   const std::string& colName)
{
    int type = sqlite3_column_type(stmt, i);

    if (isBooleanColumn(table, colName)) {
        if (type == SQLITE_NULL) return boolJson(false);
        if (type == SQLITE_INTEGER) return boolJson(sqlite3_column_int64(stmt, i) != 0);
        if (type == SQLITE_TEXT) {
            std::string s = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
            return boolJson(s == "1" || s == "true" || s == "True" || s == "TRUE");
        }
        return boolJson(false);
    }

    if (isJsonArrayColumn(table, colName)) {
        if (type == SQLITE_NULL) { JsonVal v; v.type = JsonVal::T::Array; return v; }
        std::string s = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
        if (s.empty()) { JsonVal v; v.type = JsonVal::T::Array; return v; }
        try {
            JsonVal parsed = parseJson(s);
            if (parsed.isArr()) return parsed;
        } catch (...) { /* fall through — not valid JSON, treat as plain string below */ }
        JsonVal v; v.type = JsonVal::T::String; v.s = s; return v;
    }

    switch (type) {
        case SQLITE_NULL: return JsonVal{};
        case SQLITE_INTEGER: {
            JsonVal v; v.type = JsonVal::T::Number;
            v.n = static_cast<double>(sqlite3_column_int64(stmt, i));
            return v;
        }
        case SQLITE_FLOAT: {
            JsonVal v; v.type = JsonVal::T::Number;
            v.n = sqlite3_column_double(stmt, i);
            return v;
        }
        default: {
            const unsigned char* txt = sqlite3_column_text(stmt, i);
            JsonVal v; v.type = JsonVal::T::String;
            v.s = txt ? reinterpret_cast<const char*>(txt) : "";
            return v;
        }
    }
}

/* Runs `sql` and returns each result row as a JsonObj (column name -> value).
 * `aliases` lets a query add extra key names pointing at an existing
 * column's value (e.g. groups."group_sid" also exposed as "sid"), so the
 * generic downstream code — written against the old JSON field names —
 * keeps working unmodified. */
static JsonArr runQueryAsJsonArr(sqlite3* db, const std::string& table,
                                  const std::string& sql,
                                  const std::vector<std::pair<std::string, std::string>>& aliases = {})
{
    JsonArr out;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[ERROR] SQL prepare failed for " << table << ": " << sqlite3_errmsg(db) << "\n";
        return out;
    }

    int nCols = sqlite3_column_count(stmt);
    std::vector<std::string> colNames(nCols);
    for (int i = 0; i < nCols; ++i)
        colNames[i] = sqlite3_column_name(stmt, i);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        JsonVal row; row.type = JsonVal::T::Object;
        for (int i = 0; i < nCols; ++i)
            row.obj.push_back({colNames[i], sqliteColumnToJson(stmt, i, table, colNames[i])});
        for (const auto& alias : aliases) {
            const JsonVal* src = row.find(alias.second);
            if (src) row.obj.push_back({alias.first, *src});
        }
        out.push_back(std::move(row));
    }

    sqlite3_finalize(stmt);
    return out;
}

/* member_of: aggregate user_member_of rows into a JSON array of group
 * names, keyed by the owning user's rowid. */
static std::map<long long, JsonVal> loadUserMemberOf(sqlite3* db) {
    std::map<long long, JsonVal> out;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT user_rowid, value FROM user_member_of ORDER BY user_rowid";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        long long uid = sqlite3_column_int64(stmt, 0);
        const unsigned char* val = sqlite3_column_text(stmt, 1);
        JsonVal item; item.type = JsonVal::T::String;
        item.s = val ? reinterpret_cast<const char*>(val) : "";
        auto& arr = out[uid];
        arr.type = JsonVal::T::Array;
        arr.arr.push_back(std::move(item));
    }
    sqlite3_finalize(stmt);
    return out;
}

/* admin_rules: aggregate user_admin_rules rows into a JSON array of
 * {level, severity, label, detail} objects, keyed by user rowid. */
static std::map<long long, JsonVal> loadUserAdminRules(sqlite3* db) {
    std::map<long long, JsonVal> out;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT user_rowid, level, severity, label, detail_json "
                       "FROM user_admin_rules ORDER BY user_rowid";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        long long uid = sqlite3_column_int64(stmt, 0);

        JsonVal obj; obj.type = JsonVal::T::Object;
        JsonVal level; level.type = JsonVal::T::Number;
        level.n = static_cast<double>(sqlite3_column_int64(stmt, 1));
        obj.obj.push_back({"level", level});

        auto textOf = [&](int i) {
            const unsigned char* t = sqlite3_column_text(stmt, i);
            JsonVal v; v.type = JsonVal::T::String;
            v.s = t ? reinterpret_cast<const char*>(t) : "";
            return v;
        };
        obj.obj.push_back({"severity", textOf(2)});
        obj.obj.push_back({"label", textOf(3)});

        if (sqlite3_column_type(stmt, 4) == SQLITE_NULL) {
            obj.obj.push_back({"detail", JsonVal{}});
        } else {
            std::string detailRaw = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            try {
                obj.obj.push_back({"detail", parseJson(detailRaw)});
            } catch (...) {
                JsonVal v; v.type = JsonVal::T::String; v.s = detailRaw;
                obj.obj.push_back({"detail", v});
            }
        }

        auto& arr = out[uid];
        arr.type = JsonVal::T::Array;
        arr.arr.push_back(std::move(obj));
    }
    sqlite3_finalize(stmt);
    return out;
}

/* Wraps a JsonArr as {"<key>": [...]}, mirroring the shape the rest of
 * the code expects from the old domain_*.json files. */
static JsonVal wrapAsRoot(const std::string& key, JsonArr arr) {
    JsonVal root; root.type = JsonVal::T::Object;
    JsonVal list; list.type = JsonVal::T::Array; list.arr = std::move(arr);
    root.obj.push_back({key, std::move(list)});
    return root;
}

/* dangerous_ace / extended_rights → {"acls": [...]} */
static JsonVal loadAclsFromDb(sqlite3* db, const std::string& table) {
    std::string sql = "SELECT * FROM \"" + table + "\"";
    JsonArr rows = runQueryAsJsonArr(db, table, sql);
    return wrapAsRoot("acls", std::move(rows));
}

/* users → {"users": [...]}, enriched with member_of / admin_rules
 * aggregated from their join tables (id -> user_rowid). */
static JsonVal loadUsersFromDb(sqlite3* db) {
    JsonArr rows = runQueryAsJsonArr(db, "users", "SELECT * FROM \"users\"");

    auto memberOf   = loadUserMemberOf(db);
    auto adminRules = loadUserAdminRules(db);

    /* id was selected via SELECT * so it's present as "id" on each row */
    for (JsonVal& row : rows) {
        const JsonVal* idVal = row.find("id");
        long long uid = (idVal && idVal->isNum()) ? static_cast<long long>(idVal->n) : -1;

        auto mIt = memberOf.find(uid);
        row.obj.push_back({"member_of", mIt != memberOf.end() ? mIt->second : JsonVal{JsonVal::T::Array}});

        auto aIt = adminRules.find(uid);
        row.obj.push_back({"admin_rules", aIt != adminRules.end() ? aIt->second : JsonVal{JsonVal::T::Array}});
    }

    return wrapAsRoot("users", std::move(rows));
}

/* computers → {"computers": [...]} */
static JsonVal loadComputersFromDb(sqlite3* db) {
    JsonArr rows = runQueryAsJsonArr(db, "computers", "SELECT * FROM \"computers\"");
    return wrapAsRoot("computers", std::move(rows));
}

/* groups → {"groups": [...]}. The groups table uses "group_sid" /
 * "group_dn" while the rest of the engine (buildSidLookup, RBCD/MemberOf
 * enrichment, GROUP_ATTRS) expects "sid" / "dn" — expose both via
 * aliases instead of touching downstream code. */
static JsonVal loadGroupsFromDb(sqlite3* db) {
    JsonArr rows = runQueryAsJsonArr(
        db, "groups", "SELECT * FROM \"groups\"",
        { {"sid", "group_sid"}, {"dn", "group_dn"}, {"name", "group_name"} });
    return wrapAsRoot("groups", std::move(rows));
}

static bool isNonEmpty(const JsonVal& v) {
    switch (v.type) {
        case JsonVal::T::Bool:   return v.b;
        case JsonVal::T::Number: return v.n != 0.0;
        case JsonVal::T::String: return !v.s.empty();
        case JsonVal::T::Array:  return !v.arr.empty();
        case JsonVal::T::Object: return !v.obj.empty();
        case JsonVal::T::Null:   return false;
    }
    return false;
}

static std::vector<std::pair<std::string, JsonVal>>
extractAttrs(const JsonVal& entry, const std::vector<std::string>& keys) {
    std::vector<std::pair<std::string, JsonVal>> out;
    for (const std::string& k : keys) {
        const JsonVal* v = entry.find(k);
        if (v && isNonEmpty(*v))
            out.push_back({k, *v});
    }
    return out;
}

using SidLookup = std::map<std::string, size_t>;

static SidLookup buildSidLookup(const JsonArr& items) {
    SidLookup lut;
    for (size_t i = 0; i < items.size(); ++i) {
        const JsonVal* sid = items[i].find("sid");
        if (sid && sid->isStr() && !sid->str().empty())
            lut[sid->str()] = i;
    }
    return lut;
}

static const std::vector<std::string> USER_ATTRS = {
    "disabled", "normal_account", "pwd_not_required",
    "is_admin", "potential_admin", "is_direct_admin", "is_nested_admin",
    "admin_rules", "dcsync", "asrep", "kerberoastable", "spn",
    "msds_supportedencryptiontypesname", "msds_supportedencryptiontypes",
    "primary_group_sid", "unconstrained_delegation",
    "member_of", "domain_sid", "primary_group_id",
    "key_credential_link", "has_key_credential_link"
};

static const std::vector<std::string> COMPUTER_ATTRS = {
    "disabled", "unconstrained_delegation", "rbcd_enabled", "rbcd_principals",
    "has_laps", "haslaps", "laps_attributes", "is_domain_controller", "domainsid"
};

static const std::vector<std::string> GROUP_ATTRS = {
    "group_sid", "group_type", "is_privileged", "is_nested",
    "is_protected", "isaclprotected", "primary_group_token", "domainsid"
};

/* Lookup and extract attributes for a given SID + target_type */
static std::vector<std::pair<std::string, JsonVal>>
lookupAttrs(const std::string&      targetSid,
            const std::string&      targetType,
            const JsonArr&          users,
            const SidLookup&        userLut,
            const JsonArr&          computers,
            const SidLookup&        computerLut,
            const JsonArr&          groups,
            const SidLookup&        groupLut)
{
    if (targetType == "User") {
        auto it = userLut.find(targetSid);
        if (it != userLut.end())
            return extractAttrs(users[it->second], USER_ATTRS);
    } else if (targetType == "Computer") {
        auto it = computerLut.find(targetSid);
        if (it != computerLut.end())
            return extractAttrs(computers[it->second], COMPUTER_ATTRS);
    } else if (targetType == "Group") {
        auto it = groupLut.find(targetSid);
        if (it != groupLut.end())
            return extractAttrs(groups[it->second], GROUP_ATTRS);
    }
    return {};
}

static void enrichStepAttributes(
        AceStep& s,
        const JsonArr& users,
        const SidLookup& userLut,
        const JsonArr& computers,
        const SidLookup& computerLut,
        const JsonArr& groups,
        const SidLookup& groupLut)
{
    s.target_attributes = lookupAttrs(s.target_sid, s.target_type,
                                      users, userLut,
                                      computers, computerLut,
                                      groups, groupLut);
    for (AceStep& child : s.next_step)
        enrichStepAttributes(child, users, userLut, computers, computerLut, groups, groupLut);
}

static std::string getStr(const JsonVal& entry, const std::string& key) {
    const JsonVal* v = entry.find(key);
    return (v && v->isStr()) ? v->str() : "";
}

static std::vector<std::string> getStrArr(const JsonVal& entry, const std::string& key) {
    std::vector<std::string> out;
    const JsonVal* v = entry.find(key);
    if (v && v->isArr())
        for (const JsonVal& el : v->arr)
            if (el.isStr()) out.push_back(el.str());
    return out;
}

static void mergeUnique(std::vector<std::string>&       dst,
                        const std::vector<std::string>& src)
{
    for (const std::string& s : src)
        if (std::find(dst.begin(), dst.end(), s) == dst.end())
            dst.push_back(s);
}

static std::string rightsDisplay(const std::vector<std::string>& edge_rights) {
    std::string r;
    for (size_t i = 0; i < edge_rights.size(); ++i) {
        if (i) r += ", ";
        r += edge_rights[i];
    }
    return r;
}

static void mergeSource(std::string& dst, const std::string& src) {
    if (dst.find(src) == std::string::npos) {
        if (!dst.empty()) dst += ", ";
        dst += src;
    }
}

static std::vector<AceRecord> extractMatching(
        const JsonVal&     root,
        const std::string& targetSid,
        const std::string& principalName,
        const std::string& label)
{
    std::vector<AceRecord>        results;
    std::map<std::string, size_t> sidIdx;   

    const JsonVal* aclsPtr = root.find("acls");
    if (!aclsPtr || !aclsPtr->isArr()) return results;

    for (const JsonVal& entry : aclsPtr->arr) {
        if (!entry.isObj()) continue;

        const JsonVal* sidPtr = entry.find("principal_sid");
        if (!sidPtr || !sidPtr->isStr()) sidPtr = entry.find("principalSid");
        if (!sidPtr || !sidPtr->isStr()) continue;
        if (sidPtr->str() != targetSid)  continue;

        std::string tSid = getStr(entry, "target_sid");

        auto it = sidIdx.find(tSid);
        if (it != sidIdx.end()) {
            AceRecord& existing = results[it->second];
            mergeUnique(existing.rights,      getStrArr(entry, "rights"));
            mergeUnique(existing.edge_rights, getStrArr(entry, "edge_rights"));
            existing.rights_display = rightsDisplay(existing.edge_rights);
            mergeSource(existing.source_file, label);
            continue;
        }

        AceRecord r;
        r.source_file    = label;
        r.target_name    = getStr(entry, "target_name");
        r.target_sid     = tSid;
        r.target_dn      = getStr(entry, "target_dn");
        r.target_type    = getStr(entry, "target_type");
        r.principal_sid  = sidPtr->str();
        r.principal_name = principalName;
        r.object_acetype = getStr(entry, "object_acetype");
        if (r.object_acetype.empty())
            r.object_acetype = getStr(entry, "object_ace_type");
        r.ace_qualifier  = getStr(entry, "ace_qualifier");
        r.rights         = getStrArr(entry, "rights");
        r.edge_rights    = getStrArr(entry, "edge_rights");
        r.rights_display = rightsDisplay(r.edge_rights);

        sidIdx[tSid] = results.size();
        results.push_back(std::move(r));
    }

    return results;
}

static std::vector<AceRecord> mergeAceRecords(std::vector<AceRecord> in) {
    std::vector<AceRecord>        out;
    std::map<std::string, size_t> sidIdx;

    for (AceRecord& r : in) {
        auto it = sidIdx.find(r.target_sid);
        if (it != sidIdx.end()) {
            AceRecord& existing = out[it->second];
            mergeUnique(existing.rights,      r.rights);
            mergeUnique(existing.edge_rights, r.edge_rights);
            existing.rights_display = rightsDisplay(existing.edge_rights);
            mergeSource(existing.source_file, r.source_file);
        } else {
            sidIdx[r.target_sid] = out.size();
            out.push_back(std::move(r));
        }
    }
    return out;
}

static std::string trimTrailingDollar(std::string value) {
    while (!value.empty() && value.back() == '$')
        value.pop_back();
    return value;
}

struct RbcdComputer {
    std::string              sid;
    std::string              name;
    std::string              dn;
    std::vector<std::string> principals;
};

struct PrivGroup {
    std::string sid;
    std::string name;
    std::string dn;
    long        primaryToken = -1;
};

static std::vector<PrivGroup> extractPrivilegedGroups(const JsonArr& groupsArr) {
    std::vector<PrivGroup> out;
    for (const JsonVal& entry : groupsArr) {
        if (!entry.isObj()) continue;
        const JsonVal* isPriv = entry.find("is_privileged");
        if (!isPriv || !isPriv->isBool() || !isPriv->b) continue;

        PrivGroup g;
        g.sid = getStr(entry, "sid");
        g.name = getStr(entry, "group_name");
        if (g.name.empty()) g.name = getStr(entry, "name");
        g.dn  = getStr(entry, "dn");

        const JsonVal* token = entry.find("primary_group_token");
        if (token && token->isNum()) g.primaryToken = static_cast<long>(token->n);

        if (g.sid.empty() || g.primaryToken < 0) continue;
        out.push_back(std::move(g));
    }
    return out;
}

static std::vector<RbcdComputer> extractRbcdComputers(const JsonArr& computersArr) {
    std::vector<RbcdComputer> out;

    for (const JsonVal& entry : computersArr) {
        if (!entry.isObj()) continue;

        const JsonVal* rbcdEnabled = entry.find("rbcd_enabled");
        if (!rbcdEnabled || !rbcdEnabled->isBool() || !rbcdEnabled->b)
            continue;

        RbcdComputer computer;
        computer.sid = getStr(entry, "sid");
        computer.name = trimTrailingDollar(getStr(entry, "computer_name"));
        if (computer.name.empty())
            computer.name = trimTrailingDollar(getStr(entry, "name"));
        if (computer.name.empty())
            computer.name = trimTrailingDollar(getStr(entry, "dns_name"));
        computer.dn  = getStr(entry, "dn");

        const JsonVal* principals = entry.find("rbcd_principals");
        if (principals && principals->isArr()) {
            for (const JsonVal& p : principals->arr) {
                if (p.isStr() && !p.str().empty())
                    computer.principals.push_back(p.str());
            }
        }

        if (computer.sid.empty() || computer.principals.empty())
            continue;

        out.push_back(std::move(computer));
    }

    return out;
}

static void collectNodeIndexFromStep(
        const AceStep& step,
        std::map<std::string, std::pair<std::string, std::string>>& index)
{
    if (!step.target_sid.empty() && !index.count(step.target_sid))
        index[step.target_sid] = {step.target_name, step.target_type};
    for (const AceStep& child : step.next_step)
        collectNodeIndexFromStep(child, index);
}

static void collectNodeIndexFromRecord(
        const AceRecord& record,
        std::map<std::string, std::pair<std::string, std::string>>& index)
{
    if (!record.target_sid.empty() && !index.count(record.target_sid))
        index[record.target_sid] = {record.target_name, record.target_type};
    for (const AceStep& step : record.next_step)
        collectNodeIndexFromStep(step, index);
}

static size_t attachRbcdEdgesToSteps(
        std::vector<AceStep>& stepList,
        const std::map<std::string, std::vector<RbcdComputer>>& rbcdByPrincipal,
        const std::map<std::string, std::pair<std::string, std::string>>& nodeIndex,
        const JsonArr& usersArr,
        const SidLookup& userLut,
        const JsonArr& computersArr,
        const SidLookup& computerLut,
        const JsonArr& groupsArr,
        const SidLookup& groupLut,
        size_t& attachedCount)
{
    size_t localCount = 0;

    for (AceStep& step : stepList) {
        auto principalIt = rbcdByPrincipal.find(step.target_sid);
        if (principalIt != rbcdByPrincipal.end()) {
            for (const RbcdComputer& computer : principalIt->second) {
                AceStep rbcdStep;
                rbcdStep.target_name    = computer.name.empty() ? computer.sid : computer.name;
                rbcdStep.target_sid     = computer.sid;
                rbcdStep.target_dn      = computer.dn;
                rbcdStep.target_type    = "Computer";
                rbcdStep.principal_sid  = step.target_sid;
                rbcdStep.principal_type = step.target_type.empty() ? "User" : step.target_type;
                if (auto infoIt = nodeIndex.find(step.target_sid); infoIt != nodeIndex.end() && !infoIt->second.first.empty())
                    rbcdStep.principal_name = infoIt->second.first;
                else
                    rbcdStep.principal_name = step.target_name.empty() ? step.target_sid : step.target_name;
                rbcdStep.object_acetype = "rbcd";
                rbcdStep.ace_qualifier  = "Allow";
                rbcdStep.rights         = {"RBCD"};
                rbcdStep.rights_display = "RBCD";
                rbcdStep.edge_rights    = {"RBCD"};
                rbcdStep.source_file    = "rbcd";
                rbcdStep.target_attributes = lookupAttrs(computer.sid, "Computer",
                                                         usersArr, userLut,
                                                         computersArr, computerLut,
                                                         groupsArr, groupLut);

                step.next_step.push_back(std::move(rbcdStep));
                ++localCount;
                ++attachedCount;
            }
        }

        localCount += attachRbcdEdgesToSteps(step.next_step, rbcdByPrincipal, nodeIndex,
                                             usersArr, userLut,
                                             computersArr, computerLut,
                                             groupsArr, groupLut,
                                             attachedCount);
    }

    return localCount;
}

static size_t attachRbcdEdgesToRecords(
        std::vector<AceRecord>& records,
        const std::map<std::string, std::vector<RbcdComputer>>& rbcdByPrincipal,
        const std::map<std::string, std::pair<std::string, std::string>>& nodeIndex,
        const JsonArr& usersArr,
        const SidLookup& userLut,
        const JsonArr& computersArr,
        const SidLookup& computerLut,
        const JsonArr& groupsArr,
        const SidLookup& groupLut,
        size_t& attachedCount)
{
    size_t localCount = 0;

    for (AceRecord& record : records) {
        auto principalIt = rbcdByPrincipal.find(record.target_sid);
        if (principalIt != rbcdByPrincipal.end()) {
            for (const RbcdComputer& computer : principalIt->second) {
                AceStep rbcdStep;
                rbcdStep.target_name    = computer.name.empty() ? computer.sid : computer.name;
                rbcdStep.target_sid     = computer.sid;
                rbcdStep.target_dn      = computer.dn;
                rbcdStep.target_type    = "Computer";
                rbcdStep.principal_sid  = record.target_sid;
                rbcdStep.principal_type = record.target_type.empty() ? "User" : record.target_type;
                if (auto infoIt = nodeIndex.find(record.target_sid); infoIt != nodeIndex.end() && !infoIt->second.first.empty())
                    rbcdStep.principal_name = infoIt->second.first;
                else
                    rbcdStep.principal_name = record.target_name.empty() ? record.target_sid : record.target_name;
                rbcdStep.object_acetype = "rbcd";
                rbcdStep.ace_qualifier  = "Allow";
                rbcdStep.rights         = {"RBCD"};
                rbcdStep.rights_display = "RBCD";
                rbcdStep.edge_rights    = {"RBCD"};
                rbcdStep.source_file    = "rbcd";
                rbcdStep.target_attributes = lookupAttrs(computer.sid, "Computer",
                                                         usersArr, userLut,
                                                         computersArr, computerLut,
                                                         groupsArr, groupLut);

                record.next_step.push_back(std::move(rbcdStep));
                ++localCount;
                ++attachedCount;
            }
        }

        localCount += attachRbcdEdgesToSteps(record.next_step, rbcdByPrincipal, nodeIndex,
                                             usersArr, userLut,
                                             computersArr, computerLut,
                                             groupsArr, groupLut,
                                             attachedCount);
    }

    return localCount;
}

static bool valueMatches(const JsonVal& val, const std::string& expectedStr) {
    if (expectedStr == "true" || expectedStr == "True" || expectedStr == "TRUE") {
        return val.isBool() && val.b;
    } else if (expectedStr == "false" || expectedStr == "False" || expectedStr == "FALSE") {
        return val.isBool() && !val.b;
    } else {
        /* Treat as string match */
        return val.isStr() && val.str() == expectedStr;
    }
}


struct VulnerableUser {
    std::string sid;
    std::string name;
    std::string dn;
    bool        pwd_not_required = false;
    bool        asrep = false;
    bool        kerberoastable = false;
    std::vector<std::pair<std::string, JsonVal>> attributes;
};

static std::vector<AceRecord> extractVulnerableUserRecords(
        const JsonVal&     dangerousRoot,
        const JsonVal&     extendedRoot,
        const std::vector<VulnerableUser>& vulnerableUsers)
{
    std::vector<AceRecord> records;
    
    for (const VulnerableUser& vu : vulnerableUsers) {
        auto dangerous = extractMatching(dangerousRoot, vu.sid, vu.name, "dangerous_ace");
        auto extended  = extractMatching(extendedRoot,  vu.sid, vu.name, "extended_rights");
        
        dangerous.insert(dangerous.end(), extended.begin(), extended.end());
        auto merged = mergeAceRecords(std::move(dangerous));
        
        records.insert(records.end(), merged.begin(), merged.end());
    }
    
    return records;
}

static std::vector<AceStep> extractSteps(
        const JsonVal&     root,
        const std::string& targetSid,
        const std::string& principalName,
        const std::string& label)
{
    std::vector<AceStep>          results;
    std::map<std::string, size_t> sidIdx;

    const JsonVal* aclsPtr = root.find("acls");
    if (!aclsPtr || !aclsPtr->isArr()) return results;

    for (const JsonVal& entry : aclsPtr->arr) {
        if (!entry.isObj()) continue;

        const JsonVal* sidPtr = entry.find("principal_sid");
        if (!sidPtr || !sidPtr->isStr()) sidPtr = entry.find("principalSid");
        if (!sidPtr || !sidPtr->isStr()) continue;
        if (sidPtr->str() != targetSid)  continue;

        std::string tSid = getStr(entry, "target_sid");

        auto it = sidIdx.find(tSid);
        if (it != sidIdx.end()) {
            AceStep& existing = results[it->second];
            mergeUnique(existing.rights,      getStrArr(entry, "rights"));
            mergeUnique(existing.edge_rights, getStrArr(entry, "edge_rights"));
            existing.rights_display = rightsDisplay(existing.edge_rights);
            mergeSource(existing.source_file, label);
            continue;
        }

        AceStep s;
        s.source_file    = label;
        s.target_name    = getStr(entry, "target_name");
        s.target_sid     = tSid;
        s.target_dn      = getStr(entry, "target_dn");
        s.target_type    = getStr(entry, "target_type");
        s.principal_sid  = sidPtr->str();
        s.principal_name = principalName;
        s.object_acetype = getStr(entry, "object_acetype");
        if (s.object_acetype.empty())
            s.object_acetype = getStr(entry, "object_ace_type");
        s.ace_qualifier  = getStr(entry, "ace_qualifier");
        s.rights         = getStrArr(entry, "rights");
        s.edge_rights    = getStrArr(entry, "edge_rights");
        s.rights_display = rightsDisplay(s.edge_rights);

        sidIdx[tSid] = results.size();
        results.push_back(std::move(s));
    }

    return results;
}

static std::vector<AceStep> mergeAceSteps(std::vector<AceStep> in) {
    std::vector<AceStep>          out;
    std::map<std::string, size_t> sidIdx;

    for (AceStep& s : in) {
        auto it = sidIdx.find(s.target_sid);
        if (it != sidIdx.end()) {
            AceStep& existing = out[it->second];
            mergeUnique(existing.rights,      s.rights);
            mergeUnique(existing.edge_rights, s.edge_rights);
            existing.rights_display = rightsDisplay(existing.edge_rights);
            mergeSource(existing.source_file, s.source_file);
        } else {
            sidIdx[s.target_sid] = out.size();
            out.push_back(std::move(s));
        }
    }
    return out;
}

using ChainCache = std::map<std::string, std::vector<AceStep>>;

static void resolveChain(
        AceStep&                   step,
        const JsonVal&             dangerousRoot,
        const JsonVal&             extendedRoot,
        std::set<std::string>&     visitedSids,
        ChainCache&                cache,
        int                        depth    = 0,
        int                        maxDepth = 50)
{
    if (step.target_sid.empty())             return;
    if (visitedSids.count(step.target_sid))  return;  

    if (depth >= maxDepth) {
        std::string pad(static_cast<size_t>(depth * 2 + 6), ' ');
        std::cout << pad << "[depth " << depth << "] "
                  << step.target_name << " — max-depth (" << maxDepth
                  << ") reached, chain truncated.\n";
        return;
    }

    auto cacheIt = cache.find(step.target_sid);
    if (cacheIt != cache.end()) {
        step.next_step = cacheIt->second;
        return;
    }

    visitedSids.insert(step.target_sid);

    auto steps_d = extractSteps(dangerousRoot, step.target_sid,
                                step.target_name, "dangerous_ace");
    auto steps_e = extractSteps(extendedRoot,  step.target_sid,
                                step.target_name, "extended_rights");

    steps_d.insert(steps_d.end(), steps_e.begin(), steps_e.end());
    step.next_step = mergeAceSteps(std::move(steps_d));

    if (!step.next_step.empty()) {
        std::string pad(static_cast<size_t>(depth * 2 + 6), ' ');
        std::cout << pad << "[depth " << depth + 1 << "] "
                  << step.target_name << " (" << step.target_sid << ")"
                  << " -> " << step.next_step.size() << " further edge(s)\n";
    }

    for (AceStep& child : step.next_step)
        resolveChain(child, dangerousRoot, extendedRoot, visitedSids, cache, depth + 1, maxDepth);

    cache[step.target_sid] = step.next_step;
}

static size_t countSteps(const std::vector<AceStep>& steps) {
    size_t total = steps.size();
    for (const AceStep& s : steps)
        total += countSteps(s.next_step);
    return total;
}

static std::string jsonValToStr(const JsonVal& v) {
    switch (v.type) {
        case JsonVal::T::Null:   return "null";
        case JsonVal::T::Bool:   return v.b ? "true" : "false";
        case JsonVal::T::Number: {
            double intpart;
            if (std::modf(v.n, &intpart) == 0.0 && v.n >= -1e15 && v.n <= 1e15)
                return std::to_string(static_cast<long long>(intpart));
            return std::to_string(v.n);
        }
        case JsonVal::T::String: return "\"" + jsonEsc(v.s) + "\"";
        case JsonVal::T::Array: {
            std::string r = "[";
            for (size_t i = 0; i < v.arr.size(); ++i) {
                if (i) r += ", ";
                r += jsonValToStr(v.arr[i]);
            }
            return r + "]";
        }
        case JsonVal::T::Object: {
            std::string r = "{";
            for (size_t i = 0; i < v.obj.size(); ++i) {
                if (i) r += ", ";
                r += "\"" + jsonEsc(v.obj[i].first) + "\": " + jsonValToStr(v.obj[i].second);
            }
            return r + "}";
        }
    }
    return "null";
}

static void writeTargetAttributes(
        std::ofstream& f,
        const std::vector<std::pair<std::string, JsonVal>>& attrs,
        const std::string& ind)
{
    if (attrs.empty()) return;
    f << ind << "\"target_attributes\" : {\n";
    for (size_t i = 0; i < attrs.size(); ++i) {
        f << ind << "  \"" << jsonEsc(attrs[i].first) << "\" : "
          << jsonValToStr(attrs[i].second);
        if (i + 1 < attrs.size()) f << ",";
        f << "\n";
    }
    f << ind << "},\n";
}

static void writePrincipalAttributes(
                std::ofstream& f,
                const std::vector<std::pair<std::string, JsonVal>>& attrs,
                const std::string& ind)
{
        if (attrs.empty()) return;
        /*
         * Backwards-compatible writer for principal_attributes. Note: after
         * merging principal attributes into target attributes this will rarely
         * be invoked. Kept for compatibility but not used in merged output.
         */
        f << ind << "\"principal_attributes\" : {\n";
        for (size_t i = 0; i < attrs.size(); ++i) {
                f << ind << "  \"" << jsonEsc(attrs[i].first) << "\" : "
                    << jsonValToStr(attrs[i].second);
                if (i + 1 < attrs.size()) f << ",";
                f << "\n";
        }
        f << ind << "},\n";
}

/* Merge two attribute vectors: values from `primary` take precedence; any
 * keys present in `secondary` but missing from `primary` are appended.
 */
static std::vector<std::pair<std::string, JsonVal>>
mergeAttributes(const std::vector<std::pair<std::string, JsonVal>>& primary,
                const std::vector<std::pair<std::string, JsonVal>>& secondary)
{
    std::vector<std::pair<std::string, JsonVal>> out = primary;
    for (const auto& p : secondary) {
        bool found = false;
        for (const auto& q : primary) {
            if (q.first == p.first) { found = true; break; }
        }
        if (!found) out.push_back(p);
    }
    return out;
}

static void writeStep(std::ofstream& f, const AceStep& s, const std::string& ind) {
    f << ind << "{\n";
    f << ind << "  \"target_name\"    : \"" << jsonEsc(s.target_name)    << "\",\n";
    f << ind << "  \"target_sid\"     : \"" << jsonEsc(s.target_sid)     << "\",\n";
    f << ind << "  \"target_dn\"      : \"" << jsonEsc(s.target_dn)      << "\",\n";
    f << ind << "  \"target_type\"    : \"" << jsonEsc(s.target_type)    << "\",\n";
    f << ind << "  \"principal_sid\"  : \"" << jsonEsc(s.principal_sid)  << "\",\n";
    f << ind << "  \"principal_name\" : \"" << jsonEsc(s.principal_name) << "\",\n";
    if (!s.principal_type.empty())
        f << ind << "  \"principal_type\" : \"" << jsonEsc(s.principal_type) << "\",\n";
    f << ind << "  \"object_acetype\" : \"" << jsonEsc(s.object_acetype) << "\",\n";
    f << ind << "  \"ace_qualifier\"  : \"" << jsonEsc(s.ace_qualifier)  << "\",\n";
    f << ind << "  \"rights\"         : "   << strArrToJson(s.rights)    << ",\n";
    f << ind << "  \"rights_display\" : \"" << jsonEsc(s.rights_display) << "\",\n";
    f << ind << "  \"edge_rights\"    : "   << strArrToJson(s.edge_rights) << ",\n";
    f << ind << "  \"_source\"        : \"" << jsonEsc(s.source_file)    << "\",\n";
    writeTargetAttributes(f, s.target_attributes, ind + "  ");
    f << ind << "  \"next_step\"      : [\n";
    for (size_t k = 0; k < s.next_step.size(); ++k) {
        writeStep(f, s.next_step[k], ind + "    ");
        if (k + 1 < s.next_step.size()) f << ",";
        f << "\n";
    }
    f << ind << "  ]\n";
    f << ind << "}";
}

/* ══ Kerberoasting Attack Vector ══════════════════════════════════════════ */

struct KerberoastUser {
    std::string              sid;
    std::string              name;
    std::string              dn;
    std::vector<std::string> spn;
};

static std::string spnListToJson(const std::vector<std::string>& spns) {
    std::string r = "[";
    for (size_t i = 0; i < spns.size(); ++i) {
        if (i) r += ", ";
        r += "\"" + jsonEsc(spns[i]) + "\"";
    }
    r += "]";
    return r;
}

static std::vector<KerberoastUser> extractKerberoastableUsers(const JsonArr& usersArr) {
    std::vector<KerberoastUser> out;
    for (const JsonVal& entry : usersArr) {
        if (!entry.isObj()) continue;
        const JsonVal* kb = entry.find("kerberoastable");
        if (!kb || !kb->isBool() || !kb->b) continue;

        KerberoastUser ku;
        ku.sid  = getStr(entry, "sid");
        ku.name = getStr(entry, "username");
        ku.dn   = getStr(entry, "dn");
        if (ku.sid.empty() || ku.name.empty()) continue;

        /* Collect SPN list — stored as JSON array in domain_users.json */
        const JsonVal* spnVal = entry.find("spn");
        if (spnVal && spnVal->isArr()) {
            for (const JsonVal& s : spnVal->arr)
                if (s.isStr()) ku.spn.push_back(s.str());
        } else if (spnVal && spnVal->isStr() && !spnVal->str().empty()) {
            ku.spn.push_back(spnVal->str());
        }

        out.push_back(std::move(ku));
    }
    return out;
}

static std::vector<AceRecord> processKerberoasting(
        const std::vector<KerberoastUser>& kbUsers,
        const JsonVal&                     dangerousRoot,
        const JsonVal&                     extendedRoot,
        const JsonArr&                     usersArr,
        const SidLookup&                   userLut,
        const JsonArr&                     computersArr,
        const SidLookup&                   computerLut,
        const JsonArr&                     groupsArr,
        const SidLookup&                   groupLut,
        ChainCache&                        cache,
        int                                maxDepth)
{
    std::vector<AceRecord> results;

    for (const KerberoastUser& ku : kbUsers) {
        std::cout << "  [KERB] " << ku.name << " (" << ku.sid << ")\n";

        /* Build special_edge label: "SPN: [spn1, spn2, ...]" */
        std::string spnLabel = "SPN: " + spnListToJson(ku.spn);

        /* Find all ACEs where this kerberoastable user is the principal */
        auto dangerous = extractMatching(dangerousRoot, ku.sid, ku.name, "dangerous_ace");
        auto extended  = extractMatching(extendedRoot,  ku.sid, ku.name, "extended_rights");
        dangerous.insert(dangerous.end(), extended.begin(), extended.end());
        auto merged = mergeAceRecords(std::move(dangerous));

        if (merged.empty()) {
            /* No outgoing ACEs — emit a pure entry-point node so the user
               still appears in the graph as a kerberoastable account */
            AceRecord ep;
            ep.target_name    = ku.name;
            ep.target_sid     = ku.sid;
            ep.target_dn      = ku.dn;
            ep.target_type    = "User";
            ep.principal_sid  = ku.sid;
            ep.principal_name = ku.name;
            ep.object_acetype = "kerberoastable-entry-point";
            ep.ace_qualifier  = "Allow";
            ep.rights         = {"kerberoastable"};
            ep.rights_display = "Kerberoastable";
            ep.edge_rights    = {"kerberoastable"};
            ep.source_file    = "kerberoasting (no outgoing edges)";
            ep.special_edge   = spnLabel;
            /* Enrich principal attributes (the kerberoastable user itself) */
            ep.principal_attributes = lookupAttrs(ku.sid, "User",
                                                  usersArr, userLut,
                                                  computersArr, computerLut,
                                                  groupsArr, groupLut);
            results.push_back(std::move(ep));
            std::cout << "    -> No outgoing ACEs (pure entry point)\n";
            continue;
        }

        /* Attach special_edge and resolve chains for each outgoing record */
        for (AceRecord& rec : merged) {
            rec.special_edge  = spnLabel;
            rec.source_file   = "kerberoasting -> " + rec.source_file;

            if (rec.target_sid.empty()) continue;

            auto cacheHit = cache.find(rec.target_sid);
            if (cacheHit != cache.end()) {
                rec.next_step = cacheHit->second;
                std::cout << "    [cache hit] " << rec.target_name
                          << " — " << countSteps(rec.next_step) << " edge(s)\n";
                continue;
            }

            std::set<std::string> visited;
            visited.insert(ku.sid);
            visited.insert(rec.target_sid);

            auto steps_d = extractSteps(dangerousRoot, rec.target_sid,
                                        rec.target_name, "dangerous_ace");
            auto steps_e = extractSteps(extendedRoot,  rec.target_sid,
                                        rec.target_name, "extended_rights");
            steps_d.insert(steps_d.end(), steps_e.begin(), steps_e.end());
            rec.next_step = mergeAceSteps(std::move(steps_d));

            for (AceStep& step : rec.next_step)
                resolveChain(step, dangerousRoot, extendedRoot, visited, cache, 0, maxDepth);

            cache[rec.target_sid] = rec.next_step;

            size_t total = countSteps(rec.next_step);
            if (total > 0)
                std::cout << "    -> " << rec.target_name
                          << " : " << total << " edge(s) in chain\n";
        }

        /* Enrich target attributes */
        for (AceRecord& rec : merged) {
            rec.target_attributes = lookupAttrs(rec.target_sid, rec.target_type,
                                                usersArr, userLut,
                                                computersArr, computerLut,
                                                groupsArr, groupLut);
            for (AceStep& s : rec.next_step)
                enrichStepAttributes(s, usersArr, userLut, computersArr, computerLut, groupsArr, groupLut);
        }

        results.insert(results.end(), merged.begin(), merged.end());
        std::cout << "    -> " << merged.size() << " record(s) added\n";
    }

    return results;
}

/* ══ AS-REP Roasting Attack Vector ════════════════════════════════════════ */

struct AsrepUser {
    std::string sid;
    std::string name;
    std::string dn;
};

static std::vector<AsrepUser> extractAsrepUsers(const JsonArr& usersArr) {
    std::vector<AsrepUser> out;
    for (const JsonVal& entry : usersArr) {
        if (!entry.isObj()) continue;
        const JsonVal* ar = entry.find("asrep");
        if (!ar || !ar->isBool() || !ar->b) continue;

        AsrepUser au;
        au.sid  = getStr(entry, "sid");
        au.name = getStr(entry, "username");
        au.dn   = getStr(entry, "dn");
        if (au.sid.empty() || au.name.empty()) continue;

        out.push_back(std::move(au));
    }
    return out;
}

static std::vector<AceRecord> processAsrep(
        const std::vector<AsrepUser>& arUsers,
        const JsonVal&                dangerousRoot,
        const JsonVal&                extendedRoot,
        const JsonArr&                usersArr,
        const SidLookup&              userLut,
        const JsonArr&                computersArr,
        const SidLookup&              computerLut,
        const JsonArr&                groupsArr,
        const SidLookup&              groupLut,
        ChainCache&                   cache,
        int                           maxDepth)
{
    std::vector<AceRecord> results;

    for (const AsrepUser& au : arUsers) {
        std::cout << "  [ASREP] " << au.name << " (" << au.sid << ")\n";

        /* special_edge label — no SPN, use pre-auth attribute marker */
        std::string asrepLabel = "pre_not_auth_required";

        /* Find all outgoing ACEs where this AS-REP user is the principal */
        auto dangerous = extractMatching(dangerousRoot, au.sid, au.name, "dangerous_ace");
        auto extended  = extractMatching(extendedRoot,  au.sid, au.name, "extended_rights");
        dangerous.insert(dangerous.end(), extended.begin(), extended.end());
        auto merged = mergeAceRecords(std::move(dangerous));

        if (merged.empty()) {
            /* No outgoing ACEs — emit a pure entry-point node */
            AceRecord ep;
            ep.target_name    = au.name;
            ep.target_sid     = au.sid;
            ep.target_dn      = au.dn;
            ep.target_type    = "User";
            ep.principal_sid  = au.sid;
            ep.principal_name = au.name;
            ep.object_acetype = "asrep-entry-point";
            ep.ace_qualifier  = "Allow";
            ep.rights         = {"asreproastable"};
            ep.rights_display = "AS-REP Roastable";
            ep.edge_rights    = {"asreproastable"};
            ep.source_file    = "asrep (no outgoing edges)";
            ep.special_edge   = asrepLabel;
            /* Enrich target attributes from domain_users */
            ep.target_attributes = lookupAttrs(au.sid, "User",
                                               usersArr, userLut,
                                               computersArr, computerLut,
                                               groupsArr, groupLut);
            results.push_back(std::move(ep));
            std::cout << "    -> No outgoing ACEs (pure entry point)\n";
            continue;
        }

        /* Attach special_edge and resolve chains for each outgoing record */
        for (AceRecord& rec : merged) {
            rec.special_edge = asrepLabel;
            rec.source_file  = "asrep -> " + rec.source_file;

            if (rec.target_sid.empty()) continue;

            auto cacheHit = cache.find(rec.target_sid);
            if (cacheHit != cache.end()) {
                rec.next_step = cacheHit->second;
                std::cout << "    [cache hit] " << rec.target_name
                          << " — " << countSteps(rec.next_step) << " edge(s)\n";
                continue;
            }

            std::set<std::string> visited;
            visited.insert(au.sid);
            visited.insert(rec.target_sid);

            auto steps_d = extractSteps(dangerousRoot, rec.target_sid,
                                        rec.target_name, "dangerous_ace");
            auto steps_e = extractSteps(extendedRoot,  rec.target_sid,
                                        rec.target_name, "extended_rights");
            steps_d.insert(steps_d.end(), steps_e.begin(), steps_e.end());
            rec.next_step = mergeAceSteps(std::move(steps_d));

            for (AceStep& step : rec.next_step)
                resolveChain(step, dangerousRoot, extendedRoot, visited, cache, 0, maxDepth);

            cache[rec.target_sid] = rec.next_step;

            size_t total = countSteps(rec.next_step);
            if (total > 0)
                std::cout << "    -> " << rec.target_name
                          << " : " << total << " edge(s) in chain\n";
        }

        /* Enrich target attributes */
        for (AceRecord& rec : merged) {
            rec.target_attributes = lookupAttrs(rec.target_sid, rec.target_type,
                                                usersArr, userLut,
                                                computersArr, computerLut,
                                                groupsArr, groupLut);
            for (AceStep& s : rec.next_step)
                enrichStepAttributes(s, usersArr, userLut, computersArr, computerLut, groupsArr, groupLut);
        }

        results.insert(results.end(), merged.begin(), merged.end());
        std::cout << "    -> " << merged.size() << " record(s) added\n";
    }

    return results;
}

/* ══ Password Not Required Attack Vector ══════════════════════════════════ */

struct PwdNotRequiredUser {
    std::string sid;
    std::string name;
    std::string dn;
};

static std::vector<PwdNotRequiredUser> extractPwdNotRequiredUsers(const JsonArr& usersArr) {
    std::vector<PwdNotRequiredUser> out;
    for (const JsonVal& entry : usersArr) {
        if (!entry.isObj()) continue;

        bool isPwdNotRequired = false;
        const JsonVal* pnrUnderscore = entry.find("pwd_not_required");
        if (pnrUnderscore && pnrUnderscore->isBool() && pnrUnderscore->b)
            isPwdNotRequired = true;

        const JsonVal* pnrHyphen = entry.find("pwd-not-required");
        if (pnrHyphen && pnrHyphen->isBool() && pnrHyphen->b)
            isPwdNotRequired = true;

        if (!isPwdNotRequired) continue;

        PwdNotRequiredUser pu;
        pu.sid  = getStr(entry, "sid");
        pu.name = getStr(entry, "username");
        pu.dn   = getStr(entry, "dn");
        if (pu.sid.empty() || pu.name.empty()) continue;

        out.push_back(std::move(pu));
    }
    return out;
}

static std::vector<AceRecord> processPwdNotRequired(
        const std::vector<PwdNotRequiredUser>& pnrUsers,
        const JsonVal&                         dangerousRoot,
        const JsonVal&                         extendedRoot,
        const JsonArr&                         usersArr,
        const SidLookup&                       userLut,
        const JsonArr&                         computersArr,
        const SidLookup&                       computerLut,
        const JsonArr&                         groupsArr,
        const SidLookup&                       groupLut,
        ChainCache&                            cache,
        int                                    maxDepth)
{
    std::vector<AceRecord> results;

    for (const PwdNotRequiredUser& pu : pnrUsers) {
        std::cout << "  [PWD-NOT-REQUIRED] " << pu.name << " (" << pu.sid << ")\n";

        std::string pnrLabel = "PWD-Not-Required";

        auto dangerous = extractMatching(dangerousRoot, pu.sid, pu.name, "dangerous_ace");
        auto extended  = extractMatching(extendedRoot,  pu.sid, pu.name, "extended_rights");
        dangerous.insert(dangerous.end(), extended.begin(), extended.end());
        auto merged = mergeAceRecords(std::move(dangerous));

        if (merged.empty()) {
            AceRecord ep;
            ep.target_name    = pu.name;
            ep.target_sid     = pu.sid;
            ep.target_dn      = pu.dn;
            ep.target_type    = "User";
            ep.principal_sid  = pu.sid;
            ep.principal_name = pu.name;
            ep.object_acetype = "pwd-not-required-entry-point";
            ep.ace_qualifier  = "Allow";
            ep.rights         = {"PWD-Not-Required"};
            ep.rights_display = "PWD-Not-Required";
            ep.edge_rights    = {"PWD-Not-Required"};
            ep.source_file    = "pwd-not-required (no outgoing edges)";
            ep.special_edge   = pnrLabel;
            ep.target_attributes = lookupAttrs(pu.sid, "User",
                                               usersArr, userLut,
                                               computersArr, computerLut,
                                               groupsArr, groupLut);
            results.push_back(std::move(ep));
            std::cout << "    -> No outgoing ACEs (pure entry point)\n";
            continue;
        }

        for (AceRecord& rec : merged) {
            rec.special_edge = pnrLabel;
            rec.source_file  = "pwd-not-required -> " + rec.source_file;

            if (rec.target_sid.empty()) continue;

            auto cacheHit = cache.find(rec.target_sid);
            if (cacheHit != cache.end()) {
                rec.next_step = cacheHit->second;
                std::cout << "    [cache hit] " << rec.target_name
                          << " — " << countSteps(rec.next_step) << " edge(s)\n";
                continue;
            }

            std::set<std::string> visited;
            visited.insert(pu.sid);
            visited.insert(rec.target_sid);

            auto steps_d = extractSteps(dangerousRoot, rec.target_sid,
                                        rec.target_name, "dangerous_ace");
            auto steps_e = extractSteps(extendedRoot,  rec.target_sid,
                                        rec.target_name, "extended_rights");
            steps_d.insert(steps_d.end(), steps_e.begin(), steps_e.end());
            rec.next_step = mergeAceSteps(std::move(steps_d));

            for (AceStep& step : rec.next_step)
                resolveChain(step, dangerousRoot, extendedRoot, visited, cache, 0, maxDepth);

            cache[rec.target_sid] = rec.next_step;

            size_t total = countSteps(rec.next_step);
            if (total > 0)
                std::cout << "    -> " << rec.target_name
                          << " : " << total << " edge(s) in chain\n";
        }

        for (AceRecord& rec : merged) {
            rec.target_attributes = lookupAttrs(rec.target_sid, rec.target_type,
                                                usersArr, userLut,
                                                computersArr, computerLut,
                                                groupsArr, groupLut);
            for (AceStep& s : rec.next_step)
                enrichStepAttributes(s, usersArr, userLut, computersArr, computerLut, groupsArr, groupLut);
        }

        results.insert(results.end(), merged.begin(), merged.end());
        std::cout << "    -> " << merged.size() << " record(s) added\n";
    }

    return results;
}

/* ══ Encryption Types Attack Vector ═══════════════════════════════════════ */

struct EncryptionUser {
    std::string sid;
    std::string name;
    std::string dn;
    std::string strongest_algo;
};

static std::string strongestEncryptionAlgo(const JsonVal& encList) {
    if (!encList.isArr() || encList.arr.empty()) return "";

    std::string bestName;
    double      bestRisk = -1.0;

    for (const JsonVal& item : encList.arr) {
        if (item.isObj()) {
            std::string name = getStr(item, "name");
            if (name.empty()) continue;

            double risk = 0.0;
            if (const JsonVal* riskVal = item.find("risk")) {
                if (riskVal->isNum()) risk = riskVal->n;
                else if (riskVal->isStr()) {
                    try { risk = std::stod(riskVal->s); } catch (...) { risk = 0.0; }
                }
            }

            if (bestName.empty() || risk > bestRisk) {
                bestName = name;
                bestRisk = risk;
            }
        } else if (item.isStr()) {
            if (bestName.empty()) bestName = item.str();
        }
    }

    return bestName;
}

static std::vector<EncryptionUser> extractEncryptionUsers(const JsonArr& usersArr) {
    std::vector<EncryptionUser> out;

    for (const JsonVal& entry : usersArr) {
        if (!entry.isObj()) continue;

        const JsonVal* encList = entry.find("msds_supportedencryptiontypes_name");
        if (!encList || !encList->isArr() || encList->arr.empty()) {
            encList = entry.find("msds_supportedencryptiontypesname");
        }
        if (!encList || !encList->isArr() || encList->arr.empty()) continue;

        std::string strongest = strongestEncryptionAlgo(*encList);
        if (strongest.empty()) continue;

        EncryptionUser eu;
        eu.sid = getStr(entry, "sid");
        eu.name = getStr(entry, "username");
        eu.dn = getStr(entry, "dn");
        eu.strongest_algo = strongest;
        if (eu.sid.empty() || eu.name.empty()) continue;

        out.push_back(std::move(eu));
    }

    return out;
}

static std::vector<AceRecord> processEncryption(
        const std::vector<EncryptionUser>& encUsers,
        const JsonVal&                     dangerousRoot,
        const JsonVal&                     extendedRoot,
        const JsonArr&                     usersArr,
        const SidLookup&                   userLut,
        const JsonArr&                     computersArr,
        const SidLookup&                   computerLut,
        const JsonArr&                     groupsArr,
        const SidLookup&                   groupLut,
        ChainCache&                        cache,
        int                                maxDepth)
{
    std::vector<AceRecord> results;

    for (const EncryptionUser& eu : encUsers) {
        std::cout << "  [ENC] " << eu.name << " (" << eu.sid << ")"
                  << " -> " << eu.strongest_algo << "\n";

        const std::string edgeLabel = eu.strongest_algo;

        auto dangerous = extractMatching(dangerousRoot, eu.sid, eu.name, "dangerous_ace");
        auto extended  = extractMatching(extendedRoot,  eu.sid, eu.name, "extended_rights");
        dangerous.insert(dangerous.end(), extended.begin(), extended.end());
        auto merged = mergeAceRecords(std::move(dangerous));

        if (merged.empty()) {
            AceRecord ep;
            ep.target_name    = eu.name;
            ep.target_sid     = eu.sid;
            ep.target_dn      = eu.dn;
            ep.target_type    = "User";
            ep.principal_sid  = eu.sid;
            ep.principal_name = eu.name;
            ep.object_acetype = "encryption-entry-point";
            ep.ace_qualifier  = "Allow";
            ep.rights         = {edgeLabel};
            ep.rights_display = edgeLabel;
            ep.edge_rights    = {edgeLabel};
            ep.source_file    = "encryption (no outgoing edges)";
            ep.special_edge   = edgeLabel;
            ep.target_attributes = lookupAttrs(eu.sid, "User",
                                               usersArr, userLut,
                                               computersArr, computerLut,
                                               groupsArr, groupLut);
            results.push_back(std::move(ep));
            std::cout << "    -> No outgoing ACEs (pure entry point)\n";
            continue;
        }

        for (AceRecord& rec : merged) {
            rec.special_edge   = edgeLabel;
            rec.rights         = {edgeLabel};
            rec.rights_display = edgeLabel;
            rec.edge_rights    = {edgeLabel};
            rec.source_file    = "encryption -> " + rec.source_file;

            if (rec.target_sid.empty()) continue;

            auto cacheHit = cache.find(rec.target_sid);
            if (cacheHit != cache.end()) {
                rec.next_step = cacheHit->second;
                std::cout << "    [cache hit] " << rec.target_name
                          << " — " << countSteps(rec.next_step) << " edge(s)\n";
                continue;
            }

            std::set<std::string> visited;
            visited.insert(eu.sid);
            visited.insert(rec.target_sid);

            auto steps_d = extractSteps(dangerousRoot, rec.target_sid,
                                        rec.target_name, "dangerous_ace");
            auto steps_e = extractSteps(extendedRoot,  rec.target_sid,
                                        rec.target_name, "extended_rights");
            steps_d.insert(steps_d.end(), steps_e.begin(), steps_e.end());
            rec.next_step = mergeAceSteps(std::move(steps_d));

            for (AceStep& step : rec.next_step)
                resolveChain(step, dangerousRoot, extendedRoot, visited, cache, 0, maxDepth);

            cache[rec.target_sid] = rec.next_step;

            size_t total = countSteps(rec.next_step);
            if (total > 0)
                std::cout << "    -> " << rec.target_name
                          << " : " << total << " edge(s) in chain\n";
        }

        for (AceRecord& rec : merged) {
            rec.target_attributes = lookupAttrs(rec.target_sid, rec.target_type,
                                                usersArr, userLut,
                                                computersArr, computerLut,
                                                groupsArr, groupLut);
            for (AceStep& s : rec.next_step)
                enrichStepAttributes(s, usersArr, userLut, computersArr, computerLut, groupsArr, groupLut);
        }

        results.insert(results.end(), merged.begin(), merged.end());
        std::cout << "    -> " << merged.size() << " record(s) added\n";
    }

    return results;
}

/* ═══════════════════════════════════════════════════════════════════════════ */

static void writeRecord(
        std::ofstream&       f,
        const AceRecord&     r,
        bool                 isLast)
{
    f << "    {\n";
    f << "      \"target_name\"    : \"" << jsonEsc(r.target_name)    << "\",\n";
    f << "      \"target_sid\"     : \"" << jsonEsc(r.target_sid)     << "\",\n";
    f << "      \"target_dn\"      : \"" << jsonEsc(r.target_dn)      << "\",\n";
    f << "      \"target_type\"    : \"" << jsonEsc(r.target_type)    << "\",\n";
    f << "      \"principal_sid\"  : \"" << jsonEsc(r.principal_sid)  << "\",\n";
    f << "      \"principal_name\" : \"" << jsonEsc(r.principal_name) << "\",\n";
    f << "      \"object_acetype\" : \"" << jsonEsc(r.object_acetype) << "\",\n";
    f << "      \"ace_qualifier\"  : \"" << jsonEsc(r.ace_qualifier)  << "\",\n";
    f << "      \"rights\"         : "   << strArrToJson(r.rights)      << ",\n";
    f << "      \"rights_display\" : \"" << jsonEsc(r.rights_display) << "\",\n";
    f << "      \"edge_rights\"    : "   << strArrToJson(r.edge_rights) << ",\n";
    /* Merge principal attributes into target attributes so consumer code
     * only needs to examine `target_attributes`.
     */
    const auto mergedAttrs = mergeAttributes(r.target_attributes, r.principal_attributes);
    writeTargetAttributes(f, mergedAttrs, "      ");
    if (!r.special_edge.empty())
        f << "      \"special_edge\"   : \"" << jsonEsc(r.special_edge) << "\",\n";
    f << "      \"next_step\"      : [\n";
    for (size_t j = 0; j < r.next_step.size(); ++j) {
        writeStep(f, r.next_step[j], "        ");
        if (j + 1 < r.next_step.size()) f << ",";
        f << "\n";
    }
    f << "      ],\n";
    f << "      \"_source\"        : \"" << jsonEsc(r.source_file) << "\"\n";
    f << "    }";
    if (!isLast) f << ",";
    f << "\n";
}

static void writeGraphObjects(
        const std::string&            outPath,
        const std::string&            sid,
        const std::string&            name,
        const std::vector<AceRecord>& records,
        const std::vector<AceRecord>& attackVectorRecords = {},
        const std::vector<AceRecord>& asrepRecords = {},
        const std::vector<AceRecord>& pwdNotRequiredRecords = {},
        const std::vector<AceRecord>& encryptionRecords = {})
{
    std::ofstream f(outPath, std::ios::out | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot write to file: " + outPath);

    size_t totalRecords = records.size()
                      + attackVectorRecords.size()
                      + asrepRecords.size()
                      + pwdNotRequiredRecords.size()
                      + encryptionRecords.size();

    f << "{\n";
    f << "  \"principal_sid\"  : \"" << jsonEsc(sid)  << "\",\n";
    f << "  \"principal_name\" : \"" << jsonEsc(name) << "\",\n";
    f << "  \"total\"          : "    << totalRecords  << ",\n";

    f << "  \"graph_objects\"  : [\n";

    size_t idx = 0;

    for (size_t i = 0; i < records.size(); ++i, ++idx) {
        writeRecord(f, records[i], (idx + 1 == totalRecords));
    }

    for (size_t i = 0; i < attackVectorRecords.size(); ++i, ++idx) {
        writeRecord(f, attackVectorRecords[i], (idx + 1 == totalRecords));
    }

    for (size_t i = 0; i < asrepRecords.size(); ++i, ++idx) {
        writeRecord(f, asrepRecords[i], (idx + 1 == totalRecords));
    }

    for (size_t i = 0; i < pwdNotRequiredRecords.size(); ++i, ++idx) {
        writeRecord(f, pwdNotRequiredRecords[i], (idx + 1 == totalRecords));
    }

    for (size_t i = 0; i < encryptionRecords.size(); ++i, ++idx) {
        writeRecord(f, encryptionRecords[i], (idx + 1 == totalRecords));
    }

    f << "  ]\n";
    f << "}\n";
    f.flush();
    if (!f) throw std::runtime_error("Write error on file: " + outPath);
}

/* Forward declaration for member-of helper (implementation located below) */
static size_t attachMemberOfEdges(
    const std::map<long, PrivGroup>& privByToken,
    const std::map<std::string, std::pair<std::string, std::string>>& nodeIndex,
    const JsonArr& usersArr,
    const SidLookup& userLut,
    const JsonArr& computersArr,
    const SidLookup& computerLut,
    const JsonArr& groupsArr,
    const SidLookup& groupLut,
    std::vector<AceRecord>& outGroupRecords);


int main(int argc, char* argv[]) {

    const std::filesystem::path exePath   = std::filesystem::absolute(argv[0]);
    const std::filesystem::path engineDir = exePath.parent_path();

    std::filesystem::path oxsiumRoot;

    {
        std::filesystem::path p = engineDir;
        while (!p.empty() && p != p.parent_path()) {
            if (p.filename().string() == "Main") {
                oxsiumRoot = p;
                break;
            }
            p = p.parent_path();
        }
    }

    /* Strategy 2: Look for parent of "Decision Engine" folder (which contains Main) */
    if (oxsiumRoot.empty()) {
        std::filesystem::path p = engineDir;
        while (!p.empty() && p != p.parent_path()) {
            if (p.filename().string() == "Decision Engine") {
                /* Main is the parent of Decision Engine */
                oxsiumRoot = p.parent_path();
                break;
            }
            p = p.parent_path();
        }
    }

    if (oxsiumRoot.empty()) {
        std::filesystem::path p = engineDir;
        while (!p.empty() && p != p.parent_path()) {
            if (std::filesystem::exists(p / "Domain Object")) {
                oxsiumRoot = p;
                break;
            }
            p = p.parent_path();
        }
    }

    if (oxsiumRoot.empty()) {
        oxsiumRoot = engineDir;
        std::cerr << "[WARN] Could not locate Main root automatically.\n"
                  << "       Falling back to exe directory: " << oxsiumRoot << "\n"
                  << "       Use --dangerous / --extended / --users / --computers / --groups\n"
                  << "       to specify file paths explicitly.\n";
    }

    std::cout << "[*] Main root : " << oxsiumRoot.string() << "\n";

    /* Keep repoRoot as an alias for backward compatibility */
    const std::filesystem::path& repoRoot = oxsiumRoot;

    /* Argument Parsing */
    std::string sid           = "";
    std::string name          = "";
    std::string dbFile        = (repoRoot / "Domain Object" / "domain_data.db").string();
    std::string outFile       = (engineDir   / "graph_objects.json").string();
    int         maxDepth      = 50;
    
    bool flagGpos              = false;
    bool flagOus               = false;
    bool flagTrusts            = false;
    bool flagKerberoasting     = false;
    bool flagAsrep             = false;
    bool flagPwdNotRequired    = false;
    bool flagEncryption        = false;
    bool flagKeyCredentialLink = false;
    bool flagRbcd              = false;
    bool flagMemberOf          = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if      ((arg == "-r" || arg == "--root") && i + 1 < argc) sid           = argv[++i];
        else if ((arg == "-n" || arg == "--name") && i + 1 < argc) name          = argv[++i];
        else if  (arg == "--db"                   && i + 1 < argc) dbFile        = argv[++i];
        else if  (arg == "--out"                  && i + 1 < argc) outFile       = argv[++i];
        else if  (arg == "--gpos")                flagGpos              = true;
        else if  (arg == "--ous")                 flagOus               = true;
        else if  (arg == "--trusts")              flagTrusts            = true;
        else if  (arg == "--kerberoasting")       flagKerberoasting     = true;
        else if  (arg == "--asrep")               flagAsrep             = true;
        else if  (arg == "--pwd-not-required")    flagPwdNotRequired    = true;
        else if  (arg == "--encryption")          flagEncryption        = true;
        else if  (arg == "--key-credential-link") flagKeyCredentialLink = true;
        else if  (arg == "--rbcd")                flagRbcd              = true;
        else if  (arg == "--member-of")           flagMemberOf          = true;
        else if  (arg == "--max-depth"            && i + 1 < argc) {
            try {
                int v = std::stoi(argv[++i]);
                if (v < 1)
                    std::cerr << "[WARN] --max-depth must be >= 1, using default (50).\n";
                else
                    maxDepth = v;
            } catch (...) {
                std::cerr << "[WARN] Invalid --max-depth value, using default (50).\n";
            }
        }
        else std::cerr << "[WARN] Unknown argument: " << arg << "\n";
    }

    if (sid.empty() || name.empty()) {
        std::cerr
            << "Usage: graph_engine -r <SID> -n <NAME> [options]\n\n"
            << "Required:\n"
            << "  -r, --root  <SID>    Root principal SID to filter by\n"
            << "  -n, --name  <NAME>   Root principal name (computer_name or username)\n\n"
            << "Options:\n"
            << "  --db        <file>   Path to domain_data.db (SQLite)\n"
            << "                       (default: " << dbFile << ")\n"
            << "  --out       <file>   Output destination file\n"
            << "                       (default: " << outFile << ")\n"
            << "  --gpos               Enumerate Group Policy Objects\n"
            << "  --ous                Enumerate Organizational Units\n"
            << "  --trusts             Enumerate domain trusts\n"
            << "  --kerberoasting      Find kerberoastable accounts\n"
            << "  --asrep              Find AS-REP roastable accounts\n"
            << "  --pwd-not-required   Find accounts with password not required\n"
            << "  --encryption         Enumerate encryption settings\n"
            << "  --key-credential-link Find accounts with key credential link\n"
            << "  --rbcd               Find Resource-Based Constrained Delegation targets\n"
            << "  --member-of          Enumerate group memberships\n"
            << "  --max-depth <int>    Maximum hop depth for next_step resolution\n"
            << "                       (default: 50, min: 1)\n\n"
            << "Examples:\n"
            << "  graph_engine -r S-1-5-21-767238238-2156610861-601915929-527 -n JohnDoe\n"
            << "  graph_engine -r S-1-5-21-... -n JohnDoe --kerberoasting\n"
            << "  graph_engine -r S-1-5-21-... -n JohnDoe --asrep --pwd-not-required\n";
        return 1;
    }

    std::cout << "------------------------------------------------\n";
    std::cout << "|       ACE Graph Engine - Oxsium Framework   |\n";
    std::cout << "------------------------------------------------\n";
    std::cout << "  Root SID   : " << sid           << "\n";
    std::cout << "  Root Name  : " << name          << "\n";

    /* Load everything from the SQLite database once — reused for both
     * Level-1 and Level-2 resolution. */
    std::cout << "[*] Opening database: " << dbFile << "\n";
    sqlite3* db = nullptr;
    try {
        db = openDomainDb(dbFile);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 2;
    }

    std::cout << "[*] Loading ACE data via SQL (dangerous_ace, extended_rights)...\n";
    JsonVal dangerousRoot = loadAclsFromDb(db, "dangerous_ace");
    JsonVal extendedRoot  = loadAclsFromDb(db, "extended_rights");

    std::cout << "[*] Loading domain objects via SQL (users, computers, groups) for enrichment...\n";
    JsonVal usersRoot     = loadUsersFromDb(db);
    JsonVal computersRoot = loadComputersFromDb(db);
    JsonVal groupsRoot    = loadGroupsFromDb(db);

    sqlite3_close(db);

    /* Build SID lookup tables */
    static const JsonArr emptyArr;
    const JsonArr& usersArr     = (usersRoot.isObj()     && usersRoot.find("users")     && usersRoot.find("users")->isArr())     ? usersRoot.find("users")->arr     : emptyArr;
    const JsonArr& computersArr = (computersRoot.isObj() && computersRoot.find("computers") && computersRoot.find("computers")->isArr()) ? computersRoot.find("computers")->arr : emptyArr;
    const JsonArr& groupsArr    = (groupsRoot.isObj()    && groupsRoot.find("groups")   && groupsRoot.find("groups")->isArr())   ? groupsRoot.find("groups")->arr   : emptyArr;

    SidLookup userLut     = buildSidLookup(usersArr);
    SidLookup computerLut = buildSidLookup(computersArr);
    SidLookup groupLut    = buildSidLookup(groupsArr);

    const std::vector<std::pair<std::string, JsonVal>> rootUserAttrs =
        lookupAttrs(sid, "User",
                    usersArr, userLut,
                    computersArr, computerLut,
                    groupsArr, groupLut);

    auto boolAttrText = [](const std::vector<std::pair<std::string, JsonVal>>& attrs,
                           const std::string& key) -> std::string {
        for (const auto& p : attrs) {
            if (p.first != key) continue;
            if (p.second.isBool()) return p.second.b ? "true" : "false";
            if (p.second.isStr()) return p.second.s.empty() ? "false" : p.second.s;
            if (p.second.isNum()) return p.second.n != 0.0 ? "true" : "false";
            return "false";
        }
        return "n/a";
    };

    std::cout << "    users     : " << usersArr.size()     << " object(s), "
              << userLut.size()     << " indexed\n";
    std::cout << "    computers : " << computersArr.size() << " object(s), "
              << computerLut.size() << " indexed\n";
    std::cout << "    groups    : " << groupsArr.size()    << " object(s), "
              << groupLut.size()    << " indexed\n";

    std::cout << "  is_admin        : " << boolAttrText(rootUserAttrs, "is_admin") << "\n";
    std::cout << "  potential_admin  : " << boolAttrText(rootUserAttrs, "potential_admin") << "\n";
    std::cout << "  Database   : " << dbFile         << "\n";
    std::cout << "  Output     : " << outFile        << "\n";
    std::cout << "  Max Depth  : " << maxDepth       << " hop(s)\n\n";

    /* Level-1: root principal -> direct targets */
    std::cout << "[*] Level-1 - scanning for principal_sid: " << sid << "\n";

    auto dangerous = extractMatching(dangerousRoot, sid, name, "dangerous_ace");
    std::cout << "    dangerous_ace    : " << dangerous.size() << " record(s)\n";

    auto extended  = extractMatching(extendedRoot,  sid, name, "extended_rights");
    std::cout << "    extended_rights  : " << extended.size()  << " record(s)\n";

    dangerous.insert(dangerous.end(), extended.begin(), extended.end());
    std::vector<AceRecord> all = mergeAceRecords(std::move(dangerous));
    std::cout << "    merged total     : " << all.size() << " unique target(s)\n";

    if (all.empty()) {
        std::cout << "\n[!] No matching ACEs found for root SID.\n";
    }

    /* ── Resolve chains for root principal's L1 records (if any) ── */
    size_t     totalSteps = 0;
    ChainCache chainCache;           /* global cache: target_sid -> chain */

    if (!all.empty()) {
        std::cout << "\n[*] Recursive next_step resolution...\n";

        for (AceRecord& rec : all) {
            if (rec.target_sid.empty()) {
                std::cout << "    [SKIP] " << rec.target_name
                          << " — no target_sid available\n";
                continue;
            }

            std::cout << "    [L1] " << rec.target_name
                      << " (" << rec.target_sid << ")\n";

            auto cacheHit = chainCache.find(rec.target_sid);
            if (cacheHit != chainCache.end()) {
                rec.next_step = cacheHit->second;
                std::cout << "      [cache hit] chain reused — "
                          << countSteps(rec.next_step) << " edge(s)\n";
                totalSteps += countSteps(rec.next_step);
                continue;
            }

            std::set<std::string> visited;
            visited.insert(sid);               /* root principal — never loop back */
            visited.insert(rec.target_sid);    /* mark L1 target as expanded       */

            auto steps_d = extractSteps(dangerousRoot, rec.target_sid,
                                        rec.target_name, "dangerous_ace");
            auto steps_e = extractSteps(extendedRoot,  rec.target_sid,
                                        rec.target_name, "extended_rights");

            /* Cross-file merge: same target_sid from both files → one AceStep */
            steps_d.insert(steps_d.end(), steps_e.begin(), steps_e.end());
            rec.next_step = mergeAceSteps(std::move(steps_d));

            if (!rec.next_step.empty()) {
                std::cout << "      [depth 0] " << rec.next_step.size()
                          << " direct edge(s) — expanding recursively...\n";
            }

            for (AceStep& step : rec.next_step)
                resolveChain(step, dangerousRoot, extendedRoot, visited, chainCache);

            /* Cache the result for any duplicate L1 records with same target_sid */
            chainCache[rec.target_sid] = rec.next_step;

            size_t recTotal = countSteps(rec.next_step);
            totalSteps += recTotal;

            if (recTotal > 0)
                std::cout << "      -> " << recTotal << " total edge(s) in chain\n";
        }

        /* Enrich every L1 record and its recursive steps with domain attributes */
        for (AceRecord& rec : all) {
            rec.target_attributes = lookupAttrs(rec.target_sid, rec.target_type,
                                               usersArr, userLut,
                                               computersArr, computerLut,
                                               groupsArr, groupLut);
            for (AceStep& s : rec.next_step)
                enrichStepAttributes(s, usersArr, userLut, computersArr, computerLut, groupsArr, groupLut);
        }
    } else {
        std::cout << "\n[!] No ACEs found for root SID — skipping L1 chain resolution.\n";
    }

    /* ══ Process --kerberoasting flag ══ */
    std::vector<AceRecord> kerberoastingRecords;
    if (flagKerberoasting) {
        std::cout << "\n[*] Processing --kerberoasting attack vectors...\n";
        auto kbUsers = extractKerberoastableUsers(usersArr);
        std::cout << "    Found " << kbUsers.size() << " kerberoastable user(s)\n";
        if (!kbUsers.empty()) {
            kerberoastingRecords = processKerberoasting(
                kbUsers, dangerousRoot, extendedRoot,
                usersArr, userLut, computersArr, computerLut, groupsArr, groupLut,
                chainCache, maxDepth);
            std::cout << "    Kerberoasting records resolved: "
                      << kerberoastingRecords.size() << " record(s)\n";
        }
    }

    /* ══ Process --asrep flag ══ */
    std::vector<AceRecord> asrepRecords;
    if (flagAsrep) {
        std::cout << "\n[*] Processing --asrep attack vectors...\n";
        auto arUsers = extractAsrepUsers(usersArr);
        std::cout << "    Found " << arUsers.size() << " AS-REP roastable user(s)\n";
        if (!arUsers.empty()) {
            asrepRecords = processAsrep(
                arUsers, dangerousRoot, extendedRoot,
                usersArr, userLut, computersArr, computerLut, groupsArr, groupLut,
                chainCache, maxDepth);
            std::cout << "    AS-REP records resolved: "
                      << asrepRecords.size() << " record(s)\n";
        }
    }

    /* ══ Process --pwd-not-required flag ══ */
    std::vector<AceRecord> pwdNotRequiredRecords;
    if (flagPwdNotRequired) {
        std::cout << "\n[*] Processing --pwd-not-required attack vectors...\n";
        auto pnrUsers = extractPwdNotRequiredUsers(usersArr);
        std::cout << "    Found " << pnrUsers.size() << " pwd-not-required user(s)\n";
        if (!pnrUsers.empty()) {
            pwdNotRequiredRecords = processPwdNotRequired(
                pnrUsers, dangerousRoot, extendedRoot,
                usersArr, userLut, computersArr, computerLut, groupsArr, groupLut,
                chainCache, maxDepth);
            std::cout << "    Pwd-not-required records resolved: "
                      << pwdNotRequiredRecords.size() << " record(s)\n";
        }
    }

    /* ══ Process --encryption flag ══ */
    std::vector<AceRecord> encryptionRecords;
    if (flagEncryption) {
        std::cout << "\n[*] Processing --encryption attack vectors...\n";
        auto encUsers = extractEncryptionUsers(usersArr);
        std::cout << "    Found " << encUsers.size() << " encryption-configured user(s)\n";
        if (!encUsers.empty()) {
            encryptionRecords = processEncryption(
                encUsers, dangerousRoot, extendedRoot,
                usersArr, userLut, computersArr, computerLut, groupsArr, groupLut,
                chainCache, maxDepth);
            std::cout << "    Encryption records resolved: "
                      << encryptionRecords.size() << " record(s)\n";
        }
    }

    /* ══ Process --rbcd flag ══ */
    
    size_t rbcdEdgesAttached = 0;
    size_t rbcdRelationships = 0;
    if (flagRbcd) {
        std::cout << "\n[*] Processing --rbcd attack vectors...\n";
        auto rbcdComputers = extractRbcdComputers(computersArr);
        std::cout << "    Found " << rbcdComputers.size() << " rbcd-enabled computer(s)\n";

        std::map<std::string, std::vector<RbcdComputer>> rbcdByPrincipal;
        for (const RbcdComputer& computer : rbcdComputers) {
            for (const std::string& principalSid : computer.principals)
                rbcdByPrincipal[principalSid].push_back(computer);
        }

        std::map<std::string, std::pair<std::string, std::string>> nodeIndex;
        for (const AceRecord& rec : all)
            collectNodeIndexFromRecord(rec, nodeIndex);
        for (const AceRecord& rec : kerberoastingRecords)
            collectNodeIndexFromRecord(rec, nodeIndex);
        for (const AceRecord& rec : asrepRecords)
            collectNodeIndexFromRecord(rec, nodeIndex);
        for (const AceRecord& rec : pwdNotRequiredRecords)
            collectNodeIndexFromRecord(rec, nodeIndex);
        for (const AceRecord& rec : encryptionRecords)
            collectNodeIndexFromRecord(rec, nodeIndex);

        rbcdRelationships += attachRbcdEdgesToRecords(
            all, rbcdByPrincipal, nodeIndex,
            usersArr, userLut, computersArr, computerLut, groupsArr, groupLut,
            rbcdEdgesAttached);
        rbcdRelationships += attachRbcdEdgesToRecords(
            kerberoastingRecords, rbcdByPrincipal, nodeIndex,
            usersArr, userLut, computersArr, computerLut, groupsArr, groupLut,
            rbcdEdgesAttached);
        rbcdRelationships += attachRbcdEdgesToRecords(
            asrepRecords, rbcdByPrincipal, nodeIndex,
            usersArr, userLut, computersArr, computerLut, groupsArr, groupLut,
            rbcdEdgesAttached);
        rbcdRelationships += attachRbcdEdgesToRecords(
            pwdNotRequiredRecords, rbcdByPrincipal, nodeIndex,
            usersArr, userLut, computersArr, computerLut, groupsArr, groupLut,
            rbcdEdgesAttached);
        rbcdRelationships += attachRbcdEdgesToRecords(
            encryptionRecords, rbcdByPrincipal, nodeIndex,
            usersArr, userLut, computersArr, computerLut, groupsArr, groupLut,
            rbcdEdgesAttached);

        std::cout << "    RBCD edges attached: " << rbcdEdgesAttached << "\n";
    }

    /* ══ Process --member-of flag ══ */
    size_t memberOfEdgesAttached = 0;
    if (flagMemberOf) {
        std::cout << "\n[*] Processing --member-of relationships...\n";
        auto privGroups = extractPrivilegedGroups(groupsArr);
        std::cout << "    Found " << privGroups.size() << " privileged group(s)\n";

        if (!privGroups.empty()) {
            std::map<long, PrivGroup> privByToken;
            for (const PrivGroup& g : privGroups)
                privByToken[g.primaryToken] = g;

            std::map<std::string, std::pair<std::string, std::string>> nodeIndex;
            for (const AceRecord& rec : all)
                collectNodeIndexFromRecord(rec, nodeIndex);
            for (const AceRecord& rec : kerberoastingRecords)
                collectNodeIndexFromRecord(rec, nodeIndex);
            for (const AceRecord& rec : asrepRecords)
                collectNodeIndexFromRecord(rec, nodeIndex);
            for (const AceRecord& rec : pwdNotRequiredRecords)
                collectNodeIndexFromRecord(rec, nodeIndex);
            for (const AceRecord& rec : encryptionRecords)
                collectNodeIndexFromRecord(rec, nodeIndex);

            std::vector<AceRecord> memberOfRecords;
            memberOfEdgesAttached = attachMemberOfEdges(
                privByToken, nodeIndex,
                usersArr, userLut,
                computersArr, computerLut,
                groupsArr, groupLut,
                memberOfRecords);

            /* Append generated group records to attack-vector list so they are
             * included in the final output alongside other special records. */
            if (!memberOfRecords.empty()) {
                std::cout << "    MemberOf group records created: " << memberOfRecords.size() << "\n";
                /* append */
                kerberoastingRecords.insert(kerberoastingRecords.end(), memberOfRecords.begin(), memberOfRecords.end());
            }
        }

        std::cout << "    MemberOf edges attached: " << memberOfEdgesAttached << "\n";
    }

    /* Write Output */
    std::cout << "\n[*] Writing " << all.size() << " L1 record(s) + "
              << totalSteps << " recursive edge(s)";
    if (!kerberoastingRecords.empty())
        std::cout << " + " << kerberoastingRecords.size() << " kerberoasting record(s)";
    if (!asrepRecords.empty())
        std::cout << " + " << asrepRecords.size() << " AS-REP record(s)";
    if (!pwdNotRequiredRecords.empty())
        std::cout << " + " << pwdNotRequiredRecords.size() << " pwd-not-required record(s)";
    if (!encryptionRecords.empty())
        std::cout << " + " << encryptionRecords.size() << " encryption record(s)";
    if (rbcdEdgesAttached > 0)
        std::cout << " + " << rbcdEdgesAttached << " rbcd edge(s)";
    if (memberOfEdgesAttached > 0)
        std::cout << " + " << memberOfEdgesAttached << " memberof edge(s)";
    std::cout << " to " << outFile << "...\n";
    try {
        writeGraphObjects(outFile, sid, name, all, kerberoastingRecords, asrepRecords, pwdNotRequiredRecords, encryptionRecords);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 2;
    }

    std::cout << "[+] Completed successfully.\n\n";

    /* Summary */
    std::cout << "-- Output Summary ----------------------------\n";
    std::cout << "  File                    : " << outFile         << "\n";
    std::cout << "  L1 Edges (total)        : " << all.size()      << "\n";
    std::cout << "    dangerous_ace         : " << dangerous.size() << "\n";
    std::cout << "    extended_rights       : " << extended.size()  << "\n";
    std::cout << "  next_step edges (total) : " << totalSteps       << "\n";
    std::cout << "    (fully recursive — all depths)\n";
    if (flagKerberoasting)
        std::cout << "  Kerberoasting records   : " << kerberoastingRecords.size() << "\n";
    if (flagAsrep)
        std::cout << "  AS-REP records          : " << asrepRecords.size() << "\n";
    if (flagPwdNotRequired)
        std::cout << "  Pwd-not-required records: " << pwdNotRequiredRecords.size() << "\n";
    if (flagEncryption)
        std::cout << "  Encryption records       : " << encryptionRecords.size() << "\n";
    if (flagRbcd)
        std::cout << "  RBCD edges              : " << rbcdEdgesAttached << "\n";
    if (flagMemberOf)
        std::cout << "  MemberOf edges          : " << memberOfEdgesAttached << "\n";
    std::cout << "----------------------------------------------\n";

    return 0;
}

static bool getIntAttr(const std::vector<std::pair<std::string, JsonVal>>& attrs,
                       const std::string& key,
                       long& out)
{
    for (const auto& p : attrs) {
        if (p.first == key) {
            if (p.second.isNum()) { out = static_cast<long>(p.second.n); return true; }
            if (p.second.isStr()) {
                try { out = std::stol(p.second.s); return true; } catch (...) { return false; }
            }
            return false;
        }
    }
    return false;
}

static size_t attachMemberOfEdges(
        const std::map<long, PrivGroup>& privByToken,
        const std::map<std::string, std::pair<std::string, std::string>>& nodeIndex,
        const JsonArr& usersArr,
        const SidLookup& userLut,
        const JsonArr& computersArr,
        const SidLookup& computerLut,
        const JsonArr& groupsArr,
        const SidLookup& groupLut,
        std::vector<AceRecord>& outGroupRecords)
{
    size_t attached = 0;

    /* Map token -> index within outGroupRecords */
    std::map<long, size_t> tokenIdx;

    for (const auto& nodePair : nodeIndex) {
        const std::string nodeSid  = nodePair.first;
        const std::string nodeName = nodePair.second.first;
        const std::string nodeType = nodePair.second.second;

        /* Enrich attributes for this node */
        auto attrs = lookupAttrs(nodeSid, nodeType,
                                 usersArr, userLut,
                                 computersArr, computerLut,
                                 groupsArr, groupLut);

        long primaryGroupId = -1;
        if (!getIntAttr(attrs, "primary_group_id", primaryGroupId))
            continue;

        auto it = privByToken.find(primaryGroupId);
        if (it == privByToken.end()) continue;

        const PrivGroup& pg = it->second;

        size_t recIndex;
        if (tokenIdx.count(pg.primaryToken)) {
            recIndex = tokenIdx[pg.primaryToken];
        } else {
            AceRecord gr;
            gr.target_name    = pg.name.empty() ? pg.sid : pg.name;
            gr.target_sid     = pg.sid;
            gr.target_dn      = pg.dn;
            gr.target_type    = "Group";
            gr.principal_sid  = pg.sid;
            gr.principal_name = pg.name.empty() ? pg.sid : pg.name;
            gr.object_acetype = "";
            gr.ace_qualifier  = "Allow";
            gr.rights         = {"MemberOf"};
            gr.rights_display = "MemberOf";
            gr.edge_rights    = {"MemberOf"};
            gr.source_file    = "memberof";
            /* enrich group attributes */
            gr.target_attributes = lookupAttrs(pg.sid, "Group",
                                               usersArr, userLut,
                                               computersArr, computerLut,
                                               groupsArr, groupLut);

            outGroupRecords.push_back(std::move(gr));
            recIndex = outGroupRecords.size() - 1;
            tokenIdx[pg.primaryToken] = recIndex;
        }

        AceStep ms;
        ms.target_name    = nodeName.empty() ? nodeSid : nodeName;
        ms.target_sid     = nodeSid;
        ms.target_type    = nodeType;
        ms.principal_sid  = pg.sid;
        ms.principal_name = pg.name.empty() ? pg.sid : pg.name;
        ms.object_acetype = "";
        ms.ace_qualifier  = "Allow";
        ms.rights         = {"MemberOf"};
        ms.rights_display = "MemberOf";
        ms.edge_rights    = {"MemberOf"};
        ms.source_file    = "memberof";
        ms.target_attributes = attrs; /* include node attributes on the edge */

        outGroupRecords[recIndex].next_step.push_back(std::move(ms));
        ++attached;
    }

    return attached;
}

static size_t attachMemberOfEdges(
    const std::map<long, PrivGroup>& privByToken,
    const std::map<std::string, std::pair<std::string, std::string>>& nodeIndex,
    const JsonArr& usersArr,
    const SidLookup& userLut,
    const JsonArr& computersArr,
    const SidLookup& computerLut,
    const JsonArr& groupsArr,
    const SidLookup& groupLut,
    std::vector<AceRecord>& outGroupRecords);