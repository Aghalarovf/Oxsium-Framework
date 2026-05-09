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
    std::vector<std::pair<std::string, JsonVal>> target_attributes; /* enriched from domain JSON */
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
    "key_credential_link", "has_key_credential_link"
};

static const std::vector<std::string> COMPUTER_ATTRS = {
    "disabled", "unconstrained_delegation", "rbcd_enabled", "rbcd_principals",
    "haslaps", "laps_attributes", "is_domain_controller", "domainsid"
};

static const std::vector<std::string> GROUP_ATTRS = {
    "group_sid", "group_type", "is_nested", "domainsid",
    "is_protected", "primary_group_token"
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

static std::vector<AceRecord> extractHop1EntriesByAttribute(
        const std::string&      usersFilePath,
        const std::string&      dangerousFilePath,
        const std::string&      extendedFilePath,
        const std::string&      attrName,
        const std::string&      attrValue)
{
    std::vector<AceRecord> records;
    
    std::cout << "[*] Loading users from: " << usersFilePath << "\n";
    JsonVal usersRoot = loadAcls(usersFilePath);
    if (!usersRoot.isObj()) {
        std::cerr << "[WARN] Invalid users JSON\n";
        return records;
    }
    
    const JsonArr& usersArr = (usersRoot.find("users") && usersRoot.find("users")->isArr()) 
                              ? usersRoot.find("users")->arr 
                              : JsonArr();
    
    std::cout << "    Loaded " << usersArr.size() << " user(s)\n";
    
    JsonVal dangerousRoot = loadAcls(dangerousFilePath);
    JsonVal extendedRoot  = loadAcls(extendedFilePath);
    
    std::cout << "[*] Filtering users where " << attrName << " = " << attrValue << "\n";
    
    size_t matchCount = 0;
    for (const JsonVal& userEntry : usersArr) {
        if (!userEntry.isObj()) continue;
        
        const JsonVal* attrVal = userEntry.find(attrName);
        if (!attrVal) continue;
        if (!valueMatches(*attrVal, attrValue)) continue;
        
        std::string username = getStr(userEntry, "username");
        std::string sid      = getStr(userEntry, "sid");
        std::string dn       = getStr(userEntry, "dn");
        
        if (username.empty() || sid.empty()) continue;
        
        matchCount++;
        std::cout << "    [Match " << matchCount << "] " << username << " (" << sid << ")\n";
        
        AceRecord entryPoint;
        entryPoint.target_name    = username;
        entryPoint.target_sid     = sid;
        entryPoint.target_dn      = dn;
        entryPoint.target_type    = "user";
        entryPoint.principal_sid  = sid;  
        entryPoint.principal_name = username;
        entryPoint.object_acetype = "vulnerable-entry-point";
        entryPoint.ace_qualifier  = "Allow";
        entryPoint.rights         = {attrName};  
        entryPoint.rights_display = attrName;
        entryPoint.edge_rights    = {attrName};
        entryPoint.source_file    = "vulnerable entry point (" + attrName + "=" + attrValue + ")";
        
        auto dangerous = extractMatching(dangerousRoot, sid, username, "dangerous_ace");
        auto extended  = extractMatching(extendedRoot,  sid, username, "extended_rights");
        
        dangerous.insert(dangerous.end(), extended.begin(), extended.end());
        auto merged = mergeAceRecords(std::move(dangerous));
        
        if (merged.empty()) {
            std::cout << "      -> No outgoing edges (pure entry point)\n";
            records.push_back(entryPoint);
        } else {
            std::cout << "      -> " << merged.size() << " outgoing edge(s)\n";
            records.insert(records.end(), merged.begin(), merged.end());
        }
    }
    
    std::cout << "    Total matching users: " << matchCount << "\n";
    std::cout << "    Total entry point records created: " << records.size() << "\n";
    
    return records;
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

static void writeStep(std::ofstream& f, const AceStep& s, const std::string& ind) {
    f << ind << "{\n";
    f << ind << "  \"target_name\"    : \"" << jsonEsc(s.target_name)    << "\",\n";
    f << ind << "  \"target_sid\"     : \"" << jsonEsc(s.target_sid)     << "\",\n";
    f << ind << "  \"target_dn\"      : \"" << jsonEsc(s.target_dn)      << "\",\n";
    f << ind << "  \"target_type\"    : \"" << jsonEsc(s.target_type)    << "\",\n";
    f << ind << "  \"principal_sid\"  : \"" << jsonEsc(s.principal_sid)  << "\",\n";
    f << ind << "  \"principal_name\" : \"" << jsonEsc(s.principal_name) << "\",\n";
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

static void writeGraphObjects(
        const std::string&                 outPath,
        const std::string&                 sid,
        const std::string&                 name,
        const std::vector<AceRecord>&      records,
        const std::vector<AceRecord>&      vulnerableRecords = {},
        const std::vector<VulnerableUser>& vuUsers           = {})
{
    std::ofstream f(outPath, std::ios::out | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot write to file: " + outPath);

    size_t totalRecords = records.size() + vulnerableRecords.size();

    std::map<std::string, const VulnerableUser*> vuMap;
    for (const VulnerableUser& vu : vuUsers)
        if (!vu.sid.empty())
            vuMap[vu.sid] = &vu;

    f << "{\n";
    f << "  \"principal_sid\"  : \"" << jsonEsc(sid)   << "\",\n";
    f << "  \"principal_name\" : \"" << jsonEsc(name)  << "\",\n";
    f << "  \"total\"          : "   << totalRecords << ",\n";

    /* ── Vulnerable users section ── */
    f << "  \"vulnerable_users\" : [\n";
    for (size_t i = 0; i < vuUsers.size(); ++i) {
        const VulnerableUser& vu = vuUsers[i];
        f << "    {\n";
        f << "      \"name\"             : \"" << jsonEsc(vu.name) << "\",\n";
        f << "      \"sid\"              : \"" << jsonEsc(vu.sid)  << "\",\n";
        f << "      \"dn\"               : \"" << jsonEsc(vu.dn)   << "\",\n";
        f << "      \"pwd_not_required\" : " << (vu.pwd_not_required ? "true" : "false") << ",\n";
        f << "      \"asrep\"            : " << (vu.asrep            ? "true" : "false") << ",\n";
        f << "      \"kerberoastable\"   : " << (vu.kerberoastable   ? "true" : "false") << "\n";
        f << "    }";
        if (i + 1 < vuUsers.size()) f << ",";
        f << "\n";
    }
    f << "  ],\n";

    f << "  \"graph_objects\"  : [\n";

    size_t idx = 0;

    for (size_t i = 0; i < records.size(); ++i, ++idx) {
        const AceRecord& r = records[i];
        f << "    {\n";
        f << "      \"target_name\"    : \"" << jsonEsc(r.target_name)    << "\",\n";
        f << "      \"target_sid\"     : \"" << jsonEsc(r.target_sid)     << "\",\n";
        f << "      \"target_dn\"      : \"" << jsonEsc(r.target_dn)      << "\",\n";
        f << "      \"target_type\"    : \"" << jsonEsc(r.target_type)    << "\",\n";
        f << "      \"principal_sid\"  : \"" << jsonEsc(r.principal_sid)  << "\",\n";
        f << "      \"principal_name\" : \"" << jsonEsc(r.principal_name) << "\",\n";
        f << "      \"object_acetype\" : \"" << jsonEsc(r.object_acetype) << "\",\n";
        f << "      \"ace_qualifier\"  : \"" << jsonEsc(r.ace_qualifier)  << "\",\n";
        f << "      \"rights\"         : "   << strArrToJson(r.rights)     << ",\n";
        f << "      \"rights_display\" : \"" << jsonEsc(r.rights_display) << "\",\n";
        f << "      \"edge_rights\"    : "   << strArrToJson(r.edge_rights) << ",\n";
        writeTargetAttributes(f, r.target_attributes, "      ");
        f << "      \"next_step\"      : [\n";
        for (size_t j = 0; j < r.next_step.size(); ++j) {
            writeStep(f, r.next_step[j], "        ");
            if (j + 1 < r.next_step.size()) f << ",";
            f << "\n";
        }
        f << "      ],\n";
        f << "      \"_source\"        : \"" << jsonEsc(r.source_file)    << "\"\n";
        f << "    }";
        if (idx + 1 < totalRecords) f << ",";
        f << "\n";
    }

    for (size_t i = 0; i < vulnerableRecords.size(); ++i, ++idx) {
        const AceRecord& r = vulnerableRecords[i];
        f << "    {\n";
        f << "      \"target_name\"    : \"" << jsonEsc(r.target_name)    << "\",\n";
        f << "      \"target_sid\"     : \"" << jsonEsc(r.target_sid)     << "\",\n";
        f << "      \"target_dn\"      : \"" << jsonEsc(r.target_dn)      << "\",\n";
        f << "      \"target_type\"    : \"" << jsonEsc(r.target_type)    << "\",\n";
        f << "      \"principal_sid\"  : \"" << jsonEsc(r.principal_sid)  << "\",\n";
        f << "      \"principal_name\" : \"" << jsonEsc(r.principal_name) << "\",\n";
        f << "      \"object_acetype\" : \"" << jsonEsc(r.object_acetype) << "\",\n";
        f << "      \"ace_qualifier\"  : \"" << jsonEsc(r.ace_qualifier)  << "\",\n";
        f << "      \"rights\"         : "   << strArrToJson(r.rights)     << ",\n";
        f << "      \"rights_display\" : \"" << jsonEsc(r.rights_display) << "\",\n";
        f << "      \"edge_rights\"    : "   << strArrToJson(r.edge_rights) << ",\n";
        {
            auto vuIt = vuMap.find(r.principal_sid);
            if (vuIt != vuMap.end()) {
                const VulnerableUser& vu = *vuIt->second;
                f << "      \"entry_point_flags\" : {\n";
                f << "        \"pwd_not_required\" : " << (vu.pwd_not_required ? "true" : "false") << ",\n";
                f << "        \"asrep\"            : " << (vu.asrep            ? "true" : "false") << ",\n";
                f << "        \"kerberoastable\"   : " << (vu.kerberoastable   ? "true" : "false") << "\n";
                f << "      },\n";
            }
        }
        writeTargetAttributes(f, r.target_attributes, "      ");
        f << "      \"next_step\"      : [\n";
        for (size_t j = 0; j < r.next_step.size(); ++j) {
            writeStep(f, r.next_step[j], "        ");
            if (j + 1 < r.next_step.size()) f << ",";
            f << "\n";
        }
        f << "      ],\n";
        f << "      \"_source\"        : \"" << jsonEsc(r.source_file) << " (vulnerable entry point)\"\n";
        f << "    }";
        if (idx + 1 < totalRecords) f << ",";
        f << "\n";
    }

    f << "  ]\n";
    f << "}\n";
    f.flush();
    if (!f) throw std::runtime_error("Write error on file: " + outPath);
}


int main(int argc, char* argv[]) {

    const std::filesystem::path exePath   = std::filesystem::absolute(argv[0]);
    const std::filesystem::path engineDir = exePath.parent_path();

    std::filesystem::path oxsiumRoot;

    {
        std::filesystem::path p = engineDir;
        while (!p.empty() && p != p.parent_path()) {
            if (p.filename().string() == "Oxsium-Framework") {
                oxsiumRoot = p;
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
        std::cerr << "[WARN] Could not locate Oxsium-Framework root automatically.\n"
                  << "       Falling back to exe directory: " << oxsiumRoot << "\n"
                  << "       Use --dangerous / --extended / --users / --computers / --groups\n"
                  << "       to specify file paths explicitly.\n";
    }

    std::cout << "[*] Oxsium-Framework root : " << oxsiumRoot.string() << "\n";

    /* Keep repoRoot as an alias for backward compatibility */
    const std::filesystem::path& repoRoot = oxsiumRoot;

    /* Argument Parsing */
    std::string sid           = "";
    std::string name          = "";
    std::string dangerousFile = (repoRoot / "Domain Object" / "domain_dangerous_ace.json").string();
    std::string extendedFile  = (repoRoot / "Domain Object" / "domain_extended_rights.json").string();
    std::string usersFile     = (repoRoot / "Domain Object" / "domain_users.json").string();
    std::string computersFile = (repoRoot / "Domain Object" / "domain_computers.json").string();
    std::string groupsFile    = (repoRoot / "Domain Object" / "domain_groups.json").string();
    std::string outFile       = (engineDir   / "graph_objects.json").string();
    int         maxDepth      = 50;
    
    struct Hop1Filter {
        std::string file;
        std::string attr;
        std::string value;
    };
    std::vector<Hop1Filter> hop1Filters;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if      ((arg == "-r" || arg == "--root") && i + 1 < argc) sid           = argv[++i];
        else if ((arg == "-n" || arg == "--name") && i + 1 < argc) name          = argv[++i];
        else if  (arg == "--dangerous"            && i + 1 < argc) dangerousFile = argv[++i];
        else if  (arg == "--extended"             && i + 1 < argc) extendedFile  = argv[++i];
        else if  (arg == "--users"                && i + 1 < argc) usersFile     = argv[++i];
        else if  (arg == "--computers"            && i + 1 < argc) computersFile = argv[++i];
        else if  (arg == "--groups"               && i + 1 < argc) groupsFile    = argv[++i];
        else if  (arg == "--out"                  && i + 1 < argc) outFile       = argv[++i];
        else if  (arg == "--hop1-filter"          && i + 3 < argc) {
            Hop1Filter f;
            f.file  = argv[++i];
            f.attr  = argv[++i];
            f.value = argv[++i];
            hop1Filters.push_back(f);
        }
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
            << "  --dangerous <file>   Path to domain_dangerous_ace.json\n"
            << "                       (default: " << dangerousFile << ")\n"
            << "  --extended  <file>   Path to domain_extended_rights.json\n"
            << "                       (default: " << extendedFile  << ")\n"
            << "  --users     <file>   Path to domain_users.json\n"
            << "                       (default: " << usersFile     << ")\n"
            << "  --computers <file>   Path to domain_computers.json\n"
            << "                       (default: " << computersFile << ")\n"
            << "  --groups    <file>   Path to domain_groups.json\n"
            << "                       (default: " << groupsFile    << ")\n"
            << "  --out       <file>   Output destination file\n"
            << "                       (default: " << outFile << ")\n"
            << "  --hop1-filter <file> <attr> <value>\n"
            << "                       Add Hop-1 entry point filter\n"
            << "                       Example: --hop1-filter domain_users.json kerberoastable true\n"
            << "                       Can be used multiple times for multiple filters\n"
            << "  --max-depth <int>    Maximum hop depth for next_step resolution\n"
            << "                       (default: 50, min: 1)\n\n"
            << "Examples:\n"
            << "  graph_engine -r S-1-5-21-767238238-2156610861-601915929-527 -n JohnDoe\n"
            << "  graph_engine -r S-1-5-21-... -n JohnDoe --hop1-filter domain_users.json kerberoastable true\n"
            << "  graph_engine -r S-1-5-21-... -n JohnDoe \\\n"
            << "    --hop1-filter domain_users.json kerberoastable true \\\n"
            << "    --hop1-filter domain_users.json asrep true \\\n"
            << "    --hop1-filter domain_users.json pwd_not_required true\n";
        return 1;
    }

    std::cout << "------------------------------------------------\n";
    std::cout << "|       ACE Graph Engine - Oxsium Framework   |\n";
    std::cout << "------------------------------------------------\n";
    std::cout << "  Root SID   : " << sid           << "\n";
    std::cout << "  Root Name  : " << name          << "\n";
    std::cout << "  Dangerous  : " << dangerousFile  << "\n";
    std::cout << "  Extended   : " << extendedFile   << "\n";
    std::cout << "  Output     : " << outFile        << "\n";
    std::cout << "  Max Depth  : " << maxDepth       << " hop(s)\n\n";

    /* Load ACE files once — reused for both Level-1 and Level-2 */
    std::cout << "[*] Loading ACE source files...\n";
    JsonVal dangerousRoot = loadAcls(dangerousFile);
    JsonVal extendedRoot  = loadAcls(extendedFile);

    /* Load domain object files for target attribute enrichment */
    std::cout << "[*] Loading domain object files for enrichment...\n";
    JsonVal usersRoot     = loadAcls(usersFile);
    JsonVal computersRoot = loadAcls(computersFile);
    JsonVal groupsRoot    = loadAcls(groupsFile);

    /* Build SID lookup tables */
    static const JsonArr emptyArr;
    const JsonArr& usersArr     = (usersRoot.isObj()     && usersRoot.find("users")     && usersRoot.find("users")->isArr())     ? usersRoot.find("users")->arr     : emptyArr;
    const JsonArr& computersArr = (computersRoot.isObj() && computersRoot.find("computers") && computersRoot.find("computers")->isArr()) ? computersRoot.find("computers")->arr : emptyArr;
    const JsonArr& groupsArr    = (groupsRoot.isObj()    && groupsRoot.find("groups")   && groupsRoot.find("groups")->isArr())   ? groupsRoot.find("groups")->arr   : emptyArr;

    SidLookup userLut     = buildSidLookup(usersArr);
    SidLookup computerLut = buildSidLookup(computersArr);
    SidLookup groupLut    = buildSidLookup(groupsArr);

    std::cout << "    users     : " << usersArr.size()     << " object(s), "
              << userLut.size()     << " indexed\n";
    std::cout << "    computers : " << computersArr.size() << " object(s), "
              << computerLut.size() << " indexed\n";
    std::cout << "    groups    : " << groupsArr.size()    << " object(s), "
              << groupLut.size()    << " indexed\n";

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

    /* ══ Process Hop-1 Entry Point Filters ══ */
    std::cout << "\n[*] Processing Hop-1 entry point filters...\n";
    std::vector<AceRecord> hop1Records;
    
    if (hop1Filters.empty()) {
        std::cout << "    No --hop1-filter arguments provided.\n";
    } else {
        for (size_t fidx = 0; fidx < hop1Filters.size(); ++fidx) {
            const auto& f = hop1Filters[fidx];
            std::cout << "\n  [Filter " << (fidx + 1) << "] " << f.attr << " = " << f.value << "\n";
            
            auto filtered = extractHop1EntriesByAttribute(f.file, dangerousFile, extendedFile, f.attr, f.value);
            std::cout << "    Extracted " << filtered.size() << " ACE record(s)\n";
            
            hop1Records.insert(hop1Records.end(), filtered.begin(), filtered.end());
        }
        
        if (!hop1Records.empty()) {
            std::cout << "[*] Resolving chains for Hop-1 entry point records...\n";

            size_t hop1Steps = 0;
            ChainCache hop1Cache;

            for (AceRecord& rec : hop1Records) {
                if (rec.target_sid.empty()) continue;

                std::cout << "    [HOP1] " << rec.principal_name << " -> "
                          << rec.target_name << " (" << rec.target_sid << ")\n";

                auto cacheHit = hop1Cache.find(rec.target_sid);
                if (cacheHit != hop1Cache.end()) {
                    rec.next_step = cacheHit->second;
                    std::cout << "      [cache hit] — " << countSteps(rec.next_step) << " edge(s)\n";
                    hop1Steps += countSteps(rec.next_step);
                    continue;
                }

                std::set<std::string> visited;
                visited.insert(rec.principal_sid);
                visited.insert(rec.target_sid);

                auto steps_d = extractSteps(dangerousRoot, rec.target_sid,
                                            rec.target_name, "dangerous_ace");
                auto steps_e = extractSteps(extendedRoot,  rec.target_sid,
                                            rec.target_name, "extended_rights");

                steps_d.insert(steps_d.end(), steps_e.begin(), steps_e.end());
                rec.next_step = mergeAceSteps(std::move(steps_d));

                if (!rec.next_step.empty()) {
                    std::cout << "      [depth 0] " << rec.next_step.size() << " edge(s) — expanding...\n";
                }

                for (AceStep& step : rec.next_step)
                    resolveChain(step, dangerousRoot, extendedRoot, visited, hop1Cache);

                hop1Cache[rec.target_sid] = rec.next_step;

                size_t recTotal = countSteps(rec.next_step);
                hop1Steps += recTotal;
                if (recTotal > 0)
                    std::cout << "      -> " << recTotal << " total edge(s)\n";
            }

            /* Enrich hop1 records with domain attributes */
            for (AceRecord& rec : hop1Records) {
                rec.target_attributes = lookupAttrs(rec.target_sid, rec.target_type,
                                                   usersArr, userLut,
                                                   computersArr, computerLut,
                                                   groupsArr, groupLut);
                for (AceStep& s : rec.next_step)
                    enrichStepAttributes(s, usersArr, userLut, computersArr, computerLut, groupsArr, groupLut);
            }

            std::cout << "    Hop-1 chains resolved: " << hop1Steps << " total edge(s)\n";
        }
    }

    /* Write Output */
    std::cout << "\n[*] Writing " << all.size() << " L1 record(s) + "
              << totalSteps << " recursive edge(s) + "
              << hop1Records.size() << " Hop-1 entry point record(s) to " << outFile << "...\n";
    try {
        writeGraphObjects(outFile, sid, name, all, hop1Records);
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
    std::cout << "  Hop-1 Entry Points      : " << hop1Records.size() << "\n";
    std::cout << "  next_step edges (total) : " << totalSteps       << "\n";
    std::cout << "    (fully recursive — all depths)\n";
    std::cout << "----------------------------------------------\n";

    return 0;
}