// ─── offline_processorp4.cpp ─────────────────────────────────────────────────
// SECTION 15  Well-known SID + GUID tables
// SECTION 16  mask_to_rights / find_danger_reason
// SECTION 17  trustee resolve / type / admin flag
// SECTION 18  parse_aces_block
// SECTION 19  enrich_ace / enrich_ace_object
// SECTION 20  ace_entry_to_json / ace_object_to_json
// SECTION 21  load_and_process_aces
// SECTION 22  process_aces (public entry) + process() update
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <ctime>

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 15 — Well-known SID + GUID tables
// ═════════════════════════════════════════════════════════════════════════════

const std::string& OfflineProcessor::well_known_sid_name(const std::string& sid) {
    static const std::pair<const char*, const char*> TABLE[] = {
        // Universal
        { "S-1-0-0",   "Null Authority"             },
        { "S-1-1-0",   "Everyone"                   },
        { "S-1-2-0",   "Local"                      },
        { "S-1-2-1",   "Console Logon"              },
        { "S-1-3-0",   "Creator Owner"              },
        { "S-1-3-1",   "Creator Group"              },
        { "S-1-3-2",   "Creator Owner Server"       },
        { "S-1-3-3",   "Creator Group Server"       },
        { "S-1-3-4",   "Owner Rights"               },
        { "S-1-4",     "Non-unique Authority"        },
        { "S-1-5",     "NT Authority"               },
        // NT Authority
        { "S-1-5-1",   "Dialup"                     },
        { "S-1-5-2",   "Network"                    },
        { "S-1-5-3",   "Batch"                      },
        { "S-1-5-4",   "Interactive"                },
        { "S-1-5-6",   "Service"                    },
        { "S-1-5-7",   "Anonymous"                  },
        { "S-1-5-8",   "Proxy"                      },
        { "S-1-5-9",   "Enterprise Domain Controllers" },
        { "S-1-5-10",  "Self"                       },
        { "S-1-5-11",  "Authenticated Users"        },
        { "S-1-5-12",  "Restricted Code"            },
        { "S-1-5-13",  "Terminal Server User"       },
        { "S-1-5-14",  "Remote Interactive Logon"   },
        { "S-1-5-15",  "This Organization"          },
        { "S-1-5-17",  "IUSR"                       },
        { "S-1-5-18",  "Local System"               },
        { "S-1-5-19",  "NT Authority Local Service" },
        { "S-1-5-20",  "NT Authority Network Service" },
        { "S-1-5-80",  "NT Service"                 },
        { "S-1-5-80-0","All Services"               },
        { "S-1-5-83-0","NT Virtual Machine\\Virtual Machines" },
        // Builtin aliases (RID only – endswith check below)
        { "S-1-5-32-544", "BUILTIN\\Administrators"       },
        { "S-1-5-32-545", "BUILTIN\\Users"                },
        { "S-1-5-32-546", "BUILTIN\\Guests"               },
        { "S-1-5-32-547", "BUILTIN\\Power Users"          },
        { "S-1-5-32-548", "BUILTIN\\Account Operators"    },
        { "S-1-5-32-549", "BUILTIN\\Server Operators"     },
        { "S-1-5-32-550", "BUILTIN\\Print Operators"      },
        { "S-1-5-32-551", "BUILTIN\\Backup Operators"     },
        { "S-1-5-32-552", "BUILTIN\\Replicators"          },
        { "S-1-5-32-554", "BUILTIN\\Pre-Windows 2000 Compatible Access" },
        { "S-1-5-32-555", "BUILTIN\\Remote Desktop Users" },
        { "S-1-5-32-556", "BUILTIN\\Network Configuration Operators" },
        { "S-1-5-32-557", "BUILTIN\\Incoming Forest Trust Builders" },
        { "S-1-5-32-558", "BUILTIN\\Performance Monitor Users" },
        { "S-1-5-32-559", "BUILTIN\\Performance Log Users"    },
        { "S-1-5-32-560", "BUILTIN\\Windows Authorization Access Group" },
        { "S-1-5-32-561", "BUILTIN\\Terminal Server License Servers" },
        { "S-1-5-32-562", "BUILTIN\\Distributed COM Users"   },
        { "S-1-5-32-568", "BUILTIN\\IIS_IUSRS"              },
        { "S-1-5-32-569", "BUILTIN\\Cryptographic Operators" },
        { "S-1-5-32-573", "BUILTIN\\Event Log Readers"       },
        { "S-1-5-32-574", "BUILTIN\\Certificate Service DCOM Access" },
        { "S-1-5-32-575", "BUILTIN\\RDS Remote Access Servers" },
        { "S-1-5-32-576", "BUILTIN\\RDS Endpoint Servers"   },
        { "S-1-5-32-577", "BUILTIN\\RDS Management Servers" },
        { "S-1-5-32-578", "BUILTIN\\Hyper-V Administrators" },
        { "S-1-5-32-579", "BUILTIN\\Access Control Assistance Operators" },
        { "S-1-5-32-580", "BUILTIN\\Remote Management Users" },
        { nullptr, nullptr }
    };

    static const std::string EMPTY;
    std::string u = upper(sid);
    for (int i = 0; TABLE[i].first; ++i) {
        if (u == upper(std::string(TABLE[i].first))) {
            static std::string cache;
            cache = TABLE[i].second;
            return cache;
        }
    }
    return EMPTY;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Well-known AD Object Type GUIDs
//  Source: MS-ADTS §5.1.3, BloodHound, common ACE research
// ─────────────────────────────────────────────────────────────────────────────
const std::string& OfflineProcessor::guid_to_name(const std::string& guid) {
    static const std::pair<const char*, const char*> TABLE[] = {
        // Extended Rights
        { "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes"          },
        { "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Synchronize"          },
        { "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Manage-Topology"      },
        { "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes-All"      },
        { "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes-In-Filtered-Set" },
        { "89e95b76-444d-4c62-991a-0facbeda640c", "DS-Replication-Get-Changes-All (RODC)" },
        { "00299570-246d-11d0-a768-00aa006e0529", "User-Force-Change-Password"           },
        { "ab721a54-1e2f-11d0-9819-00aa0040529b", "Send-As"                             },
        { "ab721a56-1e2f-11d0-9819-00aa0040529b", "Receive-As"                          },
        { "ab721a52-1e2f-11d0-9819-00aa0040529b", "Generic-Read"                        },
        { "ab721a53-1e2f-11d0-9819-00aa0040529b", "Generic-Write"                       },
        { "ab721a55-1e2f-11d0-9819-00aa0040529b", "Generic-Execute"                     },
        { "9923a32a-3607-11d2-b9be-0000f87a36b2", "DS-Install-Replica"                  },
        { "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc", "Run-Protect-Admin-Groups-Task"       },
        { "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd", "Recalculate-Hierarchy"               },
        { "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd", "Allocate-Rids"                       },
        { "be2bb760-7f46-11d2-b9ad-00c04f79f805", "Change-Schema-Master"                },
        { "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd", "Change-Rid-Master"                   },
        { "fec364e0-0a98-11d1-adbb-00c04fd8d5cd", "Do-Garbage-Collection"               },
        { "ab721a51-1e2f-11d0-9819-00aa0040529b", "User-Change-Password"                },
        { "68b1d179-0d15-4d4f-ab71-46152e79a7bc", "Allowed-To-Authenticate"             },
        { "2f16c4a5-b98e-432c-952a-cb388ba33f2e", "DS-Execute-Intentions-Script"        },
        { "9b026da6-0d3c-465c-8bee-5199d7165cba", "DS-Validated-Write-Computer"         },
        { "f3a64788-5306-11d1-a9c5-0000f80367c1", "Validated-SPN"                       },
        { "72e39547-7b18-11d1-adef-00c04fd8d5cd", "Validated-DNS-Host-Name"             },
        { "80863791-dbe9-4eb8-837e-7f0ab55d9ac7", "Validated-MS-DS-Behavior-Version"    },
        { "d31a8757-2447-4545-8081-3bb610cacbf2", "Validated-MS-DS-Additional-DNS-Host-Name" },
        { "e2a36dc9-ae17-47c3-b58b-be34c55ba633", "Create-Inbound-Forest-Trust"         },
        { "280f369c-67c7-438e-ae98-1d46f3c6f541", "MS-TS-GatewayAccess"                 },
        { "5805bc62-bdc9-4428-a5e2-856a0f4c185e", "Terminal-Server-License-Server"      },
        { "a1990816-4298-11d1-ade2-00c04fd8d5cd", "Open-Address-Book"                   },
        { "77b5b886-944a-11d1-aebd-0000f80367c1", "Personal-Information"                },
        { "e45795b2-9455-11d1-aebd-0000f80367c1", "Email-Information"                   },
        { "e45795b3-9455-11d1-aebd-0000f80367c1", "Web-Information"                     },
        { "59ba2f42-79a2-11d0-9020-00c04fc2d3cf", "General-Information"                 },
        { "bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "Membership"                          },
        { "037088f8-0ae1-11d2-b422-00a0c968f939", "RAS-Information"                     },
        { "b8119fd0-04f6-4762-ab7a-4986c76b3f9a", "Other-Domain-Parameters"             },
        { "6db69a1c-9422-11d1-aebd-0000f80367c1", "Logon-Information"                   },
        { "5f202010-79a5-11d0-9020-00c04fc2d4cf", "Account-Restrictions"                },
        { "4c164200-20c0-11d0-a768-00aa006e0529", "User-Account-Restrictions"           },
        { "5b47d60f-6090-40b2-9f37-2a4de88f3063", "msDS-KeyCredentialLink (Shadow Cred)" },
        // Validated Writes (object classes)
        { "bf9679c0-0de6-11d0-a285-00aa003049e2", "member (group member write)"         },
        { "bf9679a8-0de6-11d0-a285-00aa003049e2", "servicePrincipalName"                },
        // Schema GUIDs (object classes)
        { "bf967aba-0de6-11d0-a285-00aa003049e2", "user"                                },
        { "bf967a9c-0de6-11d0-a285-00aa003049e2", "group"                               },
        { "bf967a86-0de6-11d0-a285-00aa003049e2", "computer"                            },
        { "bf967aa5-0de6-11d0-a285-00aa003049e2", "organizationalUnit"                  },
        { "f30e3bc2-9ff0-11d1-b603-0000f80367c1", "groupPolicyContainer"                },
        { "19195a5b-6da0-11d0-afd3-00c04fd930c9", "organizationalUnit"                  },
        { nullptr, nullptr }
    };

    static const std::string EMPTY;
    if (guid.empty()) return EMPTY;
    std::string l = lower(guid);
    for (int i = 0; TABLE[i].first; ++i) {
        if (l == TABLE[i].first) {
            static std::string cache;
            cache = TABLE[i].second;
            return cache;
        }
    }
    return EMPTY;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 16 — mask_to_rights / find_danger_reason
// ═════════════════════════════════════════════════════════════════════════════

std::vector<std::string> OfflineProcessor::mask_to_rights(unsigned int mask,
                                                           const std::string& ot_guid)
{
    std::vector<std::string> r;

    // Full control shortcuts
    if ((mask & OfflineAceRight::ACE_GENERIC_ALL) == OfflineAceRight::ACE_GENERIC_ALL) {
        r.push_back("GenericAll");
        return r;
    }
    if (mask & OfflineAceRight::ACE_GA_BIT) {
        r.push_back("GA (Generic All bit)");
        return r;
    }

    // Individual rights
    if (mask & OfflineAceRight::ACE_WRITE_DACL)    r.push_back("WriteDACL");
    if (mask & OfflineAceRight::ACE_WRITE_OWNER)   r.push_back("WriteOwner");
    if (mask & OfflineAceRight::ACE_GENERIC_WRITE)  r.push_back("GenericWrite");
    if (mask & OfflineAceRight::ACE_DELETE)         r.push_back("Delete");
    if (mask & OfflineAceRight::ACE_READ_CONTROL)   r.push_back("ReadControl");
    if (mask & OfflineAceRight::ACE_CREATE_CHILD)   r.push_back("CreateChild");
    if (mask & OfflineAceRight::ACE_DELETE_CHILD)   r.push_back("DeleteChild");
    if (mask & OfflineAceRight::ACE_LIST_OBJECT)    r.push_back("ListObject");

    if (mask & OfflineAceRight::ACE_ALL_EXTENDED) {
        if (ot_guid.empty()) {
            r.push_back("AllExtendedRights");
        } else {
            const std::string& gname = guid_to_name(ot_guid);
            r.push_back("ExtendedRight:" + (gname.empty() ? ot_guid : gname));
        }
    } else if (mask & 0x00000100) {  // ACE_ALL_EXTENDED bit tek
        if (!ot_guid.empty()) {
            const std::string& gname = guid_to_name(ot_guid);
            r.push_back("ExtendedRight:" + (gname.empty() ? ot_guid : gname));
        }
    }

    if (mask & OfflineAceRight::ACE_DS_WRITE_PROP) {
        if (!ot_guid.empty()) {
            const std::string& gname = guid_to_name(ot_guid);
            r.push_back("WriteProperty:" + (gname.empty() ? ot_guid : gname));
        } else {
            r.push_back("WriteProperty");
        }
    }

    // Read bits (0x10, 0x20, 0x40, 0x80 — DS-specific)
    if ((mask & 0x00000010) && !(mask & OfflineAceRight::ACE_DS_WRITE_PROP))
        r.push_back("ReadProperty");
    if (mask & 0x00000008)  r.push_back("ListChildren");

    if (r.empty()) {
        char buf[12]; std::snprintf(buf, sizeof(buf), "0x%08X", mask);
        r.push_back(std::string("Mask:") + buf);
    }
    return r;
}

std::string OfflineProcessor::find_danger_reason(unsigned int mask,
                                                   const std::string& ot_guid,
                                                   bool is_allow)
{
    if (!is_allow) return "";
    if ((mask & OfflineAceRight::ACE_GENERIC_ALL) == OfflineAceRight::ACE_GENERIC_ALL)
        return "GenericAll — full control over the object";
    if (mask & OfflineAceRight::ACE_GA_BIT)
        return "GA bit — Generic All";
    if (mask & OfflineAceRight::ACE_WRITE_DACL)
        return "WriteDACL — can replace the object's ACL";
    if (mask & OfflineAceRight::ACE_WRITE_OWNER)
        return "WriteOwner — can take ownership";
    if (mask & OfflineAceRight::ACE_GENERIC_WRITE)
        return "GenericWrite — can write arbitrary properties";
    if (mask & OfflineAceRight::ACE_DS_WRITE_PROP) {
        const std::string& gname = guid_to_name(ot_guid);
        if (!gname.empty()) return "WriteProperty:" + gname;
        return "WriteProperty — can write specific attribute";
    }
    if ((mask & OfflineAceRight::ACE_ALL_EXTENDED) && ot_guid.empty())
        return "AllExtendedRights — includes DCSync, ForceChangePassword, etc.";
    if (mask & OfflineAceRight::ACE_ALL_EXTENDED) {
        // DCSync GUIDs
        static const char* DCSYNC[] = {
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
            "89e95b76-444d-4c62-991a-0facbeda640c",
            nullptr
        };
        std::string gl = lower(ot_guid);
        for (int i = 0; DCSYNC[i]; ++i)
            if (gl == DCSYNC[i]) return "DCSync right: " + guid_to_name(ot_guid);
        // ForceChangePassword
        if (gl == "00299570-246d-11d0-a768-00aa006e0529")
            return "User-Force-Change-Password — can reset password without old one";
        // Shadow Cred
        if (gl == "5b47d60f-6090-40b2-9f37-2a4de88f3063")
            return "msDS-KeyCredentialLink write — Shadow Credentials attack";
        const std::string& gname = guid_to_name(ot_guid);
        if (!gname.empty()) return "ExtendedRight:" + gname;
    }
    return "";
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 17 — trustee resolve / type / admin flag
// ═════════════════════════════════════════════════════════════════════════════

std::string OfflineProcessor::trustee_type_from_sid(const std::string& sid) const {
    // Well-known SIDs
    if (!well_known_sid_name(sid).empty()) return "well_known";

    // Lookup table
    auto it = sid_to_dn_.find(sid);
    if (it != sid_to_dn_.end()) {
        auto cit = dn_to_class_.find(upper(it->second));
        if (cit != dn_to_class_.end()) return lower(cit->second);
    }
    // S-1-5-21-...-RID heuristic
    if (sid.substr(0, 7) == "S-1-5-2") return "unknown";
    return "unknown";
}

std::pair<std::string,std::string>
OfflineProcessor::resolve_trustee(const std::string& sid) const {
    // 1. Well-known SID
    const std::string& wk = well_known_sid_name(sid);
    if (!wk.empty()) return { wk, "" };

    // 2. Lookup table
    auto it = sid_to_dn_.find(sid);
    if (it != sid_to_dn_.end()) {
        std::string udn = upper(it->second);
        std::string sam, display;
        auto sit = dn_to_sam_.find(udn);
        if (sit != dn_to_sam_.end()) sam = sit->second;
        auto dit = sid_to_display_.find(sid);
        if (dit != sid_to_display_.end()) display = dit->second;
        return { sam.empty() ? cn_from_dn(it->second) : sam, display };
    }

    // 3. Domain SID + RID heuristic derived from SID
    int r = rid_from_sid(sid);
    if (r == 502) return { "krbtgt", "" };
    if (r == 500) return { "Administrator", "" };
    if (r == 501) return { "Guest", "" };

    return { "", "" };
}

bool OfflineProcessor::trustee_is_admin(const std::string& trustee_sid) const {
    // Direct admin group SID
    if (admin_group_sids_.count(trustee_sid)) return true;
    // If trustee is a group, check transitive members
    auto it = group_transitive_sids_.find(trustee_sid);
    if (it != group_transitive_sids_.end()) {
        for (const auto& asid : admin_group_sids_)
            if (it->second.count(asid)) return true;
    }
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 18 — parse_aces_block
//  Extracts ACE list from a raw_aces.ndjson objects[] element.
//  Generic version of the inline parser used in load_raw_aces_lookup.
// ═════════════════════════════════════════════════════════════════════════════
std::vector<RawAceEntry> OfflineProcessor::parse_aces_block(const std::string& block) {
    std::vector<RawAceEntry> aces;

    const std::string aces_key = "\"aces\"";
    size_t ap = block.find(aces_key);
    if (ap == std::string::npos) return aces;
    size_t ab = block.find('[', ap + aces_key.size());
    if (ab == std::string::npos) return aces;

    size_t i = ab + 1;
    while (i < block.size()) {
        while (i < block.size() && std::isspace(static_cast<unsigned char>(block[i]))) ++i;
        if (i >= block.size() || block[i] == ']') break;
        if (block[i] != '{') { ++i; continue; }

        // Extract one ACE object
        int depth = 0; size_t start = i; bool in_s = false;
        while (i < block.size()) {
            char c = block[i];
            if (in_s) { if (c=='\\') ++i; else if (c=='"') in_s=false; }
            else { if (c=='"') in_s=true; else if (c=='{') ++depth;
                   else if (c=='}') { --depth; if (!depth){++i;break;} } }
            ++i;
        }
        std::string ace_obj = block.substr(start, i - start);

        RawAceEntry ace;
        ace.trustee_sid              = upper(jp_str(ace_obj, "trustee_sid"));
        std::string mask_str         = jp_str(ace_obj, "mask");
        try { ace.mask = static_cast<unsigned int>(
            std::stoul(mask_str, nullptr, 0)); } catch (...) {}
        ace.is_allow                 = jp_bool(ace_obj, "is_allow", true);
        ace.is_inherited             = jp_bool(ace_obj, "is_inherited", false);
        ace.object_type_guid         = lower(jp_str(ace_obj, "object_type_guid"));
        ace.inherited_object_type_guid = lower(jp_str(ace_obj, "inherited_object_type_guid"));

        if (!ace.trustee_sid.empty()) aces.push_back(std::move(ace));
    }
    return aces;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 19 — enrich_ace / enrich_ace_object
// ═════════════════════════════════════════════════════════════════════════════

ProcessedAce OfflineProcessor::enrich_ace(const RawAceEntry& raw) const {
    ProcessedAce a;

    // Raw fields
    a.trustee_sid              = raw.trustee_sid;
    a.mask                     = raw.mask;
    char hbuf[12]; std::snprintf(hbuf, sizeof(hbuf), "0x%08X", raw.mask);
    a.mask_hex                 = hbuf;
    a.is_allow                 = raw.is_allow;
    a.is_inherited             = raw.is_inherited;
    a.object_type_guid         = raw.object_type_guid;
    a.inherited_object_type_guid = raw.inherited_object_type_guid;

    // Trustee resolution
    auto [name, display] = resolve_trustee(raw.trustee_sid);
    a.trustee_name         = name;
    a.trustee_display_name = display;
    a.trustee_type         = trustee_type_from_sid(raw.trustee_sid);
    a.trustee_is_admin     = trustee_is_admin(raw.trustee_sid);

    // Rights labels
    a.rights_labels = mask_to_rights(raw.mask, raw.object_type_guid);

    // GUID names
    a.guid_name          = guid_to_name(raw.object_type_guid);
    a.inherited_guid_name= guid_to_name(raw.inherited_object_type_guid);

    // Danger detection
    a.danger_reason = find_danger_reason(raw.mask, raw.object_type_guid, raw.is_allow);
    a.is_dangerous  = !a.danger_reason.empty();

    return a;
}

ProcessedAceObject OfflineProcessor::enrich_ace_object(
    const std::string& dn,
    const std::string& object_class,
    const std::vector<RawAceEntry>& raw_aces) const
{
    ProcessedAceObject obj;
    obj.dn           = dn;
    obj.object_class = object_class;

    // DN → SAM lookup
    auto sit = dn_to_sam_.find(upper(dn));
    if (sit != dn_to_sam_.end()) obj.sam_name = sit->second;
    else obj.sam_name = cn_from_dn(dn);

    for (const auto& raw : raw_aces) {
        ProcessedAce a = enrich_ace(raw);
        if (a.is_allow)      ++obj.allow_ace_count;
        else                  ++obj.deny_ace_count;
        if (a.is_dangerous) {
            ++obj.dangerous_ace_count;
            obj.has_dangerous_aces = true;
        }
        obj.aces.push_back(std::move(a));
    }
    obj.total_ace_count = static_cast<int>(obj.aces.size());
    return obj;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 20 — JSON serialization for ACE objects
// ═════════════════════════════════════════════════════════════════════════════

std::string OfflineProcessor::ace_entry_to_json(const ProcessedAce& a) const {
    std::ostringstream o;
    o << "          {\n";
    o << "            \"trustee_sid\": "              << je(a.trustee_sid)              << ",\n";
    o << "            \"trustee_name\": "             << je(a.trustee_name)             << ",\n";
    o << "            \"trustee_display_name\": "     << je(a.trustee_display_name)     << ",\n";
    o << "            \"trustee_type\": "             << je(a.trustee_type)             << ",\n";
    o << "            \"trustee_is_admin\": "         << jb(a.trustee_is_admin)         << ",\n";
    o << "            \"mask\": "                     << je(a.mask_hex)                 << ",\n";
    o << "            \"is_allow\": "                 << jb(a.is_allow)                 << ",\n";
    o << "            \"is_inherited\": "             << jb(a.is_inherited)             << ",\n";
    o << "            \"object_type_guid\": "         << je(a.object_type_guid)         << ",\n";
    o << "            \"object_type_name\": "         << je(a.guid_name)                << ",\n";
    o << "            \"inherited_object_type_guid\": "<< je(a.inherited_object_type_guid) << ",\n";
    o << "            \"inherited_object_type_name\": "<< je(a.inherited_guid_name)     << ",\n";
    o << "            \"rights\": "                   << json_rights_arr(a.rights_labels)<< ",\n";
    o << "            \"is_dangerous\": "             << jb(a.is_dangerous)             << ",\n";
    o << "            \"danger_reason\": "            << je(a.danger_reason)            << "\n";
    o << "          }";
    return o.str();
}

std::string OfflineProcessor::ace_object_to_json(const ProcessedAceObject& obj) const {
    std::ostringstream o;
    o << "    {\n";
    o << "      \"dn\": "                  << je(obj.dn)           << ",\n";
    o << "      \"object_class\": "        << je(obj.object_class) << ",\n";
    o << "      \"sam_name\": "            << je(obj.sam_name)     << ",\n";
    o << "      \"total_ace_count\": "     << ji(obj.total_ace_count)     << ",\n";
    o << "      \"allow_ace_count\": "     << ji(obj.allow_ace_count)     << ",\n";
    o << "      \"deny_ace_count\": "      << ji(obj.deny_ace_count)      << ",\n";
    o << "      \"dangerous_ace_count\": " << ji(obj.dangerous_ace_count) << ",\n";
    o << "      \"has_dangerous_aces\": "  << jb(obj.has_dangerous_aces)  << ",\n";
    o << "      \"aces\": [\n";

    for (size_t i = 0; i < obj.aces.size(); ++i) {
        o << ace_entry_to_json(obj.aces[i]);
        if (i + 1 < obj.aces.size()) o << ",";
        o << "\n";
    }

    o << "      ]\n";
    o << "    }";
    return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 21 — load_and_process_aces  (NDJSON version)
//
//  raw_aces.ndjson format (AceCollector output):
//    Each line is one ACE — flat, not grouped by target object:
//    {"target_name":"...","target_dn":"...","target_sid":"...",
//     "target_type":"...","principal_sid":"...","ace_qualifier":"Allow",
//     "ace_type_raw":0,"object_ace_type":"","rights_display":"Full-Control",
//     "is_inherited":false,"ace_flags":0,"modified":"...","generated_at":"..."}
//
//  Processing: group by target_dn → create ProcessedAceObject → write JSON.
//  This collector does not keep raw mask; we derive RawAceEntry from rights_display.
// ═════════════════════════════════════════════════════════════════════════════
bool OfflineProcessor::load_and_process_aces(const std::string& raw_path,
                                              const std::string& out_path)
{
    log_info("[OfflineProcessor] reading raw_aces.ndjson: " + raw_path);

    auto lines = read_ndjson_lines(raw_path);
    if (lines.empty()) {
        log_err("[OfflineProcessor] raw_aces.ndjson not found or empty: " + raw_path);
        return false;
    }

    log_ok("[OfflineProcessor] " + std::to_string(lines.size()) +
           " ACE lines read. Grouping and enriching...");

    // ── Group ACEs by target_dn ───────────────────────────────────────────
    // Preserve order: insertion order
    std::vector<std::string> dn_order;
    std::unordered_map<std::string, std::vector<RawAceEntry>> dn_to_aces;
    std::unordered_map<std::string, std::string>              dn_to_type;

    for (const auto& line : lines) {
        std::string target_dn  = jp_str(line, "target_dn");
        std::string target_type= jp_str(line, "target_type");
        std::string psid       = upper(jp_str(line, "principal_sid"));
        if (target_dn.empty() || psid.empty()) continue;

        // rights_display → mask heuristic (primary collision-free values)
        const std::string& rd = jp_str(line, "rights_display");
        unsigned int mask = 0;
        if      (rd == "Full-Control")               mask = 0x001F01FF;
        else if (rd == "Write-DACL")                 mask = 0x00040000;
        else if (rd == "Write-Owner")                mask = 0x00080000;
        else if (rd == "Write-Property"  ||
                 rd == "Write-Account-Restrictions") mask = 0x00000020;
        // GenericAll: GA bit (0x10000000) — not ACE_GENERIC_ALL (0x000F01FF),
        // because when the collector writes "GenericAll" it refers to AD's GA extended bit.
        else if (rd == "GenericAll")                 mask = 0x10000000;
        // AllExtendedRights / ExtendedRight / Control-Access — all map to 0x00000100
        else if (rd == "AllExtendedRights"  ||
                 rd == "All-Extended-Rights"||
                 rd == "ExtendedRight"      ||
                 rd == "Control-Access")             mask = 0x00000100;
        else if (rd == "Read-Control")               mask = 0x00020000;
        else if (rd == "Delete")                     mask = 0x00010000;
        else if (rd == "Create-Child")               mask = 0x00000001;
        else if (rd == "Delete-Child")               mask = 0x00000002;
        // GenericRead: in AD equals ReadControl + ListChildren + ReadProperty + ListObject
        else if (rd == "GenericRead")                mask = 0x00020094;
        // GenericWrite: ACE_GENERIC_WRITE = 0x40000000 (Windows SACL bit)
        // When the collector writes this string it means WriteDACL+WriteProperty —
        // not the real mask 0x40000000. We use the ACE_GENERIC_WRITE bit.
        else if (rd == "GenericWrite")               mask = OfflineAceRight::ACE_GENERIC_WRITE;
        else {
            // "0x..." hex string — try
            if (rd.size() > 2 && rd[0] == '0' && (rd[1] == 'x' || rd[1] == 'X')) {
                try { mask = static_cast<unsigned int>(std::stoul(rd, nullptr, 16)); }
                catch (...) {}
            }
            // Combined values (space-separated)
            if (mask == 0) {
                if (rd.find("WriteDACL")    != std::string::npos) mask |= 0x00040000;
                if (rd.find("WriteOwner")   != std::string::npos) mask |= 0x00080000;
                if (rd.find("AllExtended")  != std::string::npos) mask |= 0x00000100;
                if (rd.find("GenericWrite") != std::string::npos) mask |= OfflineAceRight::ACE_GENERIC_WRITE;
            }
        }

        RawAceEntry ace;
        ace.trustee_sid = psid;
        ace.mask        = mask;
        std::string qualifier = jp_str(line, "ace_qualifier");
        ace.is_allow    = (qualifier != "Deny");
        ace.is_inherited= jp_bool(line, "is_inherited", false);

        // object_ace_type → object_type_guid
        std::string guid = jp_str(line, "object_ace_type");
        for (char& c : guid) c = static_cast<char>(
            std::tolower(static_cast<unsigned char>(c)));
        ace.object_type_guid = guid;

        if (dn_to_aces.find(target_dn) == dn_to_aces.end())
            dn_order.push_back(target_dn);
        dn_to_aces[target_dn].push_back(std::move(ace));
        if (!target_type.empty()) dn_to_type[target_dn] = target_type;
    }

    // ── Enrich and collect ───────────────────────────────────────────────────
    std::vector<ProcessedAceObject> all_objects;
    all_objects.reserve(dn_order.size());

    int total_aces     = 0;
    int dangerous_objs = 0;

    for (const auto& dn : dn_order) {
        auto& raw_aces = dn_to_aces[dn];
        std::string cls = dn_to_type.count(dn) ? dn_to_type.at(dn) : "";

        ProcessedAceObject obj = enrich_ace_object(dn, cls, raw_aces);
        total_aces += obj.total_ace_count;
        if (obj.has_dangerous_aces) ++dangerous_objs;
        all_objects.push_back(std::move(obj));
    }

        log_ok("[OfflineProcessor] " + std::to_string(total_aces) + " ACEs enriched, " +
            std::to_string(dangerous_objs) + " objects contain dangerous ACEs.");

    // ── Write to NDJSON (ZIP deferred — all output files compressed together downstream) ──
    return write_aces_parquet(all_objects, out_path);
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 22 — Public entry points  (process_aces + process updated)
// ═════════════════════════════════════════════════════════════════════════════

bool OfflineProcessor::process_aces(const OfflineProcessorOptions& opts) {
    fs::create_directories(opts.output_dir);

    // User + group lookups are needed for ACE enrichment
    load_raw_users_lookup (opts.raw_dir + "/raw_users.ndjson");
    load_raw_groups_lookup(opts.raw_dir + "/raw_groups.ndjson");
    if (!opts.domain_name.empty()) domain_name_ = opts.domain_name;
    if (domain_name_.empty()) domain_name_ = base_dn_to_domain(base_dn_);

    const std::string& ext4 = opts.output_ext.empty() ? "ndjson" : opts.output_ext;
    return load_and_process_aces(
        opts.raw_dir    + "/raw_aces.ndjson",
        opts.output_dir + "/domain_aces." + ext4);
}

bool OfflineProcessor::process_users(const OfflineProcessorOptions& opts) {
    fs::create_directories(opts.output_dir);
    if (!build_lookup_tables(opts.raw_dir)) return false;
    if (!opts.domain_name.empty()) domain_name_ = opts.domain_name;

    const std::string& ext4u = opts.output_ext.empty() ? "ndjson" : opts.output_ext;
    return load_and_process_users(
        opts.raw_dir    + "/raw_users.ndjson",
        opts.output_dir + "/domain_users." + ext4u);
}

bool OfflineProcessor::process_groups(const OfflineProcessorOptions& opts) {
    fs::create_directories(opts.output_dir);
    load_raw_groups_lookup(opts.raw_dir + "/raw_groups.ndjson");
    if (!opts.domain_name.empty()) domain_name_ = opts.domain_name;
    // base_dn — not present in groups NDJSON; no longer required from users
    if (domain_name_.empty()) domain_name_ = base_dn_to_domain(base_dn_);

    const std::string& ext4g = opts.output_ext.empty() ? "ndjson" : opts.output_ext;
    return load_and_process_groups(
        opts.raw_dir    + "/raw_groups.ndjson",
        opts.output_dir + "/domain_groups." + ext4g);
}

/*
bool OfflineProcessor::process(const OfflineProcessorOptions& opts) {
    fs::create_directories(opts.output_dir);
... Existing code ...
*/