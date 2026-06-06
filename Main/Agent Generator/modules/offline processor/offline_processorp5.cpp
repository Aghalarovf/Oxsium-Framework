// ─── offline_processorp5.cpp ─────────────────────────────────────────────────
// SECTION 23  NDJSON writer  —  domain_aces.ndjson
//
//  Each line is one ACE object (flat; object-level fields repeated per row).
//  ZIP compression is not applied at this stage — all final output files
//  are compressed together in a downstream ZIP stage.
//
//  Reading (Python):
//    import json
//    with open("domain_aces.ndjson") as f:
//        for line in f:
//            ace = json.loads(line)
//
//  Reading (C++ engine):
//    Read line by line → parse each line individually
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <fstream>
#include <sstream>

// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 23 — NDJSON writer
//  write_aces_parquet: name kept for API compatibility (public signature unchanged),
//  but now writes a plain .ndjson file directly.
// ─────────────────────────────────────────────────────────────────────────────
bool OfflineProcessor::write_aces_parquet(
    const std::vector<ProcessedAceObject>& objects,
    const std::string& out_path) const
{
    if (objects.empty()) {
        log_warn("[ACE-NDJSON] No ACEs to write — file not created.");
        return false;
    }

    std::ofstream f(out_path, std::ios::out | std::ios::trunc);
    if (!f) {
        log_err("[ACE-NDJSON] Failed to open output file: " + out_path);
        return false;
    }

    size_t total_aces = 0;
    std::vector<std::string> rows;

    for (const auto& obj : objects) {
        for (const auto& ace : obj.aces) {
            ++total_aces;

            std::ostringstream row;
            row << "{"
                // Object fields
                << "\"dn\":" << je(obj.dn) << ","
                << "\"object_class\":" << je(obj.object_class) << ","
                << "\"sam_name\":" << je(obj.sam_name) << ","
                << "\"obj_has_dangerous\":" << jb(obj.has_dangerous_aces) << ","
                // Trustee
                << "\"trustee_sid\":" << je(ace.trustee_sid) << ","
                << "\"trustee_name\":" << je(ace.trustee_name) << ","
                << "\"trustee_display_name\":" << je(ace.trustee_display_name) << ","
                << "\"trustee_type\":" << je(ace.trustee_type) << ","
                << "\"trustee_is_admin\":" << jb(ace.trustee_is_admin) << ","
                // ACE flags
                << "\"mask\":" << je(ace.mask_hex) << ","
                << "\"is_allow\":" << jb(ace.is_allow) << ","
                << "\"is_inherited\":" << jb(ace.is_inherited) << ","
                // GUID
                << "\"object_type_guid\":" << je(ace.object_type_guid) << ","
                << "\"object_type_name\":" << je(ace.guid_name) << ","
                << "\"inherited_guid\":" << je(ace.inherited_object_type_guid) << ","
                << "\"inherited_guid_name\":" << je(ace.inherited_guid_name) << ","
                // Rights array
                << "\"rights\":" << json_rights_arr(ace.rights_labels) << ","
                // Danger flags
                << "\"is_dangerous\":" << jb(ace.is_dangerous) << ","
                << "\"danger_reason\":" << je(ace.danger_reason)
                << "}";
            rows.push_back(row.str());
        }
    }

    write_objects(f, rows, out_path, "[ACE-NDJSON]");

    if (!f) {
        log_err("[ACE-NDJSON] Write error — output may be incomplete: " + out_path);
        return false;
    }

    log_ok("[OfflineProcessor] domain_aces written -> " + out_path);
    log_ok("[OfflineProcessor] "
        + std::to_string(total_aces)     + " ACE rows | "
        + std::to_string(objects.size()) + " objects");

    return true;
}