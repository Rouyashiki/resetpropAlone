#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace resetprop {

struct RebuildSummary {
    std::size_t files_scanned = 0;
    std::size_t valid_areas = 0;
    std::size_t files_rebuilt = 0;
};

struct CompactSummary {
    std::size_t files_scanned = 0;
    std::size_t valid_areas = 0;
    std::size_t files_compacted = 0;
};

bool set_property_in_file(const std::string& path,
                          const std::string& name,
                          const std::string& value,
                          std::string* error);

bool delete_property_in_file(const std::string& path,
                             const std::string& name,
                             bool* deleted,
                             std::string* error);

bool delete_property_by_scanning(const std::string& property_dir,
                                 const std::string& name,
                                 bool* deleted,
                                 std::string* error);

bool bump_property_area_serial(const std::string& property_dir, std::string* error);

bool rebuild_property_areas(const std::string& property_dir,
                            const std::optional<std::string>& context, bool force,
                            RebuildSummary* summary, std::string* error);

bool compact_property_areas(const std::string& property_dir,
                            const std::optional<std::string>& context,
                            CompactSummary* summary,
                            std::string* error);

}  // namespace resetprop
