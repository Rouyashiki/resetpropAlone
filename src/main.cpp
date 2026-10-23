#include "prop_area.hpp"
#include "persistent_props.hpp"
#include "property_contexts.hpp"

/*
 * resetprop - get/set/list Android system properties.
 * Uses bionic __system_property_* API on Android.
 * Compatible with YukiSU's Android API 31+ userspace floor.
 *
 * Copyright (C) Magisk (original resetprop)
 * Copyright (C) YukiSU - standalone C++ implementation
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

namespace {

static void usage(FILE* out, const char* prog) {
    fprintf(out,
            "resetprop - System Property Manipulation Tool\n\n"
            "Usage: %s [flags] [arguments...]\n\n"
            "Read mode arguments:\n"
            "  (no arguments)    print all properties\n"
            "  NAME              get property NAME\n\n"
            "Write mode arguments:\n"
            "  NAME VALUE        set property NAME as VALUE\n"
            "  -f, --file FILE   load and set properties from FILE\n"
            "  -d, --delete NAME delete property\n"
            "  -c, --rebuild [CONTEXT] rebuild property areas (--compact is an alias)\n"
            "  --force           rebuild all areas even when no anomalies are found\n"
            "  -c -Z NAME        rebuild the area containing property NAME\n"
            "  -c -d NAME        delete NAME and rebuild its area\n\n"
            "Wait mode arguments (toggled with -w):\n"
            "  NAME              wait until property NAME exists or changes\n"
            "  NAME OLD_VALUE    if property NAME is not OLD_VALUE, return immediately;\n"
            "                    otherwise wait until NAME changes\n\n"
            "General flags:\n"
            "  -h, --help        show this message\n"
            "  -v, --verbose     print verbose information to stderr\n"
            "  -w                switch to wait mode\n"
            "  --timeout SEC     timeout for wait mode\n\n"
            "Read mode flags:\n"
            "  -p                also read persistent properties from storage\n"
            "  -P                only read persistent properties from storage\n"
            "  -Z                print property context instead of value\n"
            "  -A, --area-path   print backing prop-area path instead of value\n"
            "  --context-type    print detected property context backend\n"
            "  --serial-path     print global property serial area path\n\n"
            "Write mode flags:\n"
            "  -n                set properties bypassing property_service\n"
            "  -p                also write persistent prop changes to storage\n",
            prog);
}

#if defined(__ANDROID__)

using PropertyMap = std::map<std::string, std::string>;

#if defined(__ANDROID_API__) && __ANDROID_API__ >= 26

struct GetCookie {
    std::string* out;
    uint32_t* serial;
    bool done;
};

static void get_callback(void* cookie, const char* /*name*/, const char* value, uint32_t serial) {
    auto* c = static_cast<GetCookie*>(cookie);
    *c->out = value ? value : "";
    if (c->serial != nullptr) {
        *c->serial = serial;
    }
    c->done = true;
}

static bool prop_get(const char* name, std::string* value, uint32_t* serial = nullptr) {
    const prop_info* pi = __system_property_find(name);
    if (!pi)
        return false;
    GetCookie cb{value, serial, false};
    __system_property_read_callback(pi, get_callback, &cb);
    return cb.done;
}

static void list_read_callback(void* cookie, const char* name, const char* value, uint32_t /*serial*/) {
    auto* out = static_cast<PropertyMap*>(cookie);
    (*out)[name ? name : ""] = value ? value : "";
}

static void list_foreach_callback(const prop_info* pi, void* cookie) {
    auto* out = static_cast<PropertyMap*>(cookie);
    __system_property_read_callback(pi, list_read_callback, out);
}

#else  // API < 26: use deprecated __system_property_read

static bool prop_get(const char* name, std::string* value, uint32_t* /*serial*/ = nullptr) {
    const prop_info* pi = __system_property_find(name);
    if (!pi)
        return false;
    char name_buf[PROP_NAME_MAX];
    char value_buf[PROP_VALUE_MAX] = {};
    const int ret = __system_property_read(pi, name_buf, value_buf);
    if (ret < 0)
        return false;
    *value = value_buf;
    return true;
}

static void list_foreach_callback(const prop_info* pi, void* cookie) {
    auto* out = static_cast<PropertyMap*>(cookie);
    char name_buf[PROP_NAME_MAX];
    char value_buf[PROP_VALUE_MAX];
    if (__system_property_read(pi, name_buf, value_buf) > 0)
        (*out)[name_buf] = value_buf;
}

#endif  // defined(__ANDROID_API__) && __ANDROID_API__ >= 26

#if !defined(PROP_DIRNAME)
#define PROP_DIRNAME "/dev/__properties__"
#endif

constexpr const char* kPropertyDir = PROP_DIRNAME;
constexpr const char* kAppcompatDir = PROP_DIRNAME "/appcompat_override";
constexpr const char* kAppcompatPrefix = "ro.appcompat_override.";
constexpr mode_t kWritableMode = 0644;
constexpr mode_t kReadonlyMode = 0444;
constexpr auto kWaitPollInterval = std::chrono::milliseconds(200);

struct PropertyMapping {
    void* start = nullptr;
    size_t length = 0;
    off_t offset = 0;
    int prot = PROT_READ;
    std::string path;
};

static bool chmod_property_tree(const std::string& path, mode_t mode) {
    DIR* dir = opendir(path.c_str());
    if (dir == nullptr) {
        fprintf(stderr, "resetprop: opendir failed for %s: %s\n", path.c_str(), strerror(errno));
        return false;
    }

    bool ok = true;
    while (true) {
        errno = 0;
        dirent* entry = readdir(dir);
        if (entry == nullptr) {
            if (errno != 0) {
                ok = false;
                fprintf(stderr, "resetprop: readdir failed for %s: %s\n", path.c_str(),
                        strerror(errno));
            }
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        const std::string child = path + "/" + entry->d_name;
        struct stat st {};
        if (lstat(child.c_str(), &st) != 0) {
            ok = false;
            fprintf(stderr, "resetprop: lstat failed for %s: %s\n", child.c_str(), strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!chmod_property_tree(child, mode)) {
                ok = false;
            }
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        if (chmod(child.c_str(), mode) != 0) {
            ok = false;
            fprintf(stderr, "resetprop: chmod failed for %s: %s\n", child.c_str(), strerror(errno));
        }
    }

    closedir(dir);
    return ok;
}

static bool parse_mapping_permissions(const std::string& perms, int* prot) {
    if (perms.size() < 4) {
        return false;
    }

    int value = PROT_NONE;
    if (perms[0] == 'r') {
        value |= PROT_READ;
    }
    if (perms[1] == 'w') {
        value |= PROT_WRITE;
    }
    if (perms[2] == 'x') {
        value |= PROT_EXEC;
    }
    *prot = value;
    return true;
}

static bool collect_property_mappings(std::vector<PropertyMapping>* mappings) {
    FILE* maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) {
        fprintf(stderr, "resetprop: failed to open /proc/self/maps: %s\n", strerror(errno));
        return false;
    }

    bool ok = true;
    char* line = nullptr;
    size_t line_cap = 0;
    while (getline(&line, &line_cap, maps) != -1) {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long offset = 0;
        char perms[5] = {};
        unsigned int major = 0;
        unsigned int minor = 0;
        unsigned long inode = 0;
        int consumed = 0;
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %n", &start, &end, perms, &offset, &major,
                   &minor, &inode, &consumed) < 7) {
            continue;
        }

        const char* path_ptr = line + consumed;
        while (*path_ptr == ' ' || *path_ptr == '\t') {
            ++path_ptr;
        }

        std::string path(path_ptr);
        while (!path.empty() && (path.back() == '\n' || path.back() == '\r')) {
            path.pop_back();
        }

        if (path.rfind(kPropertyDir, 0) != 0) {
            continue;
        }

        int prot = PROT_NONE;
        if (!parse_mapping_permissions(perms, &prot)) {
            ok = false;
            fprintf(stderr, "resetprop: failed to parse mapping perms for %s\n", path.c_str());
            continue;
        }

        PropertyMapping mapping;
        mapping.start = reinterpret_cast<void*>(start);
        mapping.length = static_cast<size_t>(end - start);
        mapping.offset = static_cast<off_t>(offset);
        mapping.prot = prot;
        mapping.path = std::move(path);
        mappings->push_back(std::move(mapping));
    }

    free(line);
    fclose(maps);
    return ok;
}

static bool remap_property_mapping(const PropertyMapping& mapping, int target_prot, int open_flags) {
    const int fd = open(mapping.path.c_str(), open_flags | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "resetprop: open failed for %s: %s\n", mapping.path.c_str(),
                strerror(errno));
        return false;
    }

    void* result =
        mmap(mapping.start, mapping.length, target_prot, MAP_SHARED | MAP_FIXED, fd, mapping.offset);
    const int saved_errno = errno;
    close(fd);

    if (result != mapping.start) {
        fprintf(stderr, "resetprop: mmap remap failed for %s: %s\n", mapping.path.c_str(),
                strerror(saved_errno));
        return false;
    }

    return true;
}

static void prime_mapping_callback(const prop_info*, void*) {}

// Bionic maps each /dev/__properties__ context file lazily and read-only, on the first lookup
// that resolves into it (ContextsSerialized::GetPropAreaForName). A /proc/self/maps snapshot
// taken before that lookup therefore cannot see the area we are about to write. Walking every
// property first forces all readable contexts to be mapped.
static void map_all_property_areas() {
    (void)__system_property_foreach(prime_mapping_callback, nullptr);
}

class ScopedPropertyWriteAccess {
public:
    ScopedPropertyWriteAccess() {
        map_all_property_areas();
        active_ = chmod_property_tree(kPropertyDir, kWritableMode) &&
                  collect_property_mappings(&mappings_);
        if (active_) {
            remap_writable();
        }
    }

    ScopedPropertyWriteAccess(const ScopedPropertyWriteAccess&) = delete;
    ScopedPropertyWriteAccess& operator=(const ScopedPropertyWriteAccess&) = delete;

    ~ScopedPropertyWriteAccess() {
        if (active_) {
            (void)remap_original();
            (void)chmod_property_tree(kPropertyDir, kReadonlyMode);
        }
    }

    bool active() const { return active_; }

    // Priming above is not airtight: GetPropAreaForName deliberately retries a context that
    // failed the SELinux read check during foreach(), so a read-only area can still appear after
    // the constructor ran. Writing through one faults with SEGV_ACCERR, so confirm the mapping
    // that actually holds the target is writable immediately before handing it to bionic.
    bool ensure_writable(const void* addr) {
        if (!active_) {
            return false;
        }
        if (find_mapping(mappings_, addr) != nullptr) {
            return true;
        }

        std::vector<PropertyMapping> current;
        if (!collect_property_mappings(&current)) {
            return false;
        }
        const PropertyMapping* mapping = find_mapping(current, addr);
        if (mapping == nullptr) {
            return false;
        }
        if ((mapping->prot & PROT_WRITE) != 0) {
            return true;
        }
        if (!remap_property_mapping(*mapping, mapping->prot | PROT_WRITE, O_RDWR)) {
            return false;
        }
        // Recorded so the destructor restores the original protection.
        mappings_.push_back(*mapping);
        return true;
    }

private:
    static const PropertyMapping* find_mapping(const std::vector<PropertyMapping>& mappings,
                                               const void* addr) {
        const auto* target = static_cast<const char*>(addr);
        for (const auto& mapping : mappings) {
            const auto* base = static_cast<const char*>(mapping.start);
            if (target >= base && target < base + mapping.length) {
                return &mapping;
            }
        }
        return nullptr;
    }

    // Best effort: only the bionic __system_property_update path needs writable mappings, and
    // ensure_writable() re-checks its own target. The prop-area fallback in prop_area.cpp maps
    // O_RDWR itself and only depends on the chmod above, so one unremappable context must not
    // fail the whole scope.
    void remap_writable() {
        for (const auto& mapping : mappings_) {
            if ((mapping.prot & PROT_WRITE) != 0) {
                continue;
            }
            (void)remap_property_mapping(mapping, mapping.prot | PROT_WRITE, O_RDWR);
        }
    }

    bool remap_original() const {
        bool ok = true;
        for (const auto& mapping : mappings_) {
            if (!remap_property_mapping(mapping, mapping.prot, O_RDONLY)) {
                ok = false;
            }
        }
        return ok;
    }

    std::vector<PropertyMapping> mappings_;
    bool active_ = false;
};

using SystemPropertyUpdateFn = int (*)(prop_info*, const char*, unsigned int);
using SystemPropertyDeleteFn = int (*)(const char*, bool);
using SystemPropertyGetContextFn = const char* (*)(const char*);
using SystemPropertiesInitFn = int (*)();
using SystemPropertyWaitFn = bool (*)(const prop_info*, uint32_t, uint32_t*, const timespec*);
using SystemPropertyAreaSerialFn = uint32_t (*)();

struct Options {
    bool help = false;
    bool verbose = false;
    bool wait_mode = false;
    bool persist = false;
    bool persist_only = false;
    bool show_context = false;
    bool show_area_path = false;
    bool show_context_type = false;
    bool show_serial_path = false;
    bool skip_svc = false;
    bool delete_mode = false;
    bool rebuild_mode = false;
    bool force = false;
    const char* file = nullptr;
    std::optional<std::chrono::steady_clock::duration> timeout;
    std::vector<const char*> positional;
};

bool g_verbose = false;

void print_error(const std::string& message) {
    fprintf(stderr, "resetprop: %s\n", message.c_str());
}

void verbose_log(const std::string& message) {
    if (g_verbose)
        fprintf(stderr, "resetprop: %s\n", message.c_str());
}

static SystemPropertyUpdateFn resolve_property_update() {
    static bool resolved = false;
    static SystemPropertyUpdateFn cached_update = nullptr;

    if (!resolved) {
        cached_update = reinterpret_cast<SystemPropertyUpdateFn>(
            dlsym(RTLD_DEFAULT, "__system_property_update"));
        resolved = true;
    }

    return cached_update;
}

static SystemPropertyDeleteFn resolve_property_delete() {
    static bool resolved = false;
    static SystemPropertyDeleteFn cached_delete = nullptr;

    if (!resolved) {
        cached_delete = reinterpret_cast<SystemPropertyDeleteFn>(
            dlsym(RTLD_DEFAULT, "__system_property_delete"));
        resolved = true;
    }

    return cached_delete;
}

static SystemPropertiesInitFn resolve_properties_init() {
    static bool resolved = false;
    static SystemPropertiesInitFn cached_init = nullptr;

    if (!resolved) {
        cached_init = reinterpret_cast<SystemPropertiesInitFn>(
            dlsym(RTLD_DEFAULT, "__system_properties_init"));
        resolved = true;
    }

    return cached_init;
}

static SystemPropertyGetContextFn resolve_property_get_context() {
    static bool resolved = false;
    static SystemPropertyGetContextFn cached_get_context = nullptr;

    if (!resolved) {
        cached_get_context = reinterpret_cast<SystemPropertyGetContextFn>(
            dlsym(RTLD_DEFAULT, "__system_property_get_context"));
        resolved = true;
    }

    return cached_get_context;
}

static SystemPropertyWaitFn resolve_property_wait() {
    static bool resolved = false;
    static SystemPropertyWaitFn cached_wait = nullptr;

    if (!resolved) {
        cached_wait = reinterpret_cast<SystemPropertyWaitFn>(
            dlsym(RTLD_DEFAULT, "__system_property_wait"));
        resolved = true;
    }

    return cached_wait;
}

static SystemPropertyAreaSerialFn resolve_property_area_serial() {
    static bool resolved = false;
    static SystemPropertyAreaSerialFn cached_area_serial = nullptr;

    if (!resolved) {
        cached_area_serial = reinterpret_cast<SystemPropertyAreaSerialFn>(
            dlsym(RTLD_DEFAULT, "__system_property_area_serial"));
        resolved = true;
    }

    return cached_area_serial;
}

static bool parse_timeout(const char* text, std::chrono::steady_clock::duration* value) {
    char* end = nullptr;
    errno = 0;
    const double parsed = std::strtod(text, &end);
    if (errno != 0 || end == text || (end != nullptr && *end != '\0') || !std::isfinite(parsed) ||
        parsed < 0) {
        return false;
    }
    using Duration = std::chrono::steady_clock::duration;
    const auto ticks = std::chrono::duration<long double, Duration::period>(
                           std::chrono::duration<long double>(parsed))
                           .count();
    if (!std::isfinite(ticks) || ticks >= static_cast<long double>(Duration::max().count())) {
        return false;
    }
    *value = Duration(static_cast<Duration::rep>(ticks));
    return true;
}

static std::string trim(std::string value) {
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

static bool parse_options(int argc, char** argv, Options* options, std::string* error) {
    bool positional = false;
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (positional) {
            options->positional.push_back(arg);
            continue;
        }
        if (std::strcmp(arg, "--") == 0) {
            positional = true;
            continue;
        }
        if (std::strcmp(arg, "-h") == 0 || std::strcmp(arg, "--help") == 0) {
            options->help = true;
            return true;
        }
        if (std::strcmp(arg, "-v") == 0 || std::strcmp(arg, "--verbose") == 0) {
            options->verbose = true;
            continue;
        }
        if (std::strcmp(arg, "-w") == 0) {
            options->wait_mode = true;
            continue;
        }
        if (std::strcmp(arg, "-p") == 0) {
            options->persist = true;
            continue;
        }
        if (std::strcmp(arg, "-P") == 0) {
            options->persist = true;
            options->persist_only = true;
            continue;
        }
        if (std::strcmp(arg, "-Z") == 0) {
            options->show_context = true;
            continue;
        }
        if (std::strcmp(arg, "-A") == 0 || std::strcmp(arg, "--area-path") == 0) {
            options->show_area_path = true;
            continue;
        }
        if (std::strcmp(arg, "--context-type") == 0) {
            options->show_context_type = true;
            continue;
        }
        if (std::strcmp(arg, "--serial-path") == 0) {
            options->show_serial_path = true;
            continue;
        }
        if (std::strcmp(arg, "-n") == 0) {
            options->skip_svc = true;
            continue;
        }
        if (std::strcmp(arg, "-d") == 0 || std::strcmp(arg, "--delete") == 0) {
            options->delete_mode = true;
            continue;
        }
        if (std::strcmp(arg, "-c") == 0 || std::strcmp(arg, "--rebuild") == 0 ||
            std::strcmp(arg, "--compact") == 0) {
            options->rebuild_mode = true;
            continue;
        }
        if (std::strcmp(arg, "--force") == 0) {
            options->force = true;
            continue;
        }
        if (std::strcmp(arg, "-f") == 0 || std::strcmp(arg, "--file") == 0) {
            if (i + 1 >= argc) {
                *error = "missing file path after --file";
                return false;
            }
            options->file = argv[++i];
            continue;
        }
        if (std::strcmp(arg, "--timeout") == 0) {
            if (i + 1 >= argc) {
                *error = "missing value after --timeout";
                return false;
            }
            std::chrono::steady_clock::duration timeout{};
            if (!parse_timeout(argv[++i], &timeout)) {
                *error = "invalid timeout value";
                return false;
            }
            options->timeout = timeout;
            continue;
        }
        options->positional.push_back(arg);
        positional = true;
    }

    return true;
}

static bool deadline_reached(const std::optional<std::chrono::steady_clock::time_point>& deadline) {
    return deadline.has_value() && std::chrono::steady_clock::now() >= *deadline;
}

static const timespec* remaining_wait_timespec(
    const std::optional<std::chrono::steady_clock::time_point>& deadline,
    timespec* spec) {
    if (!deadline.has_value()) {
        return nullptr;
    }

    auto remaining = *deadline - std::chrono::steady_clock::now();
    if (remaining < std::chrono::steady_clock::duration::zero()) {
        remaining = std::chrono::steady_clock::duration::zero();
    }

    const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(remaining);
    spec->tv_sec = static_cast<time_t>(nanos.count() / 1000000000ll);
    spec->tv_nsec = static_cast<long>(nanos.count() % 1000000000ll);
    return spec;
}

static bool wait_for_property_change(SystemPropertyWaitFn wait_fn,
                                     const prop_info* pi,
                                     uint32_t old_serial,
                                     const std::optional<std::chrono::steady_clock::time_point>& deadline,
                                     bool* timed_out) {
    if (wait_fn == nullptr) {
        return false;
    }
    if (deadline_reached(deadline)) {
        *timed_out = true;
        return false;
    }

    timespec ts {};
    uint32_t new_serial = 0;
    const bool changed =
        wait_fn(pi, old_serial, &new_serial, remaining_wait_timespec(deadline, &ts));
    if (!changed && deadline.has_value()) {
        *timed_out = true;
    }
    return changed;
}

static bool set_property_direct(ScopedPropertyWriteAccess& access,
                                const char* name,
                                const char* value) {
    const SystemPropertyUpdateFn update_fn = resolve_property_update();
    if (update_fn == nullptr) {
        fputs("resetprop: __system_property_update is unavailable at runtime\n", stderr);
        return false;
    }

    const prop_info* pi = __system_property_find(name);
    if (pi == nullptr) {
        return false;
    }
    // The lookup above may have mapped this property's context area for the first time.
    // __system_property_update writes the dirty backup area, the serial and the value, all
    // inside that mapping.
    if (!access.ensure_writable(pi)) {
        verbose_log(std::string("property area holding ") + name +
                    " is not writable, falling back to prop-area edit");
        return false;
    }
    auto* mutable_pi = const_cast<prop_info*>(pi);
    return update_fn(mutable_pi, value, strlen(value)) == 0;
}

static bool delete_property_direct(const char* name, bool* deleted) {
    *deleted = false;

    if (__system_property_find(name) == nullptr) {
        return true;
    }

    const auto delete_fn = resolve_property_delete();
    if (delete_fn != nullptr && delete_fn(name, true) == 0) {
        *deleted = (__system_property_find(name) == nullptr);
        if (*deleted) {
            return true;
        }
        verbose_log(std::string("property still visible after runtime delete, falling back to prop-area edit: ") +
                    name);
    } else if (delete_fn == nullptr) {
        verbose_log(std::string("property delete symbol is unavailable, falling back to prop-area edit: ") +
                    name);
    } else {
        verbose_log(std::string("direct property delete failed, falling back to prop-area edit: ") +
                    name);
    }

    ScopedPropertyWriteAccess access;
    if (!access.active()) {
        fputs("resetprop: failed to gain write access to property area\n", stderr);
        return false;
    }

    std::string error;
    if (!resetprop::delete_property_by_scanning(kPropertyDir, name, deleted, &error)) {
        fprintf(stderr, "resetprop: prop-area delete failed for %s: %s\n", name, error.c_str());
        return false;
    }

    return true;
}

static bool is_persist_property(const char* name) {
    return std::strncmp(name, "persist.", 8) == 0;
}

static bool is_read_only_property(const char* name) {
    return std::strncmp(name, "ro.", 3) == 0;
}

static bool get_property_context_value(const std::string& name,
                                       std::string* context,
                                       std::string* error);

static bool get_property_area_path_value(const char* props_root,
                                         const std::string& name,
                                         std::string* path,
                                         std::string* context,
                                         std::string* error);

static bool bump_property_serial_for_root(const char* props_root, std::string* error);

static bool directory_exists(const char* path) {
    struct stat st {};
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static std::string strip_appcompat_prefix(const std::string& name) {
    if (name.rfind(kAppcompatPrefix, 0) == 0) {
        return name.substr(std::strlen(kAppcompatPrefix));
    }
    return name;
}

static bool maybe_mirror_appcompat_set(const char* name,
                                       const char* value,
                                       std::string* error) {
    if (!directory_exists(kAppcompatDir) || !is_read_only_property(name)) {
        return true;
    }
    const std::string override_key = strip_appcompat_prefix(name);
    std::string path;
    std::string context;
    if (!get_property_area_path_value(kAppcompatDir, override_key, &path, &context, error)) {
        return false;
    }
    if (!resetprop::set_property_in_file(path, override_key, value, error)) {
        return false;
    }
    return bump_property_serial_for_root(kAppcompatDir, error);
}

static bool maybe_mirror_appcompat_delete(const char* name,
                                          bool* deleted,
                                          std::string* error) {
    if (!directory_exists(kAppcompatDir) || !is_read_only_property(name)) {
        return true;
    }
    bool appcompat_deleted = false;
    std::string path;
    std::string context;
    const std::string override_key = strip_appcompat_prefix(name);
    if (!get_property_area_path_value(kAppcompatDir, override_key, &path, &context, error)) {
        return false;
    }
    if (!resetprop::delete_property_in_file(path, override_key, &appcompat_deleted, error)) {
        return false;
    }
    if (appcompat_deleted && !bump_property_serial_for_root(kAppcompatDir, error)) {
        return false;
    }
    *deleted = *deleted || appcompat_deleted;
    return true;
}

static bool delete_property_from_area(const char* name, bool* deleted, std::string* error) {
    std::string path;
    std::string context;
    if (!get_property_area_path_value(kPropertyDir, name, &path, &context, error)) {
        return false;
    }
    return resetprop::delete_property_in_file(path, name, deleted, error);
}

static bool get_property_context_value(const std::string& name,
                                       std::string* context,
                                       std::string* error) {
    return resetprop::resolve_property_context_from(kPropertyDir, name, context, error);
}

static bool get_property_area_path_value(const char* props_root,
                                         const std::string& name,
                                         std::string* path,
                                         std::string* context,
                                         std::string* error) {
    return resetprop::resolve_property_area_path(props_root, name, path, context, error);
}

static bool bump_property_serial_for_root(const char* props_root, std::string* error) {
    std::string path;
    if (!resetprop::resolve_property_serial_path(props_root, &path, error)) {
        return false;
    }
    return resetprop::bump_property_area_serial(path, error);
}

static bool get_property_value(const Options& options,
                               const char* name,
                               std::string* value,
                               bool* found,
                               std::string* error) {
    *found = false;

    if (options.show_context) {
        if (!get_property_context_value(name, value, error)) {
            return false;
        }
        *found = true;
        return true;
    }

    if (options.show_area_path) {
        std::string context;
        if (!get_property_area_path_value(kPropertyDir, name, value, &context, error)) {
            return false;
        }
        *found = true;
        return true;
    }

    if (!options.persist_only) {
        if (prop_get(name, value)) {
            *found = true;
            return true;
        }
    }

    if ((options.persist || options.persist_only) && is_persist_property(name)) {
        return resetprop::get_persistent_property(name, value, found, error);
    }

    return true;
}

static bool list_properties(const Options& options,
                            PropertyMap* properties,
                            std::string* error) {
    properties->clear();

    if (!options.persist_only) {
        if (__system_property_foreach(list_foreach_callback, properties) != 0) {
            *error = "__system_property_foreach failed";
            return false;
        }
    }

    if (options.persist || options.persist_only) {
        resetprop::PersistentPropertyMap persist_props;
        if (!resetprop::list_persistent_properties(&persist_props, error)) {
            return false;
        }
        for (const auto& [name, value] : persist_props) {
            properties->emplace(name, value);
        }
    }

    return true;
}

static bool set_property_value(const Options& options,
                               const char* name,
                               const char* value,
                               std::string* error) {
    const bool direct = options.skip_svc || std::strncmp(name, "ro.", 3) == 0;

    if (direct) {
        ScopedPropertyWriteAccess access;
        if (!access.active()) {
            *error = "failed to gain write access to property area";
            return false;
        }

        if (is_read_only_property(name) || !set_property_direct(access, name, value)) {
            std::string path;
            std::string context;
            if (!get_property_area_path_value(kPropertyDir, name, &path, &context, error)) {
                return false;
            }
            if (!resetprop::set_property_in_file(path, name, value, error)) {
                return false;
            }
            if (!bump_property_serial_for_root(kPropertyDir, error)) {
                return false;
            }
        }
        if (!maybe_mirror_appcompat_set(name, value, error)) {
            return false;
        }
    } else if (__system_property_set(name, value) != 0) {
        *error = "__system_property_set failed";
        return false;
    }

    if (options.persist && is_persist_property(name) &&
        !resetprop::set_persistent_property(name, value, error)) {
        return false;
    }

    return true;
}

static bool delete_property_value(const Options& options,
                                  const char* name,
                                  bool* deleted,
                                  std::string* error) {
    *deleted = false;

    if (!options.persist_only) {
        ScopedPropertyWriteAccess access;
        if (!access.active()) {
            *error = "failed to gain write access to property area";
            return false;
        }
        if (!delete_property_from_area(name, deleted, error)) {
            return false;
        }
        if (*deleted && !bump_property_serial_for_root(kPropertyDir, error)) {
            return false;
        }
        if (!maybe_mirror_appcompat_delete(name, deleted, error)) {
            return false;
        }
    }

    if (options.persist && is_persist_property(name)) {
        bool persist_deleted = false;
        if (!resetprop::delete_persistent_property(name, &persist_deleted, error)) {
            return false;
        }
        *deleted = *deleted || persist_deleted;
    }

    return true;
}

static bool load_property_file(const Options& options, const char* path, std::string* error) {
    FILE* file = fopen(path, "r");
    if (file == nullptr) {
        *error = "failed to open property file";
        return false;
    }
    (void)fcntl(fileno(file), F_SETFD, FD_CLOEXEC);

    char* buffer = nullptr;
    std::size_t capacity = 0;
    std::size_t line_number = 0;
    bool ok = true;
    while (getline(&buffer, &capacity, file) >= 0) {
        ++line_number;
        std::string line(buffer);
        const auto comment_pos = line.find('#');
        if (comment_pos != std::string::npos)
            line.erase(comment_pos);
        line = trim(std::move(line));
        if (line.empty() || line.rfind("import ", 0) == 0)
            continue;

        const auto equal_pos = line.find('=');
        if (equal_pos == std::string::npos)
            continue;
        std::string key = trim(line.substr(0, equal_pos));
        std::string value = trim(line.substr(equal_pos + 1));
        if (key.empty())
            continue;
        if (!set_property_value(options, key.c_str(), value.c_str(), error)) {
            *error = "line " + std::to_string(line_number) + ": " + *error;
            ok = false;
            break;
        }
    }
    if (ferror(file) != 0) {
        *error = "failed to read property file";
        ok = false;
    }
    free(buffer);
    fclose(file);
    return ok;
}

static bool wait_for_property(const char* name, const char* old_value,
                              const std::optional<std::chrono::steady_clock::duration>& timeout,
                              bool* timed_out) {
    *timed_out = false;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    if (timeout.has_value()) {
        const auto now = std::chrono::steady_clock::now();
        const auto max = std::chrono::steady_clock::time_point::max();
        deadline =
            now.time_since_epoch() > max.time_since_epoch() - *timeout ? max : now + *timeout;
    }

    const auto wait_fn = resolve_property_wait();
    const auto area_serial_fn = resolve_property_area_serial();

    while (true) {
        uint32_t global_serial = 0;
        if (wait_fn != nullptr && area_serial_fn != nullptr) {
            global_serial = area_serial_fn();
        }

        if (__system_property_find(name) != nullptr) {
            break;
        }

        if (wait_fn != nullptr && area_serial_fn != nullptr) {
            if (!wait_for_property_change(wait_fn, nullptr, global_serial, deadline, timed_out)) {
                if (*timed_out) {
                    return false;
                }
            }
            continue;
        }

        if (deadline_reached(deadline)) {
            *timed_out = true;
            return false;
        }

        const auto now = std::chrono::steady_clock::now();
        const auto poll_interval =
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(kWaitPollInterval);
        const auto sleep_for = deadline.has_value() ? std::min(poll_interval, *deadline - now)
                                                    : poll_interval;
        if (sleep_for > std::chrono::steady_clock::duration::zero()) {
            std::this_thread::sleep_for(sleep_for);
        }
    }

    if (old_value == nullptr) {
        return true;
    }

    while (true) {
        uint32_t global_serial = 0;
        if (wait_fn != nullptr && area_serial_fn != nullptr) {
            global_serial = area_serial_fn();
        }

        std::string value;
        uint32_t prop_serial = 0;
        if (!prop_get(name, &value, &prop_serial) || value != old_value) {
            return true;
        }

        bool waited = false;
        if (wait_fn != nullptr && area_serial_fn != nullptr) {
            waited = true;
            if (!wait_for_property_change(wait_fn, nullptr, global_serial, deadline, timed_out)) {
                if (*timed_out) {
                    return false;
                }
            }
        } else if (wait_fn != nullptr) {
            const prop_info* pi = __system_property_find(name);
            if (pi != nullptr) {
                waited = true;
                if (!wait_for_property_change(wait_fn, pi, prop_serial, deadline, timed_out)) {
                    if (*timed_out) {
                        return false;
                    }
                }
            }
        }

        if (waited) {
            continue;
        }

        if (deadline_reached(deadline)) {
            *timed_out = true;
            return false;
        }

        const auto now = std::chrono::steady_clock::now();
        const auto poll_interval =
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(kWaitPollInterval);
        const auto sleep_for = deadline.has_value() ? std::min(poll_interval, *deadline - now)
                                                    : poll_interval;
        if (sleep_for > std::chrono::steady_clock::duration::zero()) {
            std::this_thread::sleep_for(sleep_for);
        }
    }
}

#endif  // __ANDROID__

}  // namespace

extern "C" {

int resetprop_main(int argc, char** argv) {
    const char* prog = (argv && argv[0]) ? argv[0] : "resetprop";

#if !defined(__ANDROID__)
    fputs("resetprop: Android only. Build with NDK for device.\n", stderr);
    usage(stderr, prog);
    return 1;
#else

#if defined(__ANDROID_API__) && __ANDROID_API__ >= 26
    if (const auto init_fn = resolve_properties_init(); init_fn != nullptr) {
        if (init_fn() != 0) {
            fputs("resetprop: __system_properties_init failed\n", stderr);
            return 1;
        }
    }
#endif

    Options options;
    std::string error;
    if (!parse_options(argc, argv, &options, &error)) {
        print_error(error);
        usage(stderr, prog);
        return 1;
    }
    g_verbose = options.verbose;

    if (options.help) {
        usage(stderr, prog);
        return 0;
    }

    const int special_modes = static_cast<int>(options.wait_mode) +
                              static_cast<int>(options.delete_mode) +
                              static_cast<int>(options.file != nullptr);
    if (special_modes > 1) {
        fputs("resetprop: multiple operation modes detected\n", stderr);
        return 1;
    }
    if (options.rebuild_mode && (options.wait_mode || options.file != nullptr)) {
        fputs("resetprop: only -d can be combined with -c\n", stderr);
        return 1;
    }
    if (options.show_context && options.show_area_path) {
        fputs("resetprop: -Z and -A are mutually exclusive\n", stderr);
        return 1;
    }
    if (options.persist_only && (options.delete_mode || options.rebuild_mode ||
                                 options.file != nullptr || options.positional.size() == 2)) {
        fputs("resetprop: -P is read-only and cannot be combined with write operations\n", stderr);
        return 1;
    }
    if (options.show_context_type || options.show_serial_path) {
        if (options.wait_mode || options.delete_mode || options.rebuild_mode ||
            options.file != nullptr || !options.positional.empty() || options.show_context ||
            options.show_area_path) {
            fputs("resetprop: context-inspection flags cannot be combined with other modes\n",
                  stderr);
            return 1;
        }
        if (options.show_context_type) {
            resetprop::PropertyContextType type;
            if (!resetprop::detect_property_context_type(kPropertyDir, &type, &error)) {
                print_error(error);
                return 1;
            }
            printf("%s\n", resetprop::property_context_type_name(type));
        }
        if (options.show_serial_path) {
            std::string path;
            if (!resetprop::resolve_property_serial_path(kPropertyDir, &path, &error)) {
                print_error(error);
                return 1;
            }
            printf("%s\n", path.c_str());
        }
        return 0;
    }

    if (options.wait_mode) {
        if (options.positional.empty() || options.positional.size() > 2) {
            usage(stderr, prog);
            return 1;
        }
        bool timed_out = false;
        if (!wait_for_property(options.positional[0],
                               options.positional.size() == 2 ? options.positional[1] : nullptr,
                               options.timeout, &timed_out)) {
            if (timed_out) {
                fprintf(stderr, "resetprop: timeout waiting for %s\n", options.positional[0]);
                return 2;
            }
            return 1;
        }
        return 0;
    }

    if (options.rebuild_mode) {
        if (options.positional.size() > 1) {
            usage(stderr, prog);
            return 1;
        }
        std::optional<std::string> context;
        if (!options.positional.empty()) {
            context = options.positional[0];
            if ((options.show_context || options.delete_mode) &&
                !get_property_context_value(options.positional[0], &*context, &error)) {
                print_error(error);
                return 1;
            }
        }
        if (options.delete_mode) {
            if (options.positional.empty()) {
                usage(stderr, prog);
                return 1;
            }
            bool deleted = false;
            if (!delete_property_value(options, options.positional[0], &deleted, &error)) {
                print_error(error);
                return 1;
            }
            if (!deleted) {
                fprintf(stderr, "resetprop: property not found: %s\n", options.positional[0]);
                return 1;
            }
        }

        const auto rebuild_one_dir = [&](const char* dir) -> bool {
            resetprop::RebuildSummary summary;
            if (!resetprop::rebuild_property_areas(dir, context, options.force, &summary, &error)) {
                return false;
            }
            verbose_log("rebuilt " + std::to_string(summary.files_rebuilt) + " property areas");
            return true;
        };

        if (!rebuild_one_dir(kPropertyDir)) {
            fprintf(stderr, "resetprop: rebuild failed: %s\n", error.c_str());
            return 1;
        }
        if (context.has_value() && directory_exists(kAppcompatDir) &&
            !rebuild_one_dir(kAppcompatDir)) {
            fprintf(stderr, "resetprop: rebuild failed: %s\n", error.c_str());
            return 1;
        }
        return 0;
    }

    if (options.file != nullptr) {
        if (!options.positional.empty()) {
            usage(stderr, prog);
            return 1;
        }
        if (!load_property_file(options, options.file, &error)) {
            print_error(error);
            return 1;
        }
        return 0;
    }

    if (options.delete_mode) {
        if (options.positional.size() != 1) {
            usage(stderr, prog);
            return 1;
        }
        bool deleted = false;
        if (!delete_property_value(options, options.positional[0], &deleted, &error)) {
            print_error(error);
            return 1;
        }
        if (!deleted) {
            fprintf(stderr, "resetprop: property not found: %s\n", options.positional[0]);
            return 1;
        }
        return 0;
    }

    if (options.positional.empty()) {
        PropertyMap properties;
        if (!list_properties(options, &properties, &error)) {
            print_error(error);
            return 1;
        }
        for (const auto& [name, value] : properties) {
            if (options.show_context) {
                std::string context;
                if (!get_property_context_value(name, &context, &error)) {
                    print_error(error);
                    return 1;
                }
                printf("[%s]: [%s]\n", name.c_str(), context.c_str());
            } else if (options.show_area_path) {
                std::string path;
                std::string context;
                if (!get_property_area_path_value(kPropertyDir, name, &path, &context, &error)) {
                    print_error(error);
                    return 1;
                }
                printf("[%s]: [%s]\n", name.c_str(), path.c_str());
            } else {
                printf("[%s]: [%s]\n", name.c_str(), value.c_str());
            }
        }
        return 0;
    }

    if (options.positional.size() == 1) {
        std::string value;
        bool found = false;
        if (!get_property_value(options, options.positional[0], &value, &found, &error)) {
            print_error(error);
            return 1;
        }
        if (!found) {
            fprintf(stderr, "resetprop: property not found: %s\n", options.positional[0]);
            return 1;
        }
        printf("%s\n", value.c_str());
        return 0;
    }

    if (options.positional.size() == 2) {
        if (!set_property_value(options, options.positional[0], options.positional[1], &error)) {
            print_error(error);
            return 1;
        }
        return 0;
    }

    usage(stderr, prog);
    return 1;
#endif
}

}  // extern "C"

#if defined(RESETPROP_STANDALONE)
int main(int argc, char** argv) {
    return resetprop_main(argc, argv);
}
#endif
