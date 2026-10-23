# resetpropAlone

Standalone (or multi-call) **resetprop** — Magisk-style Android system property tool for YukiSU.

- **Entry**: `resetprop_main(int argc, char **argv)` for use when linked into ksud; define `RESETPROP_STANDALONE` for a standalone executable with `main()`.
- **Android**: Uses bionic `__system_property_*` APIs plus direct prop-area mmap edits for `-n`, delete fallback when `__system_property_delete` is unavailable, prop-area compaction, persistent property storage support, and property-context parsing across `serialized`, `split`, and `pre-split` layouts.
- **Supported flags**: `-n`, `-d/--delete`, `-c/--rebuild/--compact [CONTEXT]`, `--force`, `-w`, `--timeout`, `-f/--file`, `-p`, `-P`, `-Z`, `-A/--area-path`, `--context-type`, `--serial-path`, `-v`.
- **Usage**:
  - no args = list all properties
  - `NAME` = get property, context (`-Z`), or backing area path (`-A`)
  - `NAME VALUE` = set property; arguments after NAME are literal values, including `-d` and `--help`
  - `-d NAME` = delete property
  - `-f FILE` = load a `system.prop`-style file
  - `-w NAME [OLD_VALUE]` = wait for existence/change
  - `-c` = rebuild property areas containing allocation gaps or abnormal layouts; unchanged areas succeed
  - `-c --force` = rebuild every property area
  - `-c CONTEXT` = rebuild one SELinux context
  - `-c -Z NAME` / `-c -d NAME` = resolve NAME's context and rebuild it, optionally deleting NAME first
  - `-p` = include stored `persist.*` properties, preferring runtime values when reading
  - `-P` = read only stored persistent properties
  - `--context-type` = print detected property-context backend (`serialized`, `split`, or `presplit`)
  - `--serial-path` = print the current global property serial area path

Long property values are preserved by single-property reads and waits. Wait timeouts must be
finite, nonnegative, and representable by the monotonic clock.

## Build

### Android (NDK)

```bash
export ANDROID_NDK=/path/to/ndk
cmake -S . -B build_android \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26
cmake --build build_android
```

(API 26+ for `__system_property_read_callback`.)

### Host (stub)

```bash
cmake -S . -B build && cmake --build build
```

Prints that resetprop is for Android only.
