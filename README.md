# AESDumpster

This is a fork of [GHFear/AESDumpster](https://github.com/GHFear/AESDumpster) with a native Linux build and a handful of scanning/reliability improvements, described below. All credit for the original tool and technique goes to GHFear.

## Usage

Drag and drop one or more Unreal Engine executables onto `AESDumpster` (or pass them as command-line arguments). It scans each one for embedded AES pak-encryption keys and prints any it finds, colored and ranked by entropy, with the most likely candidate highlighted.

## Building

### Windows (Visual Studio)

Open `AESDumpster/AESDumpster.sln` and build. Requires the v143 (VS 2022) toolset.

### Linux / native

```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Produces an `AESDumpster` binary in `build/`. No MinGW or Wine needed — this is a genuine native port (see below), verified against real Unreal Engine executables on both platforms.

## Changes from upstream

- **Native Linux support.** The Win32-specific pieces (console coloring, file I/O, the wide-char entry point) are now behind small platform branches; the actual key-scanning logic never depended on Windows in the first place, since it's parsing the *target* executable's PE format rather than calling into the OS. A `CMakeLists.txt` builds it natively on Linux alongside the existing Visual Studio project.
- **Section-restricted scanning with fallback.** The scanner tries `.text`/`.rdata` first (faster, fewer false positives on large modern UE5 binaries) and automatically falls back to a full-file scan if that turns up nothing.
- **Memory-mapped file loading.** Executables are mapped rather than fully read into a heap buffer, with an automatic fallback to the old read-into-memory approach if mapping isn't available.
- **Duplicate key results are deduplicated**, preserving discovery order.
- **Broader false-positive filtering.** The existing hand-maintained blacklist of known bad matches is kept as-is, alongside a new heuristic that catches float-constant-table false positives generically instead of needing new entries by hand.
- **Batch reliability fix.** Previously, one unreadable file in a multi-file drag-and-drop batch could silently abort processing of the rest; each file is now handled independently.
- Assorted correctness fixes: leaked file handles, unchecked reads, and mismatched `new`/`delete` usage.

Known gap: some newer UE5 Shipping builds still aren't matched (likely a compiler codegen change for how the key is initialized) — see the `TODO(UE5)` note in `KeyTools/KeyDumpster.h`.

The original `README` from the upstream repo is as follows:

---

AES Dumpster 1.3 Online Version:  [https://illusory.dev/aesdumpster/](https://illusory.dev/aesdumpster/) <br>

Find Android AES Keys (IDA Pro Scripts):<br>
-arm64-v8a: https://github.com/GHFear/find-ue4-aes-key-arm64-v8a<br>
-armeabi-v7a: https://github.com/GHFear/find-ue4-aes-key-armeabi-v7a<br>
-armeabi-v7a-type2: https://github.com/GHFear/find-ue4-aes-key-armeabi-v7a-type2
