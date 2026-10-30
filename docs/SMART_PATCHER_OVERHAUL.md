# Smart Patcher + APK Editor Overhaul

[Русский](SMART_PATCHER_OVERHAUL.ru.md)

## Audit findings

- Patch lookup keys used only `file_path + method_name`, so overloaded methods could overwrite or deduplicate each other.
- The Go exporter already produced hashes and block artifacts, but the Zig APK Editor ignored them.
- The editor replaced complete method bodies even when a minimal validated block patch existed.
- Reverting one patch restored the whole `.original` file, potentially removing unrelated edits and other patches.
- Method matching accepted loose substrings and silently selected the first match.
- Patch paths were joined without rejecting absolute paths or `..` traversal.
- `apply_safe` was exported but not enforced by the IDE.
- JSON persistence in the IDE interpolated source code without JSON escaping.
- The standalone `cmd/patch-apk` command contained hard-coded developer paths.

## Implementation TODO

- [x] Introduce signature-aware patch identity and deterministic patch IDs.
- [x] Normalize candidate strategies by Dalvik return type, merge corroborating signals, penalize library/unknown contexts, and rank deterministically.
- [x] Upgrade the JSON bridge to schema v2 while keeping v1 fields compatible.
- [x] Export flattened block-patch metadata for the Zig IDE.
- [x] Make Go artifact application path-safe, idempotent, block-aware, and atomic.
- [x] Add precise reverse application instead of whole-file rollback.
- [x] Harden Zig method lookup, path validation, safety checks, line endings, and conflict handling.
- [x] Make Zig apply/revert use minimal blocks when whole-method context drifted.
- [x] Preserve patch identity and safety metadata in IDE history.
- [x] Replace unsafe manual JSON persistence with the standard JSON stringifier.
- [x] Improve IDE batch status and prevent accepting blocked patches.
- [x] Replace the hard-coded APK replacement utility with a reusable CLI.
- [x] Add regression tests for overload identity, path traversal, idempotency, block relocation, and independent revert.
- [ ] Run native Go/Zig test suites in an environment containing Go 1.27.1 and Zig 0.15.1.

## Compatibility

The editor continues to read legacy `1.0.0` patch files. New exports use schema `2.0.0` and add optional fields; old consumers can ignore them. The source `patches.json` remains compatible with the existing queue/history workflow.
