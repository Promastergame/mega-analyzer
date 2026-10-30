# Hermes instruction definitions

The generated file hermes_opcodes_generated.go is derived from the official
[facebook/hermes](https://github.com/facebook/hermes) BytecodeList.def.
The manifest pins every source revision and SHA-256 digest, including the
matching BytecodeFileFormat.h. MIT attribution is retained in LICENSE.

Regenerate using Python 3 and Go:

    python scripts/generate_hermes_tables.py --source-dir <source directory>

Download each manifest revision's include/hermes/BCGen/HBC/BytecodeList.def
and BytecodeFileFormat.h into that directory as v<VERSION>-<filename>.
The generator rejects modified inputs. Jump macros expand to separate short
and long instructions. Optional HERMES_RUN_WASM instructions are excluded:
they are not part of React Native HBC and are reported as unsupported opcodes.
The missing upstream CallDirectLongIndex annotation is filled from its
documented third operand, a function index.

Supported versions are enumerated explicitly; absent versions are never
interpreted using a nearby version's layout. Versions 97–98 use 12-byte compact
function headers; 99–100 change bit widths and large-header offsets again.
Version 100 is supported for the exact pinned revision (upstream later
reverted that version bump).

Coverage describes string tables, function headers and instruction decoding.
Call edges prove static call sites, not runtime reachability. Register calls
remain unresolved; closure construction is a function reference, not a call.
