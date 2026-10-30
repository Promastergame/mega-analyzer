# Vendored `iced-x86` 1.21.0 (zero-dep fork)

Upstream: https://github.com/icedland/iced (crate `iced-x86`, version 1.21.0,
git `c50f29b7bc305696895c075f3fc7719751426b12`, path `src/rust/iced-x86`).
License: MIT — full upstream text in `LICENSE.txt` next to this file
(the `.crate` from the registry ships no license file; MIT requires the
copyright + permission notice to travel with substantial copies, so it is
vendored here verbatim).
Copied verbatim from the crates.io registry, then transformed exactly once:

- all 21 `lazy_static! { VIS static ref NAME: TYPE = INIT; }` blocks
  (19 files under `src/`) rewritten to
  `VIS static NAME: std::sync::LazyLock<TYPE> =
  std::sync::LazyLock::new(|| INIT);`
- 19 `use lazy_static::lazy_static;` lines removed;
- one `#![allow(clippy::let_unit_value)]` inner attribute dropped (it sat
  at the top of one init block; inner attributes on closure bodies are
  unstable — plain `cargo build` never fires that lint, only clippy would
  warn);
- `[dependencies.lazy_static]` removed from `Cargo.toml`,
  `std = ["lazy_static"]` → `std = []`, `no_std = [...]` → `no_std = []`.

`LazyLock` derefs to the table type, so every use site (`TABLES.*`,
`&*REGS_TBL`, …) compiles unchanged, with identical runtime semantics
(thread-safe one-time init). The vendored copy is **std-only** (nothing in
this workspace builds iced without `std`).

Wired in via `[patch.crates-io]` in `rust/Cargo.toml` and both
`server/native/*/Cargo.toml` workspaces.

## Re-applying on an upstream bump

1. Copy the new `iced-x86-X.Y.Z` registry dir over this one
   (keep this README and `lazylock_patch.py`).
2. Run `python third-party/iced-x86/lazylock_patch.py third-party/iced-x86`
   from the repo root (verified to reproduce this tree byte-for-byte from
   pristine 1.21.0), then re-apply the `Cargo.toml` cleanup below.
3. `cargo check --workspace` + `cargo test -p omnisec-disasm
   -p omnisec-emu-x86 -p omnisec-debugger` must stay green.
