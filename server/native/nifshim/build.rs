//! Build script for `nifshim`.
//!
//! We compile a tiny C helper file (`src/helpers.c`) against the *real*
//! `erl_nif.h` header shipped with the Erlang/OTP installation that will
//! run this NIF. Using the real header (instead of hand-copied Rust
//! struct definitions, or bindgen) is what makes this ABI-safe across
//! OTP versions without adding a single external crate dependency.
//!
//! Discovery order for the erts include dir:
//!   1. `ERTS_INCLUDE_DIR` env var (explicit override).
//!   2. `erl -eval` query against the `erl` on PATH.
//!
//! Discovery order for the C compiler:
//!   1. `CC` env var.
//!   2. `cc`, then `gcc`, then `clang` on PATH.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn find_erts_include_dir() -> PathBuf {
    if let Ok(dir) = env::var("ERTS_INCLUDE_DIR") {
        return PathBuf::from(dir);
    }

    let erl = env::var("ERL_PATH").unwrap_or_else(|_| "erl".to_string());
    let script =
        "io:format(\"~s\", [filename:join([code:root_dir(), \"erts-\" ++ erlang:system_info(version), \"include\"])]), halt().";

    let output = Command::new(&erl)
        .args(["-noshell", "-eval", script])
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "nifshim: failed to run `{erl}` to locate erl_nif.h ({e}). \
                 Set ERTS_INCLUDE_DIR explicitly to the erts-X.Y/include directory."
            )
        });

    if !output.status.success() {
        panic!(
            "nifshim: `{erl}` exited with an error while locating erl_nif.h:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let path = PathBuf::from(path);
    if !path.join("erl_nif.h").exists() {
        panic!(
            "nifshim: erl_nif.h not found at {:?}. Set ERTS_INCLUDE_DIR explicitly.",
            path
        );
    }
    path
}

fn find_cc() -> String {
    if let Ok(cc) = env::var("CC") {
        return cc;
    }
    for candidate in ["cc", "gcc", "clang"] {
        if Command::new(candidate).arg("--version").output().is_ok() {
            return candidate.to_string();
        }
    }
    panic!("nifshim: no C compiler found on PATH (looked for cc, gcc, clang). Set CC explicitly.");
}

fn main() {
    let include_dir = find_erts_include_dir();
    let cc = find_cc();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/helpers.c");
    let obj = out_dir.join("nifshim_helpers.o");
    let lib_path = out_dir.join("libnifshim_helpers.a");

    println!("cargo:rerun-if-changed=src/helpers.c");
    println!("cargo:rerun-if-env-changed=ERTS_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=ERL_PATH");
    println!("cargo:rerun-if-env-changed=CC");

    let status = Command::new(&cc)
        .arg("-c")
        .arg("-O2")
        .arg("-fPIC")
        .arg("-I")
        .arg(&include_dir)
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("nifshim: failed to invoke C compiler");
    if !status.success() {
        panic!("nifshim: C compiler failed to build helpers.c");
    }

    let ar = env::var("AR").unwrap_or_else(|_| "ar".to_string());
    let status = Command::new(&ar)
        .arg("rcs")
        .arg(&lib_path)
        .arg(&obj)
        .status()
        .expect("nifshim: failed to invoke `ar`");
    if !status.success() {
        panic!("nifshim: `ar` failed to package helpers.o");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=nifshim_helpers");
    // Export the include dir so leaf crates' own build.rs (entry.c) can reuse it.
    println!("cargo:erts_include_dir={}", include_dir.display());
}
