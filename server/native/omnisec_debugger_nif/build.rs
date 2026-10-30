//! Compiles `src/entry.c`, which builds the `ErlNifEntry` NIF table for
//! this crate (`omnisec_debugger_nif`) using the real `erl_nif.h`, and
//! declares `extern` prototypes for the raw NIF functions implemented
//! in `src/lib.rs` (via `nifshim::nif_entry!`).
//!
//! Mirrors `native/nifshim/build.rs`'s erts/cc discovery so this crate
//! has zero build-dependencies of its own.

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
        .unwrap_or_else(|e| panic!("failed to run `{erl}` to locate erl_nif.h ({e})"));
    if !output.status.success() {
        panic!(
            "`{erl}` failed while locating erl_nif.h:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn find_cc() -> String {
    env::var("CC").unwrap_or_else(|_| {
        for c in ["cc", "gcc", "clang"] {
            if Command::new(c).arg("--version").output().is_ok() {
                return c.to_string();
            }
        }
        panic!("no C compiler found on PATH");
    })
}

fn main() {
    let include_dir = find_erts_include_dir();
    let cc = find_cc();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest.join("src/entry.c");
    let obj = out_dir.join("entry.o");
    let lib_path = out_dir.join("libomnisec_debugger_entry.a");

    println!("cargo:rerun-if-changed=src/entry.c");

    let status = Command::new(&cc)
        .args(["-c", "-O2", "-fPIC"])
        .arg("-I")
        .arg(&include_dir)
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("failed to invoke C compiler");
    assert!(status.success(), "C compiler failed to build entry.c");

    let ar = env::var("AR").unwrap_or_else(|_| "ar".to_string());
    let status = Command::new(&ar)
        .args(["rcs"])
        .arg(&lib_path)
        .arg(&obj)
        .status()
        .expect("failed to invoke `ar`");
    assert!(status.success(), "`ar` failed to package entry.o");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=omnisec_debugger_entry");
}
