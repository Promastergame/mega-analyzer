#![allow(missing_docs)]

use std::env;
use std::path::PathBuf;

fn main() {
    if env::var("CARGO_FEATURE_ZIG_RUNTIME").is_ok() {
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let zig_dir = manifest_dir.join("../../../zig");

        // Try to build the zig library automatically if zig is available
        let build_status = std::process::Command::new("zig")
            .args(["build", "-Doptimize=ReleaseFast"])
            .current_dir(&zig_dir)
            .status();

        match build_status {
            Ok(status) if status.success() => {
                let lib_path = zig_dir.join("zig-out").join("lib");
                println!("cargo:rustc-link-search=native={}", lib_path.display());
                println!("cargo:rustc-link-lib=static=omnisec-ml-runtime");
            }
            _ => {
                // Fallback: check if the library already exists
                let lib_path = zig_dir.join("zig-out").join("lib");
                if lib_path.exists() {
                    println!("cargo:rustc-link-search=native={}", lib_path.display());
                    println!("cargo:rustc-link-lib=static=omnisec-ml-runtime");
                } else {
                    println!(
                        "cargo:warning=Failed to build Zig runtime and no pre-built library found at {}. Fallback to pure Rust.",
                        lib_path.display()
                    );
                }
            }
        }
    }

    // Rerun if the feature or Zig runtime sources change.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_ZIG_RUNTIME");
    println!("cargo:rerun-if-changed=../../../zig/src/main.zig");
    println!("cargo:rerun-if-changed=../../../zig/src/spmv.zig");
    println!("cargo:rerun-if-changed=../../../zig/src/batch_inference.zig");
    println!("cargo:rerun-if-changed=../../../zig/build.zig");
}
