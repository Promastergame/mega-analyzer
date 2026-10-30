//! `nifshim` — a minimal, dependency-free replacement for the parts of
//! `rustler` this project actually uses.
//!
//! Design: keep the ABI-sensitive struct layouts (`ErlNifEntry`,
//! `ErlNifFunc`, `ErlNifBinary`, ...) entirely inside a small C file
//! that is compiled against the *real* `erl_nif.h` for the target
//! Erlang/OTP install (see `build.rs` + `helpers.c`). Rust only ever
//! touches simple, ABI-stable types: raw pointers, `usize`-sized
//! `ERL_NIF_TERM`, and fixed-width integers.
//!
//! No `rustler`, no `bindgen`, no proc-macros, no external crates.

#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_char, c_int};
use std::panic::{self, AssertUnwindSafe};

pub mod sys {
    use core::ffi::{c_int, c_void};

    /// Opaque `ErlNifEnv*`. We never read its fields directly — every
    /// operation on it goes through an `enif_*` call inside helpers.c.
    pub type ErlNifEnv = c_void;

    /// `ERL_NIF_TERM` is defined by erl_nif.h as an unsigned integer the
    /// same width as a native pointer (`UWord`), i.e. `usize`.
    pub type Term = usize;

    extern "C" {
        pub fn shim_get_binary(
            env: *mut ErlNifEnv,
            term: Term,
            out_data: *mut *const u8,
            out_len: *mut usize,
        ) -> c_int;
        pub fn shim_make_binary(env: *mut ErlNifEnv, data: *const u8, len: usize) -> Term;

        pub fn shim_get_u64(env: *mut ErlNifEnv, term: Term, out: *mut u64) -> c_int;
        pub fn shim_get_i64(env: *mut ErlNifEnv, term: Term, out: *mut i64) -> c_int;
        pub fn shim_get_u32(env: *mut ErlNifEnv, term: Term, out: *mut u32) -> c_int;
        pub fn shim_get_double(env: *mut ErlNifEnv, term: Term, out: *mut f64) -> c_int;

        pub fn shim_make_u64(env: *mut ErlNifEnv, v: u64) -> Term;
        pub fn shim_make_i64(env: *mut ErlNifEnv, v: i64) -> Term;
        pub fn shim_make_u32(env: *mut ErlNifEnv, v: u32) -> Term;
        pub fn shim_make_double(env: *mut ErlNifEnv, v: f64) -> Term;

        pub fn shim_make_atom(env: *mut ErlNifEnv, name: *const core::ffi::c_char) -> Term;
        pub fn shim_is_nil(env: *mut ErlNifEnv, term: Term) -> c_int;
        pub fn shim_get_bool(env: *mut ErlNifEnv, term: Term, out: *mut c_int) -> c_int;
        pub fn shim_make_bool(env: *mut ErlNifEnv, v: c_int) -> Term;

        pub fn shim_make_badarg(env: *mut ErlNifEnv) -> Term;

        pub fn shim_make_tuple2(env: *mut ErlNifEnv, a: Term, b: Term) -> Term;
    }
}

pub use sys::{ErlNifEnv, Term};

/// Raw pointer to the environment, threaded through every call.
pub type Env = *mut ErlNifEnv;

fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("atom/string must not contain NUL bytes")
}

// ===================================================================
// Decoding (Term -> Rust)
// ===================================================================

pub fn get_binary(env: Env, term: Term) -> Option<Vec<u8>> {
    unsafe {
        let mut data: *const u8 = std::ptr::null();
        let mut len: usize = 0;
        if sys::shim_get_binary(env, term, &mut data, &mut len) == 0 {
            return None;
        }
        Some(std::slice::from_raw_parts(data, len).to_vec())
    }
}

/// Rustler's default `String` decoder requires a binary term containing
/// valid UTF-8 — mirrored here exactly.
pub fn get_string(env: Env, term: Term) -> Option<String> {
    String::from_utf8(get_binary(env, term)?).ok()
}

pub fn get_u64(env: Env, term: Term) -> Option<u64> {
    unsafe {
        let mut v: u64 = 0;
        (sys::shim_get_u64(env, term, &mut v) != 0).then(|| v)
    }
}

pub fn get_i64(env: Env, term: Term) -> Option<i64> {
    unsafe {
        let mut v: i64 = 0;
        (sys::shim_get_i64(env, term, &mut v) != 0).then(|| v)
    }
}

pub fn get_u32(env: Env, term: Term) -> Option<u32> {
    unsafe {
        let mut v: u32 = 0;
        (sys::shim_get_u32(env, term, &mut v) != 0).then(|| v)
    }
}

pub fn get_usize(env: Env, term: Term) -> Option<usize> {
    get_u64(env, term).map(|v| v as usize)
}

pub fn get_f64(env: Env, term: Term) -> Option<f64> {
    unsafe {
        let mut v: f64 = 0.0;
        (sys::shim_get_double(env, term, &mut v) != 0).then(|| v)
    }
}

pub fn get_bool(env: Env, term: Term) -> Option<bool> {
    unsafe {
        let mut v: c_int = 0;
        (sys::shim_get_bool(env, term, &mut v) != 0).then(|| v != 0)
    }
}

pub fn is_nil(env: Env, term: Term) -> bool {
    unsafe { sys::shim_is_nil(env, term) != 0 }
}

/// Decodes `nil -> None`, anything else via the inner decoder.
pub fn get_option_u32(env: Env, term: Term) -> Option<Option<u32>> {
    if is_nil(env, term) {
        return Some(None);
    }
    get_u32(env, term).map(Some)
}

// ===================================================================
// Encoding (Rust -> Term)
// ===================================================================

pub fn make_binary(env: Env, data: &[u8]) -> Term {
    unsafe { sys::shim_make_binary(env, data.as_ptr(), data.len()) }
}

pub fn make_str(env: Env, s: &str) -> Term {
    make_binary(env, s.as_bytes())
}

pub fn make_u64(env: Env, v: u64) -> Term {
    unsafe { sys::shim_make_u64(env, v) }
}

pub fn make_i64(env: Env, v: i64) -> Term {
    unsafe { sys::shim_make_i64(env, v) }
}

pub fn make_usize(env: Env, v: usize) -> Term {
    make_u64(env, v as u64)
}

pub fn make_f64(env: Env, v: f64) -> Term {
    unsafe { sys::shim_make_double(env, v) }
}

pub fn make_bool(env: Env, v: bool) -> Term {
    unsafe { sys::shim_make_bool(env, if v { 1 } else { 0 }) }
}

pub fn make_atom(env: Env, name: &str) -> Term {
    let c = cstr(name);
    unsafe { sys::shim_make_atom(env, c.as_ptr() as *const c_char) }
}

pub fn make_ok(env: Env) -> Term {
    make_atom(env, "ok")
}

pub fn make_badarg(env: Env) -> Term {
    unsafe { sys::shim_make_badarg(env) }
}

pub fn make_tuple2(env: Env, a: Term, b: Term) -> Term {
    unsafe { sys::shim_make_tuple2(env, a, b) }
}

// ===================================================================
// Entry-point plumbing
// ===================================================================

/// Runs `body`, catching any Rust panic so it can never unwind across
/// the FFI boundary into the BEAM (which is undefined behavior).
/// A panic is converted into `enif_make_badarg`, matching the safety
/// guarantee `rustler` normally provides.
pub unsafe fn guard(env: Env, body: impl FnOnce() -> Term) -> Term {
    match panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(term) => term,
        Err(_) => make_badarg(env),
    }
}

/// Declares one raw, `#[no_mangle]` NIF entry point named `$raw_name`
/// (referenced from the crate's `entry.c`) with a fixed arity, wired to
/// a safe body closure over `$env` and the decoded `$args` slice.
///
/// Example:
/// ```ignore
/// nif_entry!(raw_health_check, 0, |env, _args| {
///     nifshim::make_ok(env)
/// });
/// ```
#[macro_export]
macro_rules! nif_entry {
    ($raw_name:ident, $arity:expr, |$env:ident, $args:ident| $body:block) => {
        #[no_mangle]
        pub unsafe extern "C" fn $raw_name(
            env: *mut $crate::ErlNifEnv,
            argc: std::os::raw::c_int,
            argv: *const $crate::Term,
        ) -> $crate::Term {
            $crate::guard(env, || {
                if argc as usize != $arity {
                    return $crate::make_badarg(env);
                }
                let $args: &[$crate::Term] = std::slice::from_raw_parts(argv, argc as usize);
                let $env: $crate::Env = env;
                $body
            })
        }
    };
}

/// Convenience: decode-or-badarg for use inside a `nif_entry!` body.
#[macro_export]
macro_rules! decode {
    ($env:expr, $opt:expr) => {
        match $opt {
            Some(v) => v,
            None => return $crate::make_badarg($env),
        }
    };
}
