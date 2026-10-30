#![allow(unsafe_code)]
#![allow(missing_docs)]
#![allow(unused_imports)]

//! Heavy symbolic-execution worker (Z3) — dependency-free NIF bridge.
//!
//! NIF plumbing (arg decoding/encoding, dirty-scheduler flag, the
//! `ErlNifEntry` table) is provided by the local zero-dependency
//! `nifshim` crate instead of `rustler` — see `native/nifshim` and
//! `src/entry.c`. Business logic below (loading libz3 dynamically via
//! an in-house `dynload` module and driving its C API) is unchanged
//! from the original.

use nifshim::{Env, Term, decode, nif_entry};
use std::ffi::{CStr, CString, c_void};
use std::os::raw::{c_char, c_uint};

// Z3 Types
type Z3Config = c_void;
type Z3Context = c_void;
type Z3Solver = c_void;
type Z3Ast = c_void;
type Z3AstVector = c_void;

const Z3_L_FALSE: i32 = -1;
#[allow(dead_code)]
const Z3_L_UNDEF: i32 = 0;
const Z3_L_TRUE: i32 = 1;

// Z3 API Signatures
type Z3GlobalParamSetFn = unsafe extern "C" fn(param_id: *const c_char, param_value: *const c_char);
type Z3SetErrorHandlerFn =
    unsafe extern "C" fn(ctx: *mut Z3Context, h: Option<extern "C" fn(*mut Z3Context, c_uint)>);
type Z3MkConfigFn = unsafe extern "C" fn() -> *mut Z3Config;
type Z3DelConfigFn = unsafe extern "C" fn(cfg: *mut Z3Config);
type Z3MkContextFn = unsafe extern "C" fn(cfg: *mut Z3Config) -> *mut Z3Context;
type Z3DelContextFn = unsafe extern "C" fn(ctx: *mut Z3Context);
type Z3MkSolverFn = unsafe extern "C" fn(ctx: *mut Z3Context) -> *mut Z3Solver;
type Z3SolverIncRefFn = unsafe extern "C" fn(ctx: *mut Z3Context, s: *mut Z3Solver);
type Z3SolverDecRefFn = unsafe extern "C" fn(ctx: *mut Z3Context, s: *mut Z3Solver);
type Z3SolverAssertFn = unsafe extern "C" fn(ctx: *mut Z3Context, s: *mut Z3Solver, a: *mut Z3Ast);
type Z3SolverCheckFn = unsafe extern "C" fn(ctx: *mut Z3Context, s: *mut Z3Solver) -> i32;
type Z3ParseSmtlib2StringFn = unsafe extern "C" fn(
    ctx: *mut Z3Context,
    str: *const c_char,
    num_sorts: c_uint,
    sort_names: *const *mut c_void,
    sorts: *const *mut c_void,
    num_decls: c_uint,
    decl_names: *const *mut c_void,
    decls: *const *mut c_void,
) -> *mut Z3AstVector;
type Z3AstVectorSizeFn = unsafe extern "C" fn(ctx: *mut Z3Context, v: *mut Z3AstVector) -> c_uint;
type Z3AstVectorGetFn =
    unsafe extern "C" fn(ctx: *mut Z3Context, v: *mut Z3AstVector, i: c_uint) -> *mut Z3Ast;
type Z3AstVectorIncRefFn = unsafe extern "C" fn(ctx: *mut Z3Context, v: *mut Z3AstVector);
type Z3AstVectorDecRefFn = unsafe extern "C" fn(ctx: *mut Z3Context, v: *mut Z3AstVector);
#[allow(dead_code)]
type Z3GetErrorMsgFn = unsafe extern "C" fn(ctx: *mut Z3Context, err: c_uint) -> *const c_char;
type Z3SolverGetReasonUnknownFn =
    unsafe extern "C" fn(ctx: *mut Z3Context, s: *mut Z3Solver) -> *const c_char;

// Custom error handler to prevent Z3 from calling exit(1).
extern "C" fn z3_error_handler(_ctx: *mut Z3Context, _err: c_uint) {
    // Intentionally empty — suppresses Z3's default exit(1) on error.
}

/// Zero-dependency dynamic library loader replacing `libloading`.
///
/// Only `open` + `symbol lookup` + `close-on-drop` are needed for the Z3
/// C API, so this implements exactly that on top of `kernel32` (Windows)
/// and `dlopen` (Unix), std-only.
mod dynload {
    use super::{CString, c_char, c_void};

    #[cfg(windows)]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryA(name: *const c_char) -> *mut c_void;
        fn GetProcAddress(handle: *mut c_void, name: *const c_char) -> *mut c_void;
        fn FreeLibrary(handle: *mut c_void) -> i32;
    }

    #[cfg(unix)]
    #[cfg_attr(target_os = "linux", link(name = "dl"))]
    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flag: i32) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> i32;
    }

    #[cfg(unix)]
    const RTLD_NOW: i32 = 2;

    pub struct DynLib {
        handle: *mut c_void,
    }

    impl DynLib {
        /// Opens `path`. Mirrors `libloading::Library::new`.
        ///
        /// # Safety
        /// `path` is passed to the OS loader; the returned handle must stay
        /// alive while any looked-up symbol is called (guaranteed here: `lib`
        /// outlives all calls in `solve_opaque_predicate_impl`).
        pub unsafe fn open(path: &str) -> Result<Self, String> {
            let c_path = CString::new(path).map_err(|e| format!("invalid library path: {e}"))?;
            // SAFETY: `c_path` is a valid NUL-terminated string.
            let handle = unsafe {
                #[cfg(windows)]
                {
                    LoadLibraryA(c_path.as_ptr())
                }
                #[cfg(unix)]
                {
                    dlopen(c_path.as_ptr(), RTLD_NOW)
                }
            };
            if handle.is_null() {
                Err(format!("failed to load dynamic library: {path}"))
            } else {
                Ok(Self { handle })
            }
        }

        /// Looks up `symbol` (NUL-terminated byte string like `b"Z3_mk_config"`).
        ///
        /// # Safety
        /// Caller must ensure `T` matches the real symbol type.
        pub unsafe fn get<T>(&self, symbol: &[u8]) -> Result<T, String> {
            // `libloading` accepts `b"name"` without the trailing NUL; the OS
            // APIs require it, so append it here.
            let mut name = Vec::with_capacity(symbol.len() + 1);
            name.extend_from_slice(symbol);
            name.push(0);
            // SAFETY: `name` is NUL-terminated; handle is a valid open library.
            let ptr = unsafe {
                #[cfg(windows)]
                {
                    GetProcAddress(self.handle, name.as_ptr() as *const c_char)
                }
                #[cfg(unix)]
                {
                    dlsym(self.handle, name.as_ptr() as *const c_char)
                }
            };
            if ptr.is_null() {
                let s = String::from_utf8_lossy(symbol).into_owned();
                return Err(format!("missing symbol in dynamic library: {s}"));
            }
            // SAFETY: function pointers and data pointers share the address
            // space on all supported targets; `T` is a `fn` pointer type.
            Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&ptr) })
        }
    }

    impl Drop for DynLib {
        fn drop(&mut self) {
            // SAFETY: handle came from a successful `open` and is closed once.
            unsafe {
                #[cfg(windows)]
                {
                    FreeLibrary(self.handle);
                }
                #[cfg(unix)]
                {
                    dlclose(self.handle);
                }
            }
        }
    }
}

use dynload::DynLib;

/// Result of the SMT-LIB2 satisfiability check, in a shape that maps
/// 1:1 onto what the original NIF encoded (atom or 2-tuple of atoms /
/// atom+string).
enum SolveOutcome {
    Sat,
    Unsat,
    UnknownPlain,
    UnknownTimeout,
    UnknownReason(String),
    ErrorInvalidExpr,
}

fn solve_opaque_predicate_impl(smtlib2_expr: String) -> Result<SolveOutcome, String> {
    unsafe {
        let lib = DynLib::open("priv/native/libz3.dll")
            .or_else(|_| DynLib::open("libz3.dll"))
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;

        let z3_global_param_set: Z3GlobalParamSetFn = lib
            .get(b"Z3_global_param_set")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_set_error_handler: Z3SetErrorHandlerFn = lib
            .get(b"Z3_set_error_handler")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_mk_config: Z3MkConfigFn = lib
            .get(b"Z3_mk_config")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_del_config: Z3DelConfigFn = lib
            .get(b"Z3_del_config")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_mk_context: Z3MkContextFn = lib
            .get(b"Z3_mk_context")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_del_context: Z3DelContextFn = lib
            .get(b"Z3_del_context")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_mk_solver: Z3MkSolverFn = lib
            .get(b"Z3_mk_solver")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_solver_inc_ref: Z3SolverIncRefFn = lib
            .get(b"Z3_solver_inc_ref")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_solver_dec_ref: Z3SolverDecRefFn = lib
            .get(b"Z3_solver_dec_ref")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_solver_assert: Z3SolverAssertFn = lib
            .get(b"Z3_solver_assert")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_solver_check: Z3SolverCheckFn = lib
            .get(b"Z3_solver_check")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_parse_smtlib2_string: Z3ParseSmtlib2StringFn =
            lib.get(b"Z3_parse_smtlib2_string")
                .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_ast_vector_size: Z3AstVectorSizeFn = lib
            .get(b"Z3_ast_vector_size")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_ast_vector_get: Z3AstVectorGetFn = lib
            .get(b"Z3_ast_vector_get")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_ast_vector_inc_ref: Z3AstVectorIncRefFn = lib
            .get(b"Z3_ast_vector_inc_ref")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_ast_vector_dec_ref: Z3AstVectorDecRefFn = lib
            .get(b"Z3_ast_vector_dec_ref")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;
        let z3_solver_get_reason_unknown: Z3SolverGetReasonUnknownFn = lib
            .get(b"Z3_solver_get_reason_unknown")
            .map_err(|e| format!("Failed to load libz3.dll: {e}"))?;

        // Global timeout (2000 ms) to prevent BEAM hangs.
        let param_id = CString::new("timeout").unwrap();
        let param_val = CString::new("2000").unwrap();
        z3_global_param_set(param_id.as_ptr(), param_val.as_ptr());

        let cfg = z3_mk_config();
        let ctx = z3_mk_context(cfg);
        z3_set_error_handler(ctx, Some(z3_error_handler));

        let solver = z3_mk_solver(ctx);
        z3_solver_inc_ref(ctx, solver);

        let expr_c_str = if let Ok(s) = CString::new(smtlib2_expr) {
            s
        } else {
            z3_solver_dec_ref(ctx, solver);
            z3_del_context(ctx);
            z3_del_config(cfg);
            return Ok(SolveOutcome::ErrorInvalidExpr);
        };

        let ast_vector = z3_parse_smtlib2_string(
            ctx,
            expr_c_str.as_ptr(),
            0,
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        );

        if ast_vector.is_null() {
            z3_solver_dec_ref(ctx, solver);
            z3_del_context(ctx);
            z3_del_config(cfg);
            return Ok(SolveOutcome::ErrorInvalidExpr);
        }

        z3_ast_vector_inc_ref(ctx, ast_vector);

        let size = z3_ast_vector_size(ctx, ast_vector);
        for i in 0..size {
            let ast = z3_ast_vector_get(ctx, ast_vector, i);
            z3_solver_assert(ctx, solver, ast);
        }

        let result = z3_solver_check(ctx, solver);

        let outcome = match result {
            Z3_L_TRUE => SolveOutcome::Sat,
            Z3_L_FALSE => SolveOutcome::Unsat,
            _ => {
                let reason_ptr = z3_solver_get_reason_unknown(ctx, solver);
                if reason_ptr.is_null() {
                    SolveOutcome::UnknownPlain
                } else {
                    let reason_str = CStr::from_ptr(reason_ptr).to_string_lossy().into_owned();
                    if reason_str.contains("canceled") || reason_str.contains("timeout") {
                        SolveOutcome::UnknownTimeout
                    } else {
                        SolveOutcome::UnknownReason(reason_str)
                    }
                }
            }
        };

        z3_ast_vector_dec_ref(ctx, ast_vector);
        z3_solver_dec_ref(ctx, solver);
        z3_del_context(ctx);
        z3_del_config(cfg);

        Ok(outcome)
    }
}

fn encode_outcome(env: Env, outcome: SolveOutcome) -> Term {
    match outcome {
        SolveOutcome::Sat => nifshim::make_atom(env, "sat"),
        SolveOutcome::Unsat => nifshim::make_atom(env, "unsat"),
        SolveOutcome::UnknownPlain => nifshim::make_atom(env, "unknown"),
        SolveOutcome::UnknownTimeout => nifshim::make_tuple2(
            env,
            nifshim::make_atom(env, "unknown"),
            nifshim::make_atom(env, "timeout"),
        ),
        SolveOutcome::UnknownReason(reason) => nifshim::make_tuple2(
            env,
            nifshim::make_atom(env, "unknown"),
            nifshim::make_str(env, &reason),
        ),
        SolveOutcome::ErrorInvalidExpr => nifshim::make_tuple2(
            env,
            nifshim::make_atom(env, "error"),
            nifshim::make_atom(env, "invalid_expr"),
        ),
    }
}

// Export `nif_init` directly from Rust so rustc's cdylib linker driver
// includes `nif_init` in the dynamic export table (.dynsym on Linux / export table on PE/Mach-O).
// It delegates to `c_nif_init` generated by `ERL_NIF_INIT` in `entry.c`.
#[cfg(windows)]
unsafe extern "C" {
    fn c_nif_init(callbacks: *mut core::ffi::c_void) -> *const core::ffi::c_void;
}
#[cfg(not(windows))]
unsafe extern "C" {
    fn c_nif_init() -> *const core::ffi::c_void;
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nif_init(callbacks: *mut core::ffi::c_void) -> *const core::ffi::c_void {
    unsafe { c_nif_init(callbacks) }
}

#[cfg(not(windows))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nif_init() -> *const core::ffi::c_void {
    unsafe { c_nif_init() }
}

nif_entry!(raw_solve_opaque_predicate, 1, |env, args| {
    let smtlib2_expr = decode!(env, nifshim::get_string(env, args[0]));
    match solve_opaque_predicate_impl(smtlib2_expr) {
        Ok(outcome) => encode_outcome(env, outcome),
        Err(msg) => nifshim::make_tuple2(
            env,
            nifshim::make_atom(env, "error"),
            nifshim::make_str(env, &msg),
        ),
    }
});
