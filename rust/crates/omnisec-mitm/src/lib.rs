#![allow(unsafe_code)]
#![allow(missing_docs)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, OnceLock};

pub mod capture;
pub mod cert;
pub mod dhcp;
pub mod dns;
pub mod obfs;
pub mod ssl;
pub mod tls;

use capture::MitmCapture;

/// Zero-dependency error alias replacing `anyhow::Result`.
///
/// `std::io::Error` is used as the generic error carrier so `?` on
/// `std::io` errors keeps working via `From`, while custom messages are
/// built with `std::io::Error::new(ErrorKind::Other, msg)`.
pub type MitmResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Spawn a blocking server loop on a detached thread.
///
/// Replaces the old `tokio::runtime::Runtime::spawn`: every MITM server is
/// a blocking std loop (one thread per listener, threads per connection),
/// so no async runtime is needed at all.
fn spawn_server(name: &'static str, f: impl FnOnce() -> MitmResult<()> + Send + 'static) {
    std::thread::spawn(move || {
        if let Err(e) = f() {
            omnisec_log::error!("{name} failed: {e}");
        }
    });
}

/// Shared accumulator for all live-capture data produced by the proxy runners
/// in this session. All three runners (SSL strip, DNS spoof, obfuscated proxy)
/// append their observations here so the Go side can call
/// `omnisec_mitm_take_capture` to drain real data instead of synthesizing
/// stand-ins.
static CAPTURE_STORE: OnceLock<Arc<Mutex<MitmCapture>>> = OnceLock::new();

fn capture_store() -> Arc<Mutex<MitmCapture>> {
    CAPTURE_STORE
        .get_or_init(|| Arc::new(Mutex::new(MitmCapture::default())))
        .clone()
}

const ERR_NULL_ARG: i32 = -1;
const ERR_RUNTIME: i32 = -2;
const ERR_PANIC: i32 = -3;

fn ffi_guard<F>(f: F) -> i32
where
    F: FnOnce() -> i32,
{
    if let Ok(code) = catch_unwind(AssertUnwindSafe(f)) {
        code
    } else {
        omnisec_log::error!("panic escaped Rust MITM FFI boundary");
        ERR_PANIC
    }
}

unsafe fn cstr_to_string(ptr: *const c_char) -> Result<String, i32> {
    if ptr.is_null() {
        return Err(ERR_NULL_ARG);
    }
    Ok(unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned())
}

/// Initializes the MITM module (logging and shared capture store).
///
/// Kept as a no-op for FFI compatibility: there is no async runtime to
/// start anymore (servers are blocking std threads). Always returns 0.
/// This must be called from Go before using any other MITM functions.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_mitm_init() -> i32 {
    ffi_guard(|| {
        // Touch the store so first-use initialization happens here,
        // inside the FFI guard, rather than on a server thread.
        let _ = capture_store();
        0
    })
}

/// Starts a DNS spoofing server.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_mitm_start_dns_spoof(
    listen_addr: *const c_char,
    target_domain: *const c_char,
    spoofed_ip: *const c_char,
) -> i32 {
    ffi_guard(|| {
        let addr = match unsafe { cstr_to_string(listen_addr) } {
            Ok(v) => v,
            Err(c) => return c,
        };
        let domain = match unsafe { cstr_to_string(target_domain) } {
            Ok(v) => v,
            Err(c) => return c,
        };
        let ip = match unsafe { cstr_to_string(spoofed_ip) } {
            Ok(v) => v,
            Err(c) => return c,
        };

        let sink = capture_store();
        spawn_server("DNS spoof server", move || {
            dns::run_dns_spoof_server(&addr, &domain, &ip, sink)
        });

        0
    })
}

/// Starts a rogue DHCP server.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_mitm_start_dhcp_spoof(
    listen_addr: *const c_char,
    gateway_ip: *const c_char,
) -> i32 {
    ffi_guard(|| {
        let addr = match unsafe { cstr_to_string(listen_addr) } {
            Ok(v) => v,
            Err(c) => return c,
        };
        let gateway = match unsafe { cstr_to_string(gateway_ip) } {
            Ok(v) => v,
            Err(c) => return c,
        };

        spawn_server("DHCP rogue server", move || {
            dhcp::run_rogue_dhcp_server(&addr, &gateway)
        });

        0
    })
}

/// Starts the SSL stripping HTTP proxy.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_mitm_start_ssl_strip(listen_addr: *const c_char) -> i32 {
    ffi_guard(|| {
        let addr = match unsafe { cstr_to_string(listen_addr) } {
            Ok(v) => v,
            Err(c) => return c,
        };

        let sink = capture_store();
        spawn_server("SSL strip proxy", move || {
            ssl::run_ssl_strip_proxy(&addr, sink)
        });

        0
    })
}

/// Generates a root CA certificate and private key, writing them to `out_dir`.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_mitm_generate_ca(out_dir: *const c_char) -> i32 {
    ffi_guard(|| {
        let dir = match unsafe { cstr_to_string(out_dir) } {
            Ok(v) => v,
            Err(c) => return c,
        };

        match ssl::ensure_root_ca(&dir) {
            Ok(()) => 0,
            Err(e) => {
                omnisec_log::error!("Failed to generate/load Root CA: {}", e);
                ERR_RUNTIME
            }
        }
    })
}

/// Starts the Obfuscated Proxy.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_mitm_start_obfs_proxy(
    listen_addr: *const c_char,
    upstream_addr: *const c_char,
    key_32: *const u8,
) -> i32 {
    ffi_guard(|| {
        if key_32.is_null() {
            return ERR_NULL_ARG;
        }

        let listen = match unsafe { cstr_to_string(listen_addr) } {
            Ok(v) => v,
            Err(c) => return c,
        };
        let upstream = match unsafe { cstr_to_string(upstream_addr) } {
            Ok(v) => v,
            Err(c) => return c,
        };

        let mut key = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(key_32, key.as_mut_ptr(), 32);
        }

        let sink = capture_store();
        spawn_server("Obfuscated proxy", move || {
            obfs::run_obfuscated_proxy(&listen, &upstream, key, sink)
        });

        0
    })
}

/// Drains the shared live-capture accumulator and returns its contents as a
/// JSON C string (UTF-8, NUL-terminated). The store is reset to an empty
/// `MitmCapture` after draining so subsequent calls return only new data.
///
/// Returns NULL on serialisation failure or if the store mutex is poisoned.
/// The caller must free the returned string with `omnisec_mitm_free_str`.
#[unsafe(no_mangle)]
pub extern "C" fn omnisec_mitm_take_capture() -> *mut c_char {
    let result: Result<*mut c_char, ()> = catch_unwind(AssertUnwindSafe(|| {
        let store = capture_store();
        let mut guard = store.lock().map_err(|_| ())?;
        let drained = std::mem::take(&mut *guard);
        drop(guard);
        let json = omnisec_json::to_json_string(&drained);
        CString::new(json).map(CString::into_raw).map_err(|_| ())
    }))
    .unwrap_or(Err(()));

    result.unwrap_or(std::ptr::null_mut())
}

/// Frees a C string returned by `omnisec_mitm_take_capture`.
///
/// # Safety
/// `ptr` must be a non-null pointer previously returned by
/// `omnisec_mitm_take_capture` and must not be freed more than once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_mitm_free_str(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}
