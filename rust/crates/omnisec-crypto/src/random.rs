//! Cryptographic randomness from the operating system, without a weak fallback.

use std::io;

/// Fill a buffer with cryptographic randomness. An unavailable OS source is
/// an error; callers must not generate keys or nonces after such an error.
pub fn fill_os_random(bytes: &mut [u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    system_random(bytes)
}

/// Generate a fresh 256-bit seed for a cryptographic key.
pub fn entropy_seed() -> io::Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    fill_os_random(&mut seed)?;
    Ok(seed)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn system_random(bytes: &mut [u8]) -> io::Result<()> {
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
    for chunk in bytes.chunks_mut(u32::MAX as usize) {
        // SAFETY: the buffer is writable for the complete checked u32 length.
        // This flag requires a null algorithm handle and selects the OS CSPRNG.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(io::Error::other(format!(
                "BCryptGenRandom failed: {status:#x}"
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn system_random(bytes: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    // The OS CSPRNG on Linux, Android and macOS. read_exact handles short
    // reads and interruptions; failure propagates instead of using time/PID.
    std::fs::File::open("/dev/urandom")?.read_exact(bytes)
}

#[cfg(not(any(unix, windows)))]
fn system_random(_bytes: &mut [u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no OS CSPRNG on this target",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_random_fills_only_the_requested_slice() {
        let mut guarded = [0xa5; 66];
        fill_os_random(&mut guarded[1..65]).unwrap();
        assert_eq!(guarded[0], 0xa5);
        assert_eq!(guarded[65], 0xa5);
        assert_ne!(&guarded[1..65], &[0xa5; 64]);
        assert_ne!(entropy_seed().unwrap(), entropy_seed().unwrap());
        fill_os_random(&mut []).unwrap();
    }
}
