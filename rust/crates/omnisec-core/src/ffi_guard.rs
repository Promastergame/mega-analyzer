//! Panic containment for the C-ABI boundary.
//!
//! Every `extern "C"` entry point that receives untrusted bytes must run
//! its payload through [`catch_panic`]. A panic escaping across the FFI
//! boundary is undefined behaviour in the best case and, with the release
//! profile built for unwinding, aborts the host process (the Go analyzer
//! and the API server die with it) in the common one. Guarded calls
//! degrade to the function's documented empty/error result instead.

/// Runs `body` under [`std::panic::catch_unwind`].
///
/// Returns `Some(result)` on success. On panic, invokes `on_panic()` —
/// which should write the function's empty/error result — and returns
/// `None`. The panic payload is discarded: the Go side only sees the
/// contractual failure shape, and panics carry no deliverable data.
pub fn catch_panic<R, F: FnOnce() -> R>(body: F, on_panic: impl FnOnce()) -> Option<R> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(result) => Some(result),
        Err(_payload) => {
            on_panic();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::catch_panic;

    #[test]
    fn returns_body_result() {
        let out = catch_panic(|| 7u32, || panic!("must not run"));
        assert_eq!(out, Some(7));
    }

    #[test]
    fn invokes_on_panic_and_returns_none() {
        let mut notified = false;
        let out = catch_panic(
            || panic!("crafted input"),
            || {
                notified = true;
            },
        );
        assert!(out.is_none());
        assert!(notified);
    }
}
