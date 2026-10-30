//! Small shared helpers used across probe modules.
//!
//! Historically `base_symbol_name` was copy-pasted into both `vulns` and
//! `malware`. Keeping a single definition here removes the drift risk and
//! gives us one place to extend symbol-name normalisation.

/// Strip an ELF symbol-versioning suffix so rule tables can match the base
/// name.
///
/// `strcpy@@GLIBC_2.17` -> `strcpy`, `system@LIBC` -> `system`,
/// `plain_name` -> `plain_name`.
#[must_use]
pub(crate) fn base_symbol_name(name: &str) -> &str {
    name.split_once('@').map_or(name, |(base, _)| base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_versioning_suffix() {
        assert_eq!(base_symbol_name("strcpy@@GLIBC_2.17"), "strcpy");
        assert_eq!(base_symbol_name("system@LIBC"), "system");
        assert_eq!(base_symbol_name("plain"), "plain");
    }
}
