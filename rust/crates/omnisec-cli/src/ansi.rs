//! Minimal ANSI helper. Replaces `owo-colors` and `console`.
//!
//! Why a 60-line module instead of a published crate:
//!
//!   * we only ever need foreground colour, bold, underline, dimmed.
//!   * we only target VT-capable terminals (Windows 10+ enables ANSI by
//!     default since 2019; pre-2019 PowerShell users lose colour, which is
//!     fine — text remains readable).
//!   * `owo-colors` brings ~25 KB of generic-heavy code; ours adds ~0.
//!
//! Convention: every helper is a *value* `Styled<'_>`, not a trait. Calls
//! like `s.red().bold()` chain by re-wrapping. The final `Display` impl
//! emits the SGR sequence, the payload, and the reset.

use std::fmt;

/// Set Graphics Rendition codes. Match real ANSI numbers so the constants
/// double as documentation.
#[derive(Clone, Copy, Default)]
pub struct Sgr {
    pub fg: Option<u8>,  // 30..37 / 90..97
    pub bold: bool,      // 1
    pub dim: bool,       // 2
    pub underline: bool, // 4
}

impl Sgr {
    /// Compose two SGR specs. RHS overrides LHS where both set.
    fn combine(self, other: Sgr) -> Sgr {
        Sgr {
            fg: other.fg.or(self.fg),
            bold: self.bold || other.bold,
            dim: self.dim || other.dim,
            underline: self.underline || other.underline,
        }
    }

    fn write_open(self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Skip emitting any escape if there is nothing to render. Keeps
        // tests / piped output clean.
        if self.fg.is_none() && !self.bold && !self.dim && !self.underline {
            return Ok(());
        }
        f.write_str("\x1b[")?;
        let mut first = true;
        let sep = |f: &mut fmt::Formatter<'_>, first: &mut bool| -> fmt::Result {
            if !*first {
                f.write_str(";")?;
            }
            *first = false;
            Ok(())
        };
        if self.bold {
            sep(f, &mut first)?;
            f.write_str("1")?;
        }
        if self.dim {
            sep(f, &mut first)?;
            f.write_str("2")?;
        }
        if self.underline {
            sep(f, &mut first)?;
            f.write_str("4")?;
        }
        if let Some(c) = self.fg {
            sep(f, &mut first)?;
            write!(f, "{c}")?;
        }
        f.write_str("m")
    }

    fn write_close(self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.fg.is_some() || self.bold || self.dim || self.underline {
            f.write_str("\x1b[0m")?;
        }
        Ok(())
    }
}

/// Wrapped reference + style. Cheap to construct, allocation-free.
pub struct Styled<'a, T: ?Sized> {
    inner: &'a T,
    sgr: Sgr,
}

impl<T: fmt::Display + ?Sized> Styled<'_, T> {
    fn map(mut self, f: impl FnOnce(&mut Sgr)) -> Self {
        f(&mut self.sgr);
        self
    }

    /// Foreground colors (30–37 normal, 90–97 bright).
    pub fn fg(self, code: u8) -> Self {
        self.map(|s| s.fg = Some(code))
    }
    pub fn bold(self) -> Self {
        self.map(|s| s.bold = true)
    }
    pub fn dim(self) -> Self {
        self.map(|s| s.dim = true)
    }
    pub fn underline(self) -> Self {
        self.map(|s| s.underline = true)
    }

    pub fn red(self) -> Self {
        self.fg(31)
    }
    pub fn green(self) -> Self {
        self.fg(32)
    }
    pub fn yellow(self) -> Self {
        self.fg(33)
    }
    pub fn cyan(self) -> Self {
        self.fg(36)
    }
    pub fn white(self) -> Self {
        self.fg(37)
    }
    pub fn bright_green(self) -> Self {
        self.fg(92)
    }
    pub fn bright_yellow(self) -> Self {
        self.fg(93)
    }
    pub fn bright_cyan(self) -> Self {
        self.fg(96)
    }
    pub fn bright_white(self) -> Self {
        self.fg(97)
    }
    pub fn dimmed(self) -> Self {
        self.dim()
    }

    /// Apply a precomputed style. Used by tables of (label, style) pairs.
    pub fn style(self, style: Sgr) -> Self {
        self.map(|s| *s = s.combine(style))
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for Styled<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.sgr.write_open(f)?;
        fmt::Display::fmt(&self.inner, f)?;
        self.sgr.write_close(f)
    }
}

/// Trait that adds the `.red() / .bold() / ...` chain to any `Display`able.
///
/// Mirrors the shape of `owo_colors::OwoColorize` so the cli display code
/// keeps reading the same way after the dependency switch.
pub trait Stylize {
    fn red(&self) -> Styled<'_, Self>;
    fn green(&self) -> Styled<'_, Self>;
    fn yellow(&self) -> Styled<'_, Self>;
    fn cyan(&self) -> Styled<'_, Self>;
    fn white(&self) -> Styled<'_, Self>;
    fn bright_green(&self) -> Styled<'_, Self>;
    fn bright_yellow(&self) -> Styled<'_, Self>;
    fn bright_cyan(&self) -> Styled<'_, Self>;
    fn bright_white(&self) -> Styled<'_, Self>;
    fn bold(&self) -> Styled<'_, Self>;
    fn dimmed(&self) -> Styled<'_, Self>;
    fn underline(&self) -> Styled<'_, Self>;
    fn style(&self, s: Sgr) -> Styled<'_, Self>;
}

impl<T: fmt::Display + ?Sized> Stylize for T {
    fn red(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .red()
    }
    fn green(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .green()
    }
    fn yellow(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .yellow()
    }
    fn cyan(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .cyan()
    }
    fn white(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .white()
    }
    fn bright_green(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .bright_green()
    }
    fn bright_yellow(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .bright_yellow()
    }
    fn bright_cyan(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .bright_cyan()
    }
    fn bright_white(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .bright_white()
    }
    fn bold(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .bold()
    }
    fn dimmed(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .dimmed()
    }
    fn underline(&self) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: Sgr::default(),
        }
        .underline()
    }
    fn style(&self, s: Sgr) -> Styled<'_, Self> {
        Styled {
            inner: self,
            sgr: s,
        }
    }
}

/// Helpers for building reusable Sgr values, mirroring `owo_colors::Style`.
pub mod styles {
    use super::Sgr;

    pub const fn new() -> Sgr {
        Sgr {
            fg: None,
            bold: false,
            dim: false,
            underline: false,
        }
    }
    pub const fn red() -> Sgr {
        Sgr {
            fg: Some(31),
            ..new()
        }
    }
    pub const fn green() -> Sgr {
        Sgr {
            fg: Some(32),
            ..new()
        }
    }
    pub const fn yellow() -> Sgr {
        Sgr {
            fg: Some(33),
            ..new()
        }
    }
    pub const fn bright_green() -> Sgr {
        Sgr {
            fg: Some(92),
            ..new()
        }
    }
    pub const fn red_bold() -> Sgr {
        Sgr {
            fg: Some(31),
            bold: true,
            dim: false,
            underline: false,
        }
    }
    pub const fn dimmed() -> Sgr {
        Sgr {
            fg: None,
            bold: false,
            dim: true,
            underline: false,
        }
    }
    pub const fn bold() -> Sgr {
        Sgr {
            fg: None,
            bold: true,
            dim: false,
            underline: false,
        }
    }
}
