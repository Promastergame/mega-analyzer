//! Zero-dependency JSON value, parser and serializer (replaces `serde_json`).
//!
//! - [`JsonValue`] keeps object insertion order (like `omnisec_json::Map`).
//! - [`parse`] / [`parse_slice`] implement a full recursive-descent parser.
//! - [`to_string`] / [`to_string_pretty`] serialize deterministically.
//! - [`json!`] macro mirrors `omnisec_json::json!` for call-site migration.
//! - [`ToJson`] / [`FromJson`] are tiny conversion traits replacing
//!   `Serialize` / `Deserialize` derives (manual impls per type).
//! - [`b64_encode`] / [`b64_decode`], [`hex_lower`] cover the custom
//!   `serde(with=...)` helpers (`flow.rs` byte streams).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub use omnisec_json_derive::{FromJson, ToJson};

/// JSON error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError(pub String);

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "json error: {}", self.0)
    }
}

impl std::error::Error for JsonError {}

/// Convenience alias mirroring `serde_json::Result`.
pub type JsonResult<T> = std::result::Result<T, JsonError>;

impl From<std::num::ParseFloatError> for JsonError {
    fn from(e: std::num::ParseFloatError) -> Self {
        Self(e.to_string())
    }
}

impl From<std::num::ParseIntError> for JsonError {
    fn from(e: std::num::ParseIntError) -> Self {
        Self(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for JsonError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self(e.to_string())
    }
}

/// Owned JSON value with insertion-ordered objects.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// null.
    Null,
    /// boolean.
    Bool(bool),
    /// signed integer.
    Int(i64),
    /// unsigned integer.
    UInt(u64),
    /// floating point.
    Float(f64),
    /// string.
    Str(String),
    /// array.
    Array(Vec<JsonValue>),
    /// object (insertion order).
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// null value.
    #[must_use]
    pub const fn null() -> Self {
        Self::Null
    }
    /// `true` if null.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    /// Borrow as str.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if let Self::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    /// Borrow as bool.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
    /// As i64 (ints, uint if fits, float truncation).
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::UInt(u) => i64::try_from(*u).ok(),
            Self::Float(f) => Some(*f as i64),
            _ => None,
        }
    }
    /// As u64.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::UInt(u) => Some(*u),
            Self::Int(i) => u64::try_from(*i).ok(),
            Self::Float(f) => Some(*f as u64),
            _ => None,
        }
    }
    /// As f64.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            Self::Int(i) => Some(*i as f64),
            Self::UInt(u) => Some(*u as f64),
            _ => None,
        }
    }
    /// Borrow as array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[JsonValue]> {
        if let Self::Array(a) = self {
            Some(a)
        } else {
            None
        }
    }
    /// Borrow as object entries.
    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        if let Self::Object(o) = self {
            Some(o)
        } else {
            None
        }
    }
    /// Object lookup by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        if let Self::Object(o) = self {
            o.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }
    /// Array index.
    #[must_use]
    pub fn index(&self, i: usize) -> Option<&JsonValue> {
        if let Self::Array(a) = self {
            a.get(i)
        } else {
            None
        }
    }

    /// `true` if this is an array (serde_json-compat helper).
    #[must_use]
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    /// `true` if this is an object (serde_json-compat helper).
    #[must_use]
    pub const fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    /// `true` if this is a number (int, uint or float).
    #[must_use]
    pub const fn is_number(&self) -> bool {
        matches!(self, Self::Int(_) | Self::UInt(_) | Self::Float(_))
    }
}

impl From<bool> for JsonValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<String> for JsonValue {
    fn from(v: String) -> Self {
        Self::Str(v)
    }
}
impl From<&str> for JsonValue {
    fn from(v: &str) -> Self {
        Self::Str(v.to_string())
    }
}
impl From<i64> for JsonValue {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}
impl From<u64> for JsonValue {
    fn from(v: u64) -> Self {
        Self::UInt(v)
    }
}
impl From<f64> for JsonValue {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}

impl std::ops::Index<&str> for JsonValue {
    type Output = JsonValue;
    /// serde_json-compatible indexing: `null` for missing keys / non-objects.
    fn index(&self, key: &str) -> &JsonValue {
        static NULL: JsonValue = JsonValue::Null;
        match self {
            JsonValue::Object(o) => o
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .unwrap_or(&NULL),
            _ => &NULL,
        }
    }
}

impl std::ops::Index<usize> for JsonValue {
    type Output = JsonValue;
    /// serde_json-compatible indexing: `null` for out-of-bounds / non-arrays.
    fn index(&self, i: usize) -> &JsonValue {
        static NULL: JsonValue = JsonValue::Null;
        match self {
            JsonValue::Array(a) => a.get(i).unwrap_or(&NULL),
            _ => &NULL,
        }
    }
}

/// Escape a string body (without surrounding quotes).
#[must_use]
pub fn escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn write_value(v: &JsonValue, out: &mut String, pretty: bool, indent: usize) {
    match v {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Int(i) => out.push_str(&i.to_string()),
        JsonValue::UInt(u) => out.push_str(&u.to_string()),
        JsonValue::Float(f) => {
            if f.is_finite() {
                let mut s = format!("{f:?}");
                if !s.contains('.') && !s.contains('e') && !s.contains("inf") {
                    s.push_str(".0");
                }
                out.push_str(&s);
            } else {
                out.push_str("null");
            }
        }
        JsonValue::Str(s) => {
            out.push('"');
            out.push_str(&escape_str(s));
            out.push('"');
        }
        JsonValue::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(indent + 1));
                }
                write_value(e, out, pretty, indent + 1);
                if i + 1 < a.len() {
                    out.push(',');
                }
            }
            if pretty {
                out.push('\n');
                out.push_str(&"  ".repeat(indent));
            }
            out.push(']');
        }
        JsonValue::Object(o) => {
            if o.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, val)) in o.iter().enumerate() {
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(indent + 1));
                }
                out.push('"');
                out.push_str(&escape_str(k));
                out.push('"');
                out.push(':');
                if pretty {
                    out.push(' ');
                }
                write_value(val, out, pretty, indent + 1);
                if i + 1 < o.len() {
                    out.push(',');
                }
            }
            if pretty {
                out.push('\n');
                out.push_str(&"  ".repeat(indent));
            }
            out.push('}');
        }
    }
}

/// Serialize compactly.
#[must_use]
pub fn to_string(v: &JsonValue) -> String {
    let mut s = String::new();
    write_value(v, &mut s, false, 0);
    s
}

/// Serialize pretty (2-space indent).
#[must_use]
pub fn to_string_pretty(v: &JsonValue) -> String {
    let mut s = String::new();
    write_value(v, &mut s, true, 0);
    s
}

/// Serialize to bytes.
#[must_use]
pub fn to_vec(v: &JsonValue) -> Vec<u8> {
    to_string(v).into_bytes()
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            b: s.as_bytes(),
            pos: 0,
        }
    }

    fn err<T>(&self, msg: &str) -> Result<T, JsonError> {
        Err(JsonError(format!("{msg} at byte {}", self.pos)))
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn eat_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), JsonError> {
        self.eat_ws();
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            self.err("expected token")
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.eat_ws();
        match self.peek() {
            Some(b'n') => self.parse_lit("null", JsonValue::Null),
            Some(b't') => self.parse_lit("true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_lit("false", JsonValue::Bool(false)),
            Some(b'"') => Ok(JsonValue::Str(self.parse_string()?)),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            _ => self.err("unexpected character"),
        }
    }

    fn parse_lit(&mut self, lit: &str, v: JsonValue) -> Result<JsonValue, JsonError> {
        if self.b.get(self.pos..self.pos + lit.len()) == Some(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(v)
        } else {
            self.err("bad literal")
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        if self.pos + 4 > self.b.len() {
            return self.err("bad \\u escape");
        }
        let s = std::str::from_utf8(&self.b[self.pos..self.pos + 4])
            .map_err(|_| JsonError("bad \\u escape".into()))?;
        let v = u32::from_str_radix(s, 16).map_err(|_| JsonError("bad \\u escape".into()))?;
        self.pos += 4;
        Ok(v)
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self
                .peek()
                .ok_or_else(|| JsonError("unterminated string".into()))?;
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    match self.peek().ok_or_else(|| JsonError("bad escape".into()))? {
                        b'"' => {
                            out.push('"');
                            self.pos += 1;
                        }
                        b'\\' => {
                            out.push('\\');
                            self.pos += 1;
                        }
                        b'/' => {
                            out.push('/');
                            self.pos += 1;
                        }
                        b'b' => {
                            out.push('\u{0008}');
                            self.pos += 1;
                        }
                        b'f' => {
                            out.push('\u{000C}');
                            self.pos += 1;
                        }
                        b'n' => {
                            out.push('\n');
                            self.pos += 1;
                        }
                        b'r' => {
                            out.push('\r');
                            self.pos += 1;
                        }
                        b't' => {
                            out.push('\t');
                            self.pos += 1;
                        }
                        b'u' => {
                            self.pos += 1;
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                if self.b.get(self.pos..self.pos + 2) == Some(b"\\u") {
                                    self.pos += 2;
                                    let lo = self.hex4()?;
                                    if (0xDC00..0xE000).contains(&lo) {
                                        let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                        out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                                    } else {
                                        return self.err("bad surrogate");
                                    }
                                } else {
                                    return self.err("lone surrogate");
                                }
                            } else {
                                out.push(char::from_u32(hi).unwrap_or('\u{FFFD}'));
                            }
                        }
                        _ => return self.err("bad escape"),
                    }
                }
                _ => {
                    // UTF-8 sequence: find next ascii boundary.
                    let start = self.pos;
                    let mut end = start + 1;
                    while end < self.b.len() && self.b[end] >= 0x80 {
                        end += 1;
                        if end - start >= 4 {
                            break;
                        }
                    }
                    let chunk = std::str::from_utf8(&self.b[start..end])
                        .map_err(|_| JsonError("bad utf8".into()))?;
                    out.push_str(chunk);
                    self.pos = end;
                }
            }
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.eat_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.eat_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return self.err("expected ',' or ']'"),
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        self.expect(b'{')?;
        let mut items = Vec::new();
        self.eat_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(items));
        }
        loop {
            self.eat_ws();
            if self.peek() != Some(b'"') {
                return self.err("expected string key");
            }
            let k = self.parse_string()?;
            self.expect(b':')?;
            let v = self.parse_value()?;
            items.push((k, v));
            self.eat_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(items));
                }
                _ => return self.err("expected ',' or '}'"),
            }
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.pos])
            .map_err(|_| JsonError("bad number".into()))?;
        if is_float {
            Ok(JsonValue::Float(s.parse::<f64>()?))
        } else if s.starts_with('-') {
            Ok(JsonValue::Int(s.parse::<i64>()?))
        } else {
            match s.parse::<u64>() {
                Ok(u) => Ok(JsonValue::UInt(u)),
                Err(_) => Ok(JsonValue::Float(s.parse::<f64>()?)),
            }
        }
    }
}

/// Parse a JSON document.
pub fn parse(s: &str) -> Result<JsonValue, JsonError> {
    let mut p = Parser::new(s);
    let v = p.parse_value()?;
    p.eat_ws();
    if p.pos != p.b.len() {
        return Err(JsonError(format!("trailing characters at byte {}", p.pos)));
    }
    Ok(v)
}

/// Parse from bytes (UTF-8).
pub fn parse_slice(b: &[u8]) -> Result<JsonValue, JsonError> {
    let s = std::str::from_utf8(b).map_err(|e| JsonError(e.to_string()))?;
    parse(s)
}

/// Parse, alias of [`parse`].
pub fn from_str(s: &str) -> Result<JsonValue, JsonError> {
    parse(s)
}

/// `omnisec_json::json!` replacement.
///
/// Supports objects, arrays, literals, nested structures and interpolation of
/// arbitrary Rust expressions (anything implementing `ToJson`).
#[macro_export]
macro_rules! json {
    (null) => { $crate::JsonValue::Null };
    (true) => { $crate::JsonValue::Bool(true) };
    (false) => { $crate::JsonValue::Bool(false) };

    ([$($rest:tt)*]) => {
        $crate::json!(@array [] $($rest)*)
    };

    ({$($rest:tt)*}) => {
        $crate::json!(@object [] $($rest)*)
    };

    ($other:expr) => { $crate::to_json_value(&$other) };

    // ─── array internals: accumulator of already-converted element exprs ───
    // NOTE on arm order: `tt` arms must precede `expr` arms (the expr matcher
    // error-recovers on `{...}` blocks and would poison the expansion), and
    // trailing-element arms must precede comma arms (a fragment that consumes
    // to end-of-input with a required `,` left is a hard "missing tokens"
    // error, not a fallthrough).
    (@array [$($elems:expr,)*]) => {
        $crate::JsonValue::Array(vec![$($elems),*])
    };
    (@array [$($elems:expr,)*] $last:tt) => {
        $crate::json!(@array [$($elems,)* $crate::json!($last),])
    };
    (@array [$($elems:expr,)*] $elem:tt, $($rest:tt)*) => {
        $crate::json!(@array [$($elems,)* $crate::json!($elem),] $($rest)*)
    };
    (@array [$($elems:expr,)*] $last:expr) => {
        $crate::json!(@array [$($elems,)* $crate::json!($last),])
    };
    (@array [$($elems:expr,)*] $elem:expr, $($rest:tt)*) => {
        $crate::json!(@array [$($elems,)* $crate::json!($elem),] $($rest)*)
    };

    // ─── object internals: accumulator of (key, value) pair tts ───
    (@object [$($acc:tt)*]) => {
        $crate::JsonValue::Object(vec![$($acc)*])
    };
    (@object [$($acc:tt)*] $key:tt : $last:tt) => {
        $crate::json!(@object [$($acc)* (($key).to_string(), $crate::json!($last)),])
    };
    (@object [$($acc:tt)*] $key:tt : $value:tt , $($rest:tt)*) => {
        $crate::json!(@object [$($acc)* (($key).to_string(), $crate::json!($value)),] $($rest)*)
    };
    (@object [$($acc:tt)*] $key:tt : $last:expr) => {
        $crate::json!(@object [$($acc)* (($key).to_string(), $crate::json!($last)),])
    };
    (@object [$($acc:tt)*] $key:tt : $value:expr , $($rest:tt)*) => {
        $crate::json!(@object [$($acc)* (($key).to_string(), $crate::json!($value)),] $($rest)*)
    };
}

/// Convert a Rust value into [`JsonValue`].
pub fn to_json_value<T: ToJson + ?Sized>(v: &T) -> JsonValue {
    v.to_json()
}

/// Conversion into [`JsonValue`] (replaces `Serialize`).
pub trait ToJson {
    /// Convert to JSON.
    fn to_json(&self) -> JsonValue;
}

/// Conversion from [`JsonValue`] (replaces `Deserialize`).
pub trait FromJson: Sized {
    /// Convert from JSON.
    fn from_json(v: &JsonValue) -> Result<Self, JsonError>;
}

/// Serialize a `ToJson` compactly.
pub fn to_json_string<T: ToJson + ?Sized>(v: &T) -> String {
    to_string(&v.to_json())
}

/// Deserialize an already-parsed value.
pub fn from_json_value<T: FromJson>(v: &JsonValue) -> Result<T, JsonError> {
    T::from_json(v)
}

/// Serialize a `ToJson` pretty.
pub fn to_json_pretty<T: ToJson + ?Sized>(v: &T) -> String {
    to_string_pretty(&v.to_json())
}

/// Deserialize from string.
pub fn from_json_str<T: FromJson>(s: &str) -> Result<T, JsonError> {
    T::from_json(&parse(s)?)
}

/// Serialize a `ToJson` to bytes.
#[must_use]
pub fn to_json_vec<T: ToJson + ?Sized>(v: &T) -> Vec<u8> {
    to_string(&v.to_json()).into_bytes()
}

/// Deserialize from bytes (UTF-8).
pub fn from_json_slice<T: FromJson>(b: &[u8]) -> Result<T, JsonError> {
    T::from_json(&parse_slice(b)?)
}

macro_rules! impl_num {
    ($($t:ty),*) => {$(
        impl ToJson for $t {
            fn to_json(&self) -> JsonValue {
                let v = *self as i128;
                if v < 0 {
                    JsonValue::Int(v as i64)
                } else if v > i64::MAX as i128 {
                    JsonValue::UInt(v as u64)
                } else {
                    // Prefer UInt for unsigned-looking range? Keep Int for signed types.
                    JsonValue::Int(v as i64)
                }
            }
        }
        impl FromJson for $t {
            fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
                match v {
                    JsonValue::Int(i) => Ok(*i as $t),
                    JsonValue::UInt(u) => Ok(*u as $t),
                    JsonValue::Float(f) => Ok(*f as $t),
                    _ => Err(JsonError(concat!("expected number for ", stringify!($t)).into())),
                }
            }
        }
    )*};
}

impl ToJson for u128 {
    fn to_json(&self) -> JsonValue {
        if *self <= u64::MAX as u128 {
            JsonValue::UInt(*self as u64)
        } else {
            JsonValue::Float(*self as f64)
        }
    }
}
impl FromJson for u128 {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        v.as_u64()
            .map(|u| u as u128)
            .ok_or_else(|| JsonError("expected number".into()))
    }
}
impl ToJson for i128 {
    fn to_json(&self) -> JsonValue {
        if *self >= i64::MIN as i128 && *self <= i64::MAX as i128 {
            JsonValue::Int(*self as i64)
        } else {
            JsonValue::Float(*self as f64)
        }
    }
}
impl FromJson for i128 {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        v.as_i64()
            .map(|i| i as i128)
            .ok_or_else(|| JsonError("expected number".into()))
    }
}
impl_num!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl ToJson for bool {
    fn to_json(&self) -> JsonValue {
        JsonValue::Bool(*self)
    }
}
impl FromJson for bool {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        v.as_bool().ok_or_else(|| JsonError("expected bool".into()))
    }
}

impl ToJson for f32 {
    fn to_json(&self) -> JsonValue {
        JsonValue::Float(f64::from(*self))
    }
}
impl FromJson for f32 {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        v.as_f64()
            .map(|f| f as f32)
            .ok_or_else(|| JsonError("expected number".into()))
    }
}
impl ToJson for f64 {
    fn to_json(&self) -> JsonValue {
        JsonValue::Float(*self)
    }
}
impl FromJson for f64 {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        v.as_f64()
            .ok_or_else(|| JsonError("expected number".into()))
    }
}

impl ToJson for String {
    fn to_json(&self) -> JsonValue {
        JsonValue::Str(self.clone())
    }
}
impl FromJson for String {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| JsonError("expected string".into()))
    }
}
impl ToJson for str {
    fn to_json(&self) -> JsonValue {
        JsonValue::Str(self.to_string())
    }
}
impl<T: ToJson> ToJson for Option<T> {
    fn to_json(&self) -> JsonValue {
        self.as_ref().map_or(JsonValue::Null, ToJson::to_json)
    }
}
impl<T: ToJson + ?Sized> ToJson for &T {
    fn to_json(&self) -> JsonValue {
        (**self).to_json()
    }
}

impl ToJson for std::path::PathBuf {
    fn to_json(&self) -> JsonValue {
        JsonValue::Str(self.display().to_string())
    }
}
impl FromJson for std::path::PathBuf {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        let s = v
            .as_str()
            .ok_or_else(|| JsonError("expected string".into()))?;
        Ok(std::path::PathBuf::from(s))
    }
}

impl ToJson for std::net::Ipv4Addr {
    fn to_json(&self) -> JsonValue {
        JsonValue::Str(self.to_string())
    }
}
impl FromJson for std::net::Ipv4Addr {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        let s = v
            .as_str()
            .ok_or_else(|| JsonError("expected string".into()))?;
        s.parse()
            .map_err(|_| JsonError("invalid IPv4 address".into()))
    }
}
impl ToJson for std::net::Ipv6Addr {
    fn to_json(&self) -> JsonValue {
        JsonValue::Str(self.to_string())
    }
}
impl FromJson for std::net::Ipv6Addr {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        let s = v
            .as_str()
            .ok_or_else(|| JsonError("expected string".into()))?;
        s.parse()
            .map_err(|_| JsonError("invalid IPv6 address".into()))
    }
}
impl ToJson for std::net::IpAddr {
    fn to_json(&self) -> JsonValue {
        JsonValue::Str(self.to_string())
    }
}
impl FromJson for std::net::IpAddr {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        let s = v
            .as_str()
            .ok_or_else(|| JsonError("expected string".into()))?;
        s.parse()
            .map_err(|_| JsonError("invalid IP address".into()))
    }
}

#[allow(non_snake_case)]
macro_rules! impl_tuple {
    ($($name:ident : $idx:tt),+) => {
        impl<$($name: ToJson),+> ToJson for ($($name,)+) {
            fn to_json(&self) -> JsonValue {
                JsonValue::Array(vec![$(self.$idx.to_json()),+])
            }
        }
        impl<$($name: FromJson),+> FromJson for ($($name,)+) {
            #[allow(non_snake_case)]
            fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
                match v {
                    JsonValue::Array(a) => {
                        let mut __i = 0usize;
                        $(
                            let $name = a.get(__i)
                                .ok_or_else(|| JsonError("tuple too short".into()))
                                .and_then($name::from_json)?;
                            __i += 1;
                        )+
                        if __i != a.len() {
                            return Err(JsonError("tuple too long".into()));
                        }
                        Ok(($($name,)+))
                    }
                    _ => Err(JsonError("expected array".into())),
                }
            }
        }
    };
}

impl_tuple!(A: 0);
impl_tuple!(A: 0, B: 1);
impl_tuple!(A: 0, B: 1, C: 2);
impl_tuple!(A: 0, B: 1, C: 2, D: 3);
impl_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4);
impl_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5);
impl_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6);
impl_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7);

impl<T: FromJson, const N: usize> FromJson for [T; N] {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        match v {
            JsonValue::Array(a) => {
                if a.len() != N {
                    return Err(JsonError(format!(
                        "expected array of {N} elements, got {}",
                        a.len()
                    )));
                }
                let items: Result<Vec<T>, JsonError> = a.iter().map(T::from_json).collect();
                let list = items?;
                <[T; N]>::try_from(list).map_err(|_| JsonError("length mismatch".into()))
            }
            _ => Err(JsonError("expected array".into())),
        }
    }
}
impl<T: FromJson> FromJson for Option<T> {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        if v.is_null() {
            Ok(None)
        } else {
            T::from_json(v).map(Some)
        }
    }
}
impl<T: ToJson> ToJson for Vec<T> {
    fn to_json(&self) -> JsonValue {
        JsonValue::Array(self.iter().map(ToJson::to_json).collect())
    }
}
impl<T: FromJson> FromJson for Vec<T> {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        match v {
            JsonValue::Array(a) => a.iter().map(T::from_json).collect(),
            _ => Err(JsonError("expected array".into())),
        }
    }
}
impl<T: ToJson> ToJson for [T] {
    fn to_json(&self) -> JsonValue {
        JsonValue::Array(self.iter().map(ToJson::to_json).collect())
    }
}
impl<T: ToJson, const N: usize> ToJson for [T; N] {
    fn to_json(&self) -> JsonValue {
        JsonValue::Array(self.iter().map(ToJson::to_json).collect())
    }
}
impl<K: ToString + Eq + std::hash::Hash, V: ToJson> ToJson for HashMap<K, V> {
    fn to_json(&self) -> JsonValue {
        let mut o = Vec::with_capacity(self.len());
        let mut keys: Vec<_> = self.keys().collect();
        keys.sort_by_key(|k| k.to_string());
        for k in keys {
            o.push((k.to_string(), self[k].to_json()));
        }
        JsonValue::Object(o)
    }
}
impl<K: std::str::FromStr + Eq + std::hash::Hash, V: FromJson> FromJson for HashMap<K, V> {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        match v {
            JsonValue::Object(o) => {
                let mut m = HashMap::with_capacity(o.len());
                for (k, val) in o {
                    let key = k
                        .parse()
                        .map_err(|_| JsonError(format!("bad map key '{k}'")))?;
                    m.insert(key, V::from_json(val)?);
                }
                Ok(m)
            }
            _ => Err(JsonError("expected object".into())),
        }
    }
}
impl<K: ToString + Ord, V: ToJson> ToJson for BTreeMap<K, V> {
    fn to_json(&self) -> JsonValue {
        JsonValue::Object(
            self.iter()
                .map(|(k, v)| (k.to_string(), v.to_json()))
                .collect(),
        )
    }
}
impl<K: std::str::FromStr + Ord, V: FromJson> FromJson for BTreeMap<K, V> {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        match v {
            JsonValue::Object(o) => {
                let mut m = BTreeMap::new();
                for (k, val) in o {
                    let key = k
                        .parse()
                        .map_err(|_| JsonError(format!("bad map key '{k}'")))?;
                    m.insert(key, V::from_json(val)?);
                }
                Ok(m)
            }
            _ => Err(JsonError("expected object".into())),
        }
    }
}
impl<V: ToJson + Eq + std::hash::Hash> ToJson for HashSet<V> {
    fn to_json(&self) -> JsonValue {
        JsonValue::Array(self.iter().map(ToJson::to_json).collect())
    }
}
impl<V: FromJson + Eq + std::hash::Hash> FromJson for HashSet<V> {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        match v {
            JsonValue::Array(a) => {
                let mut s = HashSet::with_capacity(a.len());
                for val in a {
                    s.insert(V::from_json(val)?);
                }
                Ok(s)
            }
            _ => Err(JsonError("expected array".into())),
        }
    }
}
impl<V: ToJson + Ord> ToJson for BTreeSet<V> {
    fn to_json(&self) -> JsonValue {
        JsonValue::Array(self.iter().map(ToJson::to_json).collect())
    }
}
impl<V: FromJson + Ord> FromJson for BTreeSet<V> {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        match v {
            JsonValue::Array(a) => {
                let mut s = BTreeSet::new();
                for val in a {
                    s.insert(V::from_json(val)?);
                }
                Ok(s)
            }
            _ => Err(JsonError("expected array".into())),
        }
    }
}

impl<K: ToString + Eq + std::hash::Hash + Clone, V: ToJson> ToJson
    for omnisec_collections::IndexMap<K, V>
{
    fn to_json(&self) -> JsonValue {
        JsonValue::Object(
            self.iter()
                .map(|(k, v)| (k.to_string(), v.to_json()))
                .collect(),
        )
    }
}
impl<K: std::str::FromStr + Eq + std::hash::Hash + Clone, V: FromJson> FromJson
    for omnisec_collections::IndexMap<K, V>
{
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        match v {
            JsonValue::Object(o) => {
                let mut m = omnisec_collections::IndexMap::with_capacity(o.len());
                for (k, val) in o {
                    let key = k
                        .parse()
                        .map_err(|_| JsonError(format!("bad map key '{k}'")))?;
                    m.insert(key, V::from_json(val)?);
                }
                Ok(m)
            }
            _ => Err(JsonError("expected object".into())),
        }
    }
}
impl<T: ToJson + Eq + std::hash::Hash + Clone> ToJson for omnisec_collections::IndexSet<T> {
    fn to_json(&self) -> JsonValue {
        JsonValue::Array(self.iter().map(ToJson::to_json).collect())
    }
}
impl<T: FromJson + Eq + std::hash::Hash + Clone> FromJson for omnisec_collections::IndexSet<T> {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        match v {
            JsonValue::Array(a) => {
                let mut s = omnisec_collections::IndexSet::new();
                for val in a {
                    s.insert(T::from_json(val)?);
                }
                Ok(s)
            }
            _ => Err(JsonError("expected array".into())),
        }
    }
}
impl ToJson for JsonValue {
    fn to_json(&self) -> JsonValue {
        self.clone()
    }
}
impl FromJson for JsonValue {
    fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
        Ok(v.clone())
    }
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 encode (standard alphabet, `=` padding).
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_TABLE[((n >> 18) & 63) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Base64 decode (standard alphabet, padding optional).
pub fn b64_decode(s: &str) -> Result<Vec<u8>, JsonError> {
    fn val(c: u8) -> Result<u32, JsonError> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a') as u32 + 26),
            b'0'..=b'9' => Ok((c - b'0') as u32 + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(64),
            _ => Err(JsonError("bad base64 char".into())),
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.len() % 4 != 0 {
        return Err(JsonError("bad base64 length".into()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = val(chunk[2])?;
        let v3 = val(chunk[3])?;
        if v0 == 64 || v1 == 64 {
            return Err(JsonError("bad base64 padding".into()));
        }
        out.push(((v0 << 2) | (v1 >> 4)) as u8);
        if v2 != 64 {
            out.push(((v1 << 4) | (v2 >> 2)) as u8);
        }
        if v3 != 64 {
            out.push(((v2 << 6) | v3) as u8);
        }
    }
    Ok(out)
}

/// Lowercase hex encode.
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// Hex decode (even length, case-insensitive).
pub fn hex_decode(s: &str) -> Result<Vec<u8>, JsonError> {
    if s.len() % 2 != 0 {
        return Err(JsonError("odd hex length".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let hv = |c: u8| -> Result<u8, JsonError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(JsonError("bad hex char".into())),
        }
    };
    for i in (0..b.len()).step_by(2) {
        out.push((hv(b[i])? << 4) | hv(b[i + 1])?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        for s in [
            "null",
            "true",
            "42",
            "-7",
            "3.5",
            "\"hi\"",
            "[1,2]",
            "{\"a\":1}",
        ] {
            let v = parse(s).unwrap();
            let s2 = to_string(&v);
            let v2 = parse(&s2).unwrap();
            assert_eq!(v, v2, "{s}");
        }
    }

    #[test]
    fn escapes_and_unicode() {
        let v = parse("\"\\n\\u00e9\\ud83d\\ude00\"").unwrap();
        assert_eq!(v.as_str(), Some("\n\u{e9}\u{1f600}"));
        let s = to_string(&JsonValue::Str("a\"b\n".into()));
        assert_eq!(s, "\"a\\\"b\\n\"");
    }

    #[test]
    fn pretty_is_valid() {
        let v = parse("{\"a\":[1,2],\"b\":{}}").unwrap();
        let p = to_string_pretty(&v);
        assert_eq!(parse(&p).unwrap(), v);
        assert!(p.contains('\n'));
    }

    #[test]
    fn b64_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_decode("Zm9v").unwrap(), b"foo");
    }

    #[test]
    fn json_macro_shapes() {
        use crate::{FromJson, ToJson};

        struct Item {
            name: String,
            n: u32,
        }
        impl ToJson for Item {
            fn to_json(&self) -> JsonValue {
                json!({"name": self.name, "n": self.n})
            }
        }
        impl FromJson for Item {
            fn from_json(v: &JsonValue) -> Result<Self, JsonError> {
                Ok(Self {
                    name: String::from_json(v.get("name").unwrap_or(&JsonValue::Null))?,
                    n: u32::from_json(v.get("n").unwrap_or(&JsonValue::Null))?,
                })
            }
        }

        let it = Item {
            name: "x".into(),
            n: 3,
        };
        let obj = json!({
            "item": it,
            "nested": { "text": format!("a-{}", 1), "flag": true },
            "list": [1, 2, it.n],
            "deep": [{ "inner": "v" }],
        });
        let s = to_string(&obj);
        let back = parse(&s).unwrap();
        assert_eq!(
            back.get("nested")
                .and_then(|v| v.get("text"))
                .and_then(|v| v.as_str()),
            Some("a-1")
        );
        assert_eq!(
            back.get("list")
                .and_then(|v| v.as_array())
                .map(<[JsonValue]>::len),
            Some(3)
        );
        assert_eq!(
            back.get("deep")
                .and_then(|v| v.index(0))
                .and_then(|v| v.get("inner"))
                .and_then(|v| v.as_str()),
            Some("v")
        );
        let round: Item = from_json_value(back.get("item").unwrap()).unwrap();
        assert_eq!(round.name, "x");
    }
}
