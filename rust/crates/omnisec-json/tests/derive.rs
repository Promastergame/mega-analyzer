//! Integration tests for the `ToJson` / `FromJson` derive macros.

use omnisec_json::{from_json_str, to_json_string, FromJson, ToJson};

pub mod duration_mod {
    use omnisec_json::{JsonError, JsonValue};
    use std::time::Duration;

    pub fn to_json(d: &Duration) -> JsonValue {
        JsonValue::Float(d.as_secs_f64())
    }

    pub fn from_json(v: &JsonValue) -> Result<Duration, JsonError> {
        Ok(Duration::from_secs_f64(v.as_f64().unwrap_or_default()))
    }
}

fn default_size() -> u32 {
    42
}

#[derive(Debug, ToJson, FromJson, PartialEq)]
#[json(rename_all = "snake_case")]
struct Sample {
    plain: u32,
    with_rename: String,
    #[json(default)]
    defaulted: bool,
    #[json(default = "default_size")]
    sized: u32,
    #[json(skip_serializing_if = "Option::is_none")]
    maybe: Option<String>,
    #[json(skip_serializing_if = "Vec::is_empty")]
    items: Vec<u32>,
}

#[derive(Debug, ToJson, FromJson, PartialEq)]
#[json(rename_all = "snake_case")]
enum Tag {
    Simple,
    WithData { first: u32, second: String },
    Wrapped(u64),
    Pair(u32, u32),
}

#[derive(Debug, ToJson, FromJson, PartialEq)]
struct Inner {
    a: u32,
}

#[derive(Debug, ToJson, FromJson, PartialEq)]
struct Outer {
    #[json(flatten)]
    inner: Inner,
    b: u32,
}

#[derive(Debug, ToJson, FromJson, PartialEq)]
struct WithDur {
    #[json(with = "duration_mod")]
    took: std::time::Duration,
}

#[derive(Debug, ToJson, FromJson, PartialEq)]
struct Newtype(u32);

#[test]
fn sample_roundtrip() {
    let s = Sample {
        plain: 1,
        with_rename: "x".into(),
        defaulted: true,
        sized: 7,
        maybe: Some("m".into()),
        items: vec![1, 2],
    };
    let json = to_json_string(&s);
    assert!(json.contains("with_rename"));
    let back: Sample = from_json_str(&json).unwrap();
    assert_eq!(back, s);

    // skip_serializing_if drops the keys.
    let s2 = Sample {
        plain: 1,
        with_rename: "x".into(),
        defaulted: false,
        sized: 7,
        maybe: None,
        items: Vec::new(),
    };
    let json2 = to_json_string(&s2);
    assert!(!json2.contains("maybe"));
    assert!(!json2.contains("items"));

    // Defaults apply when keys are missing.
    let back2: Sample = from_json_str(r#"{"plain":1,"with_rename":"x","items":[]}"#).unwrap();
    assert!(!back2.defaulted);
    assert_eq!(back2.sized, 42);
    assert_eq!(back2.maybe, None);
}

#[test]
fn tag_roundtrip() {
    for (t, expected) in [
        (Tag::Simple, r#""simple""#),
        (Tag::Wrapped(9), r#"{"wrapped":9}"#),
        (Tag::Pair(1, 2), r#"{"pair":[1,2]}"#),
        (
            Tag::WithData {
                first: 1,
                second: "s".into(),
            },
            r#"{"with_data":{"first":1,"second":"s"}}"#,
        ),
    ] {
        assert_eq!(to_json_string(&t), expected);
        let back: Tag = from_json_str(expected).unwrap();
        assert_eq!(back, t);
    }
}

#[test]
fn flatten_roundtrip() {
    let o = Outer {
        inner: Inner { a: 1 },
        b: 2,
    };
    let json = to_json_string(&o);
    assert_eq!(json, r#"{"a":1,"b":2}"#);
    let back: Outer = from_json_str(&json).unwrap();
    assert_eq!(back, o);
}

#[test]
fn with_module_roundtrip() {
    let w = WithDur {
        took: std::time::Duration::from_millis(1500),
    };
    let json = to_json_string(&w);
    assert_eq!(json, r#"{"took":1.5}"#);
    let back: WithDur = from_json_str(&json).unwrap();
    assert_eq!(back, w);
}

#[test]
fn newtype_roundtrip() {
    let n = Newtype(5);
    assert_eq!(to_json_string(&n), "5");
    let back: Newtype = from_json_str("5").unwrap();
    assert_eq!(back, n);
}

#[test]
fn flags_newtype_u32() {
    #[derive(Debug, ToJson, FromJson, PartialEq)]
    struct Flags(u32);

    let f = Flags(0b1010);
    assert_eq!(to_json_string(&f), "10");
    let back: Flags = from_json_str("10").unwrap();
    assert_eq!(back, f);
}
