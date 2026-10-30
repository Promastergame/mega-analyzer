//! Derive macros for `omnisec-json`: `ToJson` / `FromJson`.
//!
//! Implemented against the built-in `proc_macro` crate only — no syn/quote —
//! so the platform keeps its zero-third-party-dependency guarantee.
//!
//! Supported attribute surface (helper attribute `json`):
//! - container: `rename_all = "snake_case" | "lowercase" | "kebab-case" |
//!   "camelCase" | "PascalCase" | "SCREAMING_SNAKE_CASE"`
//! - field: `rename`, `default`, `default = "path"`, `skip`,
//!   `skip_serializing_if = "path"`, `flatten`, `with = "module"`
//!   (module must expose `to_json` / `from_json` in the `omnisec-json`
//!   convention).
//!
//! Struct shapes: named, tuple/newtype, unit. Enum shapes: unit variants,
//! newtype/tuple variants, struct variants — externally tagged (serde
//! default). Generics and `tag = ...` are intentionally not supported.

use proc_macro::{TokenStream, TokenTree};

// ─── Attribute models ───────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct FieldAttr {
    rename: Option<String>,
    default: bool,
    default_path: Option<String>,
    skip: bool,
    skip_if: Option<String>,
    flatten: bool,
    with: Option<String>,
}

#[derive(Default, Clone)]
struct ContainerAttr {
    rename_all: Option<String>,
}

// ─── Token helpers ──────────────────────────────────────────────────────────

fn toks(ts: TokenStream) -> Vec<TokenTree> {
    ts.into_iter().collect()
}

fn as_ident(tt: &TokenTree) -> Option<String> {
    match tt {
        TokenTree::Ident(i) => Some(i.to_string()),
        _ => None,
    }
}

fn is_punct(tt: &TokenTree, c: char) -> bool {
    matches!(tt, TokenTree::Punct(p) if p.as_char() == c)
}

fn join(tts: &[TokenTree]) -> String {
    let mut ts = TokenStream::new();
    ts.extend(tts.iter().cloned());
    ts.to_string()
}

fn split_top_comma(tts: &[TokenTree]) -> Vec<&[TokenTree]> {
    let mut out = Vec::new();
    let mut start = 0;
    // Generic angle brackets are plain `Punct` tokens (not groups), so commas
    // inside `HashMap<K, V>` are *not* top-level — track `<`/`>` depth.
    let mut angle = 0usize;
    for (i, t) in tts.iter().enumerate() {
        if let TokenTree::Punct(p) = t {
            match p.as_char() {
                '<' => angle += 1,
                '>' => {
                    // `->` (fn pointers) is not a generic closer.
                    if i > 0 && matches!(&tts[i - 1], TokenTree::Punct(pp) if pp.as_char() == '-') {
                        // ignore
                    } else if angle > 0 {
                        angle -= 1;
                    }
                }
                ',' if angle == 0 => {
                    out.push(&tts[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
    }
    if start < tts.len() {
        out.push(&tts[start..]);
    }
    out
}

fn strip_str_literal(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// Extract `#[json(...)]` attribute content from the head of a token list,
/// returning (attr, remaining). Other attributes (doc, derive, …) are skipped.
fn take_json_attr(tts: &[TokenTree]) -> (Option<Vec<TokenTree>>, usize) {
    let mut i = 0;
    let mut json_inner = None;
    while i + 1 < tts.len() && is_punct(&tts[i], '#') {
        if let TokenTree::Group(g) = &tts[i + 1] {
            if g.delimiter() == proc_macro::Delimiter::Bracket {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                if let Some(first) = inner.first() {
                    if as_ident(first).as_deref() == Some("json") {
                        if let Some(TokenTree::Group(pg)) = inner.get(1) {
                            json_inner = Some(pg.stream().into_iter().collect());
                        }
                        i += 2;
                        continue;
                    }
                }
                i += 2;
                continue;
            }
        }
        break;
    }
    (json_inner, i)
}

fn parse_field_attr(tts: &[TokenTree]) -> Result<FieldAttr, String> {
    let mut a = FieldAttr::default();
    for item in split_top_comma(tts) {
        if item.is_empty() {
            continue;
        }
        let key = as_ident(&item[0]).ok_or_else(|| "bad #[json] attribute".to_string())?;
        if item.len() == 1 {
            match key.as_str() {
                "default" => a.default = true,
                "skip" => a.skip = true,
                "flatten" => a.flatten = true,
                _ => return Err(format!("unsupported #[json({key})]")),
            }
        } else {
            if !is_punct(&item[1], '=') || item.len() < 3 {
                return Err(format!("malformed #[json({key} = …)]"));
            }
            let raw = strip_str_literal(&join(&item[2..]));
            match key.as_str() {
                "rename" => a.rename = Some(raw),
                "default" => a.default_path = Some(raw),
                "skip_serializing_if" => a.skip_if = Some(raw),
                "with" => a.with = Some(raw),
                _ => return Err(format!("unsupported #[json({key} = …)]")),
            }
        }
    }
    Ok(a)
}

fn parse_container_attr(tts: &[TokenTree]) -> Result<ContainerAttr, String> {
    let mut c = ContainerAttr::default();
    for item in split_top_comma(tts) {
        if item.is_empty() {
            continue;
        }
        let key = as_ident(&item[0]).ok_or_else(|| "bad #[json] attribute".to_string())?;
        match key.as_str() {
            "rename_all" => {
                if item.len() < 3 {
                    return Err("rename_all needs a value".into());
                }
                c.rename_all = Some(strip_str_literal(&join(&item[2..])));
            }
            "tag" | "transparent" | "untagged" => {
                return Err(format!(
                    "#[json({key})] is not supported by omnisec-json-derive; write the impl manually"
                ));
            }
            _ => return Err(format!("unsupported container #[json({key})]")),
        }
    }
    Ok(c)
}

// ─── Item model ─────────────────────────────────────────────────────────────

struct NamedField {
    name: String,
    #[allow(dead_code)]
    ty: String,
    attr: FieldAttr,
}

enum VFields {
    Unit,
    Unnamed(Vec<(String, FieldAttr)>),
    Named(Vec<NamedField>),
}

struct Variant {
    name: String,
    rename: Option<String>,
    fields: VFields,
}

enum Kind {
    Unit,
    Newtype,
    Tuple(Vec<String>),
    Named(Vec<NamedField>),
    Enum(Vec<Variant>),
}

struct Input {
    name: String,
    container: ContainerAttr,
    kind: Kind,
}

fn parse_input(input: TokenStream) -> Result<Input, String> {
    let ts = toks(input);
    // Collect container-level #[json(...)] attrs before the item keyword.
    let mut container = ContainerAttr::default();
    let mut i = 0;
    while i + 1 < ts.len() && is_punct(&ts[i], '#') {
        if let TokenTree::Group(g) = &ts[i + 1] {
            if g.delimiter() == proc_macro::Delimiter::Bracket {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                if inner.first().and_then(as_ident).as_deref() == Some("json") {
                    if let Some(TokenTree::Group(pg)) = inner.get(1) {
                        let content: Vec<TokenTree> = pg.stream().into_iter().collect();
                        container = parse_container_attr(&content)?;
                    }
                }
                i += 2;
                continue;
            }
        }
        break;
    }
    // Find the `struct` / `enum` keyword.
    let mut kw = None;
    let mut j = i;
    while j < ts.len() {
        match as_ident(&ts[j]).as_deref() {
            Some("struct") | Some("enum") => {
                kw = Some((as_ident(&ts[j]).unwrap(), j + 1));
                break;
            }
            _ => j += 1,
        }
    }
    let (kw, mut j) = kw.ok_or_else(|| "expected struct or enum".to_string())?;
    let name = as_ident(&ts[j]).ok_or_else(|| "expected item name".to_string())?;
    j += 1;
    // Skip generics and where clauses: walk until a Group or `;`.
    while j < ts.len() {
        match &ts[j] {
            TokenTree::Group(_) => break,
            TokenTree::Punct(p) if p.as_char() == ';' => break,
            _ => j += 1,
        }
    }
    let kind = match (kw.as_str(), ts.get(j)) {
        (_, Some(TokenTree::Punct(p))) if p.as_char() == ';' => Kind::Unit,
        ("enum", Some(TokenTree::Group(g))) => {
            let inner: Vec<TokenTree> = g.stream().into_iter().collect();
            Kind::Enum(
                split_top_comma(&inner)
                    .into_iter()
                    .filter(|v| !v.is_empty())
                    .map(parse_variant)
                    .collect::<Result<Vec<_>, String>>()?,
            )
        }
        (_, Some(TokenTree::Group(g))) => match g.delimiter() {
            proc_macro::Delimiter::Parenthesis => {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                let fields = split_top_comma(&inner)
                    .into_iter()
                    .filter(|f| !f.is_empty())
                    .map(parse_unnamed_field)
                    .collect::<Result<Vec<_>, String>>()?;
                if fields.len() == 1 {
                    Kind::Newtype
                } else {
                    Kind::Tuple(fields.into_iter().map(|(t, _)| t).collect())
                }
            }
            proc_macro::Delimiter::Brace => {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                Kind::Named(
                    split_top_comma(&inner)
                        .into_iter()
                        .filter(|f| !f.is_empty())
                        .map(parse_named_field)
                        .collect::<Result<Vec<_>, String>>()?,
                )
            }
            _ => return Err("unexpected delimiter after item name".into()),
        },
        _ => return Err("expected `{`, `(` or `;` after item name".into()),
    };
    let _ = kw;
    Ok(Input {
        name,
        container,
        kind,
    })
}

fn parse_named_field(tts: &[TokenTree]) -> Result<NamedField, String> {
    let (attr_tts, mut i) = take_json_attr(tts);
    let attr = match attr_tts {
        Some(a) => parse_field_attr(&a)?,
        None => FieldAttr::default(),
    };
    // Skip visibility.
    if as_ident(&tts[i]).as_deref() == Some("pub") {
        i += 1;
        if let Some(TokenTree::Group(g)) = tts.get(i) {
            if g.delimiter() == proc_macro::Delimiter::Parenthesis {
                i += 1;
            }
        }
    }
    let name = as_ident(&tts[i]).ok_or_else(|| "expected field name".to_string())?;
    i += 1;
    if !is_punct(&tts[i], ':') {
        return Err("expected ':' after field name".into());
    }
    i += 1;
    let ty = join(&tts[i..]);
    if ty.is_empty() {
        return Err("expected field type".into());
    }
    Ok(NamedField { name, ty, attr })
}

fn parse_unnamed_field(tts: &[TokenTree]) -> Result<(String, FieldAttr), String> {
    let (attr_tts, mut i) = take_json_attr(tts);
    let attr = match attr_tts {
        Some(a) => parse_field_attr(&a)?,
        None => FieldAttr::default(),
    };
    if as_ident(&tts[i]).as_deref() == Some("pub") {
        i += 1;
        if let Some(TokenTree::Group(g)) = tts.get(i) {
            if g.delimiter() == proc_macro::Delimiter::Parenthesis {
                i += 1;
            }
        }
    }
    let ty = join(&tts[i..]);
    if ty.is_empty() {
        return Err("expected field type".to_string());
    }
    Ok((ty, attr))
}

fn parse_variant(tts: &[TokenTree]) -> Result<Variant, String> {
    let (attr_tts, mut i) = take_json_attr(tts);
    let mut rename = None;
    if let Some(a) = attr_tts {
        for item in split_top_comma(&a) {
            if item.is_empty() {
                continue;
            }
            let key = as_ident(&item[0]).unwrap_or_default();
            if key == "rename" && item.len() >= 3 {
                rename = Some(strip_str_literal(&join(&item[2..])));
            } else if key == "other" {
                // ignore
            } else {
                return Err(format!("unsupported variant #[json({key})]"));
            }
        }
    }
    let name = as_ident(&tts[i]).ok_or_else(|| "expected variant name".to_string())?;
    i += 1;
    let fields = match tts.get(i) {
        None => VFields::Unit,
        Some(TokenTree::Group(g)) => {
            let inner: Vec<TokenTree> = g.stream().into_iter().collect();
            match g.delimiter() {
                proc_macro::Delimiter::Parenthesis => VFields::Unnamed(
                    split_top_comma(&inner)
                        .into_iter()
                        .filter(|f| !f.is_empty())
                        .map(parse_unnamed_field)
                        .collect::<Result<Vec<_>, String>>()?,
                ),
                proc_macro::Delimiter::Brace => VFields::Named(
                    split_top_comma(&inner)
                        .into_iter()
                        .filter(|f| !f.is_empty())
                        .map(parse_named_field)
                        .collect::<Result<Vec<_>, String>>()?,
                ),
                _ => return Err("unexpected variant delimiter".into()),
            }
        }
        // Discriminant (`= expr`) → treat as unit variant.
        Some(_) => VFields::Unit,
    };
    Ok(Variant {
        name,
        rename,
        fields,
    })
}

// ─── Name case conversion ───────────────────────────────────────────────────

fn apply_case(name: &str, case: &str) -> String {
    fn split_words(s: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut cur = String::new();
        let mut prev_lower = false;
        for ch in s.chars() {
            if ch == '_' || ch == '-' {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
                prev_lower = false;
            } else if ch.is_ascii_uppercase() && prev_lower {
                words.push(std::mem::take(&mut cur));
                cur.push(ch);
                prev_lower = false;
            } else if ch.is_ascii_uppercase() {
                cur.push(ch);
                prev_lower = false;
            } else {
                cur.push(ch);
                prev_lower = true;
            }
        }
        if !cur.is_empty() {
            words.push(cur);
        }
        words
    }
    let words = split_words(name);
    match case {
        "snake_case" => words
            .iter()
            .map(|w| w.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("_"),
        "SCREAMING_SNAKE_CASE" => words
            .iter()
            .map(|w| w.to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join("_"),
        "kebab-case" => words
            .iter()
            .map(|w| w.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("-"),
        "lowercase" => words.concat().to_ascii_lowercase(),
        "camelCase" => words
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let lw = w.to_ascii_lowercase();
                if i == 0 {
                    lw
                } else {
                    format!("{}{}", lw[..1].to_ascii_uppercase(), &lw[1..])
                }
            })
            .collect(),
        "PascalCase" => words
            .iter()
            .map(|w| {
                let lw = w.to_ascii_lowercase();
                format!("{}{}", lw[..1].to_ascii_uppercase(), &lw[1..])
            })
            .collect(),
        _ => name.to_string(),
    }
}

fn field_key(f: &NamedField, c: &ContainerAttr) -> String {
    let k = f
        .attr
        .rename
        .clone()
        .unwrap_or_else(|| match &c.rename_all {
            Some(case) => apply_case(&f.name, case),
            None => f.name.clone(),
        });
    format!("{k:?}")
}

fn variant_key(v: &Variant, c: &ContainerAttr) -> String {
    let k = v.rename.clone().unwrap_or_else(|| match &c.rename_all {
        Some(case) => apply_case(&v.name, case),
        None => v.name.clone(),
    });
    format!("{k:?}")
}

// ─── ToJson emission ────────────────────────────────────────────────────────

fn ser_value_expr(field_access: &str, attr: &FieldAttr) -> String {
    match &attr.with {
        Some(m) => format!("{m}::to_json({field_access})"),
        None => format!("::omnisec_json::ToJson::to_json({field_access})"),
    }
}

fn emit_to_json(inp: &Input) -> String {
    let name = &inp.name;
    let mut s = String::new();
    s.push_str(&format!(
        "impl ::omnisec_json::ToJson for {name} {{\n    fn to_json(&self) -> ::omnisec_json::JsonValue {{\n"
    ));
    match &inp.kind {
        Kind::Unit => s.push_str("        ::omnisec_json::JsonValue::Null\n"),
        Kind::Newtype => {
            s.push_str("        ::omnisec_json::ToJson::to_json(&self.0)\n");
        }
        Kind::Tuple(fields) => {
            let elems: Vec<String> = (0..fields.len())
                .map(|i| format!("::omnisec_json::ToJson::to_json(&self.{i})"))
                .collect();
            s.push_str(&format!(
                "        ::omnisec_json::JsonValue::Array(vec![{}])\n",
                elems.join(", ")
            ));
        }
        Kind::Named(fields) => {
            s.push_str("        let mut __o: ::std::vec::Vec<(::std::string::String, ::omnisec_json::JsonValue)> = ::std::vec::Vec::new();\n");
            for f in fields {
                if f.attr.skip {
                    continue;
                }
                if f.attr.flatten {
                    s.push_str(&format!(
                        "        if let ::omnisec_json::JsonValue::Object(__sub) = {} {{\n            __o.extend(__sub);\n        }}\n",
                        ser_value_expr(&format!("&self.{}", f.name), &f.attr)
                    ));
                    continue;
                }
                let key = field_key(f, &inp.container);
                let push = format!(
                    "__o.push(({key}.to_string(), {}));\n",
                    ser_value_expr("&self.__fname__", &f.attr).replace("__fname__", &f.name)
                );
                match &f.attr.skip_if {
                    Some(p) => {
                        s.push_str(&format!(
                            "        if !{p}(&self.{}) {{\n            {push}        }}\n",
                            f.name
                        ));
                    }
                    None => s.push_str(&format!("        {push}")),
                }
            }
            s.push_str("        ::omnisec_json::JsonValue::Object(__o)\n");
        }
        Kind::Enum(variants) => {
            s.push_str("        match self {\n");
            for (vi, v) in variants.iter().enumerate() {
                let key = variant_key(v, &inp.container);
                match &v.fields {
                    VFields::Unit => {
                        s.push_str(&format!(
                            "            Self::{} => ::omnisec_json::JsonValue::Str({key}.to_string()),\n",
                            v.name
                        ));
                    }
                    VFields::Unnamed(fs) if fs.len() == 1 => {
                        let expr = match &fs[0].1.with {
                            Some(m) => format!("{m}::to_json(__e0)"),
                            None => "::omnisec_json::ToJson::to_json(__e0)".to_string(),
                        };
                        s.push_str(&format!(
                            "            Self::{}(__e0) => ::omnisec_json::JsonValue::Object(vec![({key}.to_string(), {expr})]),\n",
                            v.name
                        ));
                    }
                    VFields::Unnamed(fs) => {
                        let pat: Vec<String> = (0..fs.len()).map(|i| format!("__e{i}")).collect();
                        let elems: Vec<String> = (0..fs.len())
                            .map(|i| match &fs[i].1.with {
                                Some(m) => format!("{m}::to_json(__e{i})"),
                                None => format!("::omnisec_json::ToJson::to_json(__e{i})"),
                            })
                            .collect();
                        s.push_str(&format!(
                            "            Self::{}({}) => ::omnisec_json::JsonValue::Object(vec![({key}.to_string(), ::omnisec_json::JsonValue::Array(vec![{}]))]),\n",
                            v.name,
                            pat.join(", "),
                            elems.join(", ")
                        ));
                    }
                    VFields::Named(fs) => {
                        // Rebind each field to a unique local: __v{vi}{field_index}.
                        let mut binds = String::new();
                        for (fi, f) in fs.iter().enumerate() {
                            binds.push_str(&format!("{}: __v{}{}, ", f.name, vi, fi));
                        }
                        s.push_str(&format!(
                            "            Self::{} {{ {binds} }} => {{\n                let mut __o: ::std::vec::Vec<(::std::string::String, ::omnisec_json::JsonValue)> = ::std::vec::Vec::new();\n",
                            v.name
                        ));
                        for (fi, f) in fs.iter().enumerate() {
                            if f.attr.skip {
                                continue;
                            }
                            let fkey = field_key(f, &inp.container);
                            let push = format!(
                                "__o.push(({fkey}.to_string(), {}));\n",
                                match &f.attr.with {
                                    Some(m) => format!("{m}::to_json(&__v{vi}{fi})"),
                                    None =>
                                        format!("::omnisec_json::ToJson::to_json(&__v{vi}{fi})"),
                                }
                            );
                            match &f.attr.skip_if {
                                Some(p) => s.push_str(&format!(
                                    "                if !{p}(&__v{vi}{fi}) {{\n                    {push}                }}\n"
                                )),
                                None => s.push_str(&format!("                {push}")),
                            }
                        }
                        s.push_str(&format!(
                            "                ::omnisec_json::JsonValue::Object(vec![({key}.to_string(), ::omnisec_json::JsonValue::Object(__o))])\n            }}\n"
                        ));
                    }
                }
            }
            s.push_str("        }\n");
        }
    }
    s.push_str("    }\n}\n");
    s
}

// ─── FromJson emission ──────────────────────────────────────────────────────

fn deser_field_expr(attr: &FieldAttr, val_expr: &str) -> String {
    match &attr.with {
        Some(m) => format!("{m}::from_json({val_expr})?"),
        None => format!("::omnisec_json::FromJson::from_json({val_expr})?"),
    }
}

fn missing_field_expr(f: &NamedField) -> String {
    if let Some(p) = &f.attr.default_path {
        return format!("{p}()");
    }
    if f.attr.default {
        return "::std::default::Default::default()".to_string();
    }
    deser_field_expr(&f.attr, "&::omnisec_json::JsonValue::Null")
}

fn emit_from_json(inp: &Input) -> String {
    let name = &inp.name;
    let mut s = String::new();
    s.push_str(&format!(
        "impl ::omnisec_json::FromJson for {name} {{\n    fn from_json(__v: &::omnisec_json::JsonValue) -> ::std::result::Result<Self, ::omnisec_json::JsonError> {{\n"
    ));
    match &inp.kind {
        Kind::Unit => {
            s.push_str("        ::std::result::Result::Ok(Self)\n");
        }
        Kind::Newtype => {
            s.push_str("        ::omnisec_json::FromJson::from_json(__v).map(Self)\n");
        }
        Kind::Tuple(fields) => {
            s.push_str(&format!(
                "        let __arr = match __v {{\n            ::omnisec_json::JsonValue::Array(a) => a,\n            _ => return ::std::result::Result::Err(::omnisec_json::JsonError(::std::format!(\"expected array for {name}\"))),\n        }};\n"
            ));
            s.push_str("        ::std::result::Result::Ok(Self(\n");
            for i in 0..fields.len() {
                s.push_str(&format!(
                    "            match __arr.get({i}) {{ ::std::option::Option::Some(x) => {}, ::std::option::Option::None => {} }},\n",
                    deser_field_expr(&FieldAttr::default(), "x"),
                    deser_field_expr(&FieldAttr::default(), "&::omnisec_json::JsonValue::Null"),
                ));
            }
            s.push_str("        ))\n");
        }
        Kind::Named(fields) => {
            s.push_str(&format!(
                "        let __o: &[(::std::string::String, ::omnisec_json::JsonValue)] = match __v {{\n            ::omnisec_json::JsonValue::Object(o) => o,\n            _ => return ::std::result::Result::Err(::omnisec_json::JsonError(::std::format!(\"expected object for {name}\"))),\n        }};\n"
            ));
            s.push_str(
                "        let __get = |k: &str| __o.iter().find(|(key, _)| key == k).map(|(_, v)| v);\n",
            );
            s.push_str("        ::std::result::Result::Ok(Self {\n");
            for f in fields {
                if f.attr.skip {
                    s.push_str(&format!(
                        "            {}: ::std::default::Default::default(),\n",
                        f.name
                    ));
                    continue;
                }
                if f.attr.flatten {
                    s.push_str(&format!(
                        "            {}: ::omnisec_json::FromJson::from_json(__v)?,\n",
                        f.name
                    ));
                    continue;
                }
                let key = field_key(f, &inp.container);
                let have = deser_field_expr(&f.attr, "__val");
                s.push_str(&format!(
                    "            {}: match __get({key}) {{\n                ::std::option::Option::Some(__val) => {have},\n                ::std::option::Option::None => {},\n            }},\n",
                    f.name,
                    missing_field_expr(f)
                ));
            }
            s.push_str("        })\n");
        }
        Kind::Enum(variants) => {
            s.push_str(&format!(
                "        let __err = || ::omnisec_json::JsonError(::std::format!(\"invalid variant for {name}\"));\n"
            ));
            s.push_str("        match __v {\n");
            // Unit variants via bare string.
            let unit_arms: Vec<String> = variants
                .iter()
                .filter(|v| matches!(v.fields, VFields::Unit))
                .map(|v| {
                    let key = variant_key(v, &inp.container);
                    format!(
                        "                {key} => ::std::result::Result::Ok(Self::{}),\n",
                        v.name
                    )
                })
                .collect();
            if !unit_arms.is_empty() {
                s.push_str(
                    "            ::omnisec_json::JsonValue::Str(sv) => match sv.as_str() {\n",
                );
                s.push_str(&unit_arms.concat());
                s.push_str(
                    "                _ => ::std::result::Result::Err(__err()),\n            },\n",
                );
            }
            s.push_str("            ::omnisec_json::JsonValue::Object(o) => {\n");
            s.push_str(
                "                let (__k, __val) = o.first().ok_or_else(|| ::omnisec_json::JsonError(::std::string::String::from(\"empty object for enum\")))?;\n",
            );
            s.push_str("                match __k.as_str() {\n");
            for v in variants
                .iter()
                .filter(|v| !matches!(v.fields, VFields::Unit))
            {
                let key = variant_key(v, &inp.container);
                let body = match &v.fields {
                    VFields::Unnamed(fs) if fs.len() == 1 => {
                        let e = deser_field_expr(&fs[0].1, "__val");
                        format!("::std::result::Result::Ok(Self::{}({e}))", v.name)
                    }
                    VFields::Unnamed(fs) => {
                        let mut b = String::new();
                        b.push_str(&format!(
                            "{{ let __arr = match __val {{ ::omnisec_json::JsonValue::Array(a) => a, _ => return ::std::result::Result::Err(__err()) }};\n"
                        ));
                        let mut args = Vec::new();
                        for (i, f) in fs.iter().enumerate() {
                            b.push_str(&format!(
                                "let __e{i} = match __arr.get({i}) {{ ::std::option::Option::Some(x) => {}, ::std::option::Option::None => {} }};\n",
                                deser_field_expr(&f.1, "x"),
                                deser_field_expr(&f.1, "&::omnisec_json::JsonValue::Null"),
                            ));
                            args.push(format!("__e{i}"));
                        }
                        format!(
                            "{b}::std::result::Result::Ok(Self::{}({})) }}",
                            v.name,
                            args.join(", ")
                        )
                    }
                    VFields::Named(fs) => {
                        let mut b = String::new();
                        b.push_str(
                            "{ let __fo: &[(::std::string::String, ::omnisec_json::JsonValue)] = match __val { ::omnisec_json::JsonValue::Object(o) => o, _ => return ::std::result::Result::Err(__err()) };\n",
                        );
                        b.push_str("let __fget = |k: &str| __fo.iter().find(|(key, _)| key == k).map(|(_, v)| v);\n");
                        let mut args = Vec::new();
                        for f in fs {
                            if f.attr.skip {
                                args.push(format!(
                                    "{}: ::std::default::Default::default()",
                                    f.name
                                ));
                                continue;
                            }
                            let fkey = field_key(f, &inp.container);
                            let have = deser_field_expr(&f.attr, "__fval");
                            args.push(format!(
                                "{}: match __fget({fkey}) {{ ::std::option::Option::Some(__fval) => {have}, ::std::option::Option::None => {} }}",
                                f.name,
                                missing_field_expr(f)
                            ));
                        }
                        format!(
                            "{b}::std::result::Result::Ok(Self::{} {{ {} }}) }}",
                            v.name,
                            args.join(", ")
                        )
                    }
                    VFields::Unit => unreachable!(),
                };
                s.push_str(&format!("                    {key} => {body},\n"));
            }
            s.push_str("                    _ => ::std::result::Result::Err(__err()),\n                }\n            }\n");
            s.push_str("            _ => ::std::result::Result::Err(__err()),\n        }\n");
        }
    }
    s.push_str("    }\n}\n");
    s
}

fn fail(msg: &str) -> TokenStream {
    format!("::core::compile_error!({msg:?});").parse().unwrap()
}

// ─── Macro entry points ─────────────────────────────────────────────────────

/// Derive `::omnisec_json::ToJson` for a struct or enum.
#[proc_macro_derive(ToJson, attributes(json))]
pub fn derive_to_json(input: TokenStream) -> TokenStream {
    match parse_input(input.clone()) {
        Ok(inp) => {
            let code = emit_to_json(&inp);
            if std::env::var_os("OMNISEC_JSON_DERIVE_DEBUG").is_some() {
                eprintln!("--- ToJson for {} ---\n{code}", inp.name);
            }
            code.parse().unwrap()
        }
        Err(e) => fail(&e),
    }
}

/// Derive `::omnisec_json::FromJson` for a struct or enum.
#[proc_macro_derive(FromJson, attributes(json))]
pub fn derive_from_json(input: TokenStream) -> TokenStream {
    match parse_input(input.clone()) {
        Ok(inp) => {
            let code = emit_from_json(&inp);
            if std::env::var_os("OMNISEC_JSON_DERIVE_DEBUG").is_some() {
                eprintln!("--- FromJson for {} ---\n{code}", inp.name);
            }
            code.parse().unwrap()
        }
        Err(e) => fail(&e),
    }
}
