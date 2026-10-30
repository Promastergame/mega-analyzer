use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;

#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct D {
    inner: FxHashMap<String, Inner>,
    extra: u32,
}

#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct Inner {
    x: u32,
}
