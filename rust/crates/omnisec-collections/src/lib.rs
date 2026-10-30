//! Zero-dependency collections (replaces `indexmap`, `rustc-hash`, `smallvec`).
//!
//! - [`FxHashMap`] / [`FxHashSet`] are `std` aliases (SipHash). Same API as
//!   `rustc-hash` for mechanical migration.
//! - [`IndexMap`] / [`IndexSet`] preserve insertion order (subset of indexmap).
//! - [`SmallVec`] is a `Vec` alias + [`vec!`] macro.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Fast hash map alias (std-backed; API-compatible with `FxHashMap`).
pub type FxHashMap<K, V> = HashMap<K, V>;
/// Fast hash set alias (std-backed; API-compatible with `FxHashSet`).
pub type FxHashSet<T> = HashSet<T>;

/// Small-vector alias. Inline capacity is ignored (heap `Vec`), but the type
/// and macro shape stay identical so `SmallVec<[T; N]>` call-sites compile.
pub type SmallVec<T> = Vec<T>;

/// Build a [`Vec`] with `vec!` syntax.
///
/// Supports `vec![]`, `vec![x; n]`, `vec![a, b, c]`.
#[macro_export]
macro_rules! smallvec {
    () => {
        Vec::new()
    };
    ($elem:expr; $n:expr) => {
        vec![$elem; $n]
    };
    ($($x:expr),* $(,)?) => {
        vec![$($x),*]
    };
}

/// Insertion-ordered map: subset of `indexmap::IndexMap` on std only.
#[derive(Debug, Clone, Default)]
pub struct IndexMap<K, V> {
    keys: Vec<K>,
    map: HashMap<K, usize>,
    values: Vec<V>,
}

impl<K: Eq + Hash + Clone, V> IndexMap<K, V> {
    /// Empty map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            map: HashMap::new(),
            values: Vec::new(),
        }
    }

    /// Empty map with capacity.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            keys: Vec::with_capacity(n),
            map: HashMap::with_capacity(n),
            values: Vec::with_capacity(n),
        }
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Insert or replace. Returns old value on replace.
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        if let Some(&idx) = self.map.get(&k) {
            Some(std::mem::replace(&mut self.values[idx], v))
        } else {
            let idx = self.keys.len();
            self.map.insert(k.clone(), idx);
            self.keys.push(k);
            self.values.push(v);
            None
        }
    }

    /// Borrow by key.
    #[must_use]
    pub fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k).map(|&i| &self.values[i])
    }

    /// Mutably borrow by key.
    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        self.map.get(k).copied().map(|i| &mut self.values[i])
    }

    /// `true` if key present.
    #[must_use]
    pub fn contains_key(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }

    /// Remove by key (order of remaining entries is preserved).
    pub fn shift_remove(&mut self, k: &K) -> Option<V> {
        let idx = self.map.remove(k)?;
        self.keys.remove(idx);
        let v = self.values.remove(idx);
        for (i, key) in self.keys.iter().enumerate().skip(idx) {
            if let Some(slot) = self.map.get_mut(key) {
                *slot = i;
            }
        }
        Some(v)
    }

    /// Alias for `shift_remove` (indexmap compat).
    pub fn swap_remove(&mut self, k: &K) -> Option<V> {
        self.shift_remove(k)
    }

    /// Get by insertion index.
    #[must_use]
    pub fn get_index(&self, idx: usize) -> Option<(&K, &V)> {
        Some((self.keys.get(idx)?, self.values.get(idx)?))
    }

    /// Iterate in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.keys.iter().zip(self.values.iter())
    }

    /// Mutably iterate in insertion order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.keys.iter().zip(self.values.iter_mut())
    }

    /// Keys in insertion order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.keys.iter()
    }

    /// Values in insertion order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.values.iter()
    }

    /// Retain entries matching predicate.
    pub fn retain(&mut self, mut f: impl FnMut(&K, &mut V) -> bool) {
        let mut i = 0;
        while i < self.keys.len() {
            let keep = {
                let k = &self.keys[i];
                let v = &mut self.values[i];
                f(k, v)
            };
            if keep {
                i += 1;
            } else {
                let k = self.keys.remove(i);
                self.values.remove(i);
                self.map.remove(&k);
                for (j, key) in self.keys.iter().enumerate().skip(i) {
                    if let Some(slot) = self.map.get_mut(key) {
                        *slot = j;
                    }
                }
            }
        }
    }
}

impl<K: Eq + Hash + Clone, V> PartialEq for IndexMap<K, V>
where
    V: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().all(|(k, v)| other.get(k) == Some(v))
    }
}
impl<K: Eq + Hash + Clone, V> Eq for IndexMap<K, V> where V: Eq {}

impl<K: Eq + Hash + Clone, V> std::ops::Index<&K> for IndexMap<K, V> {
    type Output = V;
    fn index(&self, k: &K) -> &V {
        self.get(k).expect("indexmap: no entry for key")
    }
}

impl<K: Eq + Hash + Clone, V> FromIterator<(K, V)> for IndexMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut m = Self::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

/// Insertion-ordered set: subset of `indexmap::IndexSet` on std only.
#[derive(Debug, Clone, Default)]
pub struct IndexSet<T> {
    inner: IndexMap<T, ()>,
}

impl<T: Eq + Hash + Clone> IndexSet<T> {
    /// Empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: IndexMap::new(),
        }
    }

    /// Insert. Returns `true` if newly inserted.
    pub fn insert(&mut self, v: T) -> bool {
        self.inner.insert(v, ()).is_none()
    }

    /// `true` if present.
    #[must_use]
    pub fn contains(&self, v: &T) -> bool {
        self.inner.contains_key(v)
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexmap_preserves_order() {
        let mut m: IndexMap<String, i32> = IndexMap::new();
        m.insert("b".to_string(), 2);
        m.insert("a".to_string(), 1);
        m.insert("c".to_string(), 3);
        let keys: Vec<_> = m.keys().cloned().collect();
        assert_eq!(keys, vec!["b", "a", "c"]);
        assert_eq!(m.get(&"a".to_string()), Some(&1));
        m.shift_remove(&"a".to_string());
        assert!(!m.contains_key(&"a".to_string()));
        let keys2: Vec<_> = m.keys().cloned().collect();
        assert_eq!(keys2, vec!["b", "c"]);
    }

    #[test]
    fn smallvec_macro_shapes() {
        let a: Vec<i32> = vec![];
        let b = vec![1, 2, 3];
        let c = vec![0u8; 4];
        assert!(a.is_empty());
        assert_eq!(b, vec![1, 2, 3]);
        assert_eq!(c, vec![0, 0, 0, 0]);
    }

    #[test]
    fn fx_aliases_work() {
        let mut m: FxHashMap<u32, u32> = FxHashMap::default();
        m.insert(1, 2);
        let mut s: FxHashSet<u32> = FxHashSet::default();
        s.insert(1);
        assert_eq!(m.get(&1), Some(&2));
        assert!(s.contains(&1));
    }
}
