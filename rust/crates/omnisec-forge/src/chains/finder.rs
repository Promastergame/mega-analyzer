//! Gadget finder.
//!
//! Walks a code blob looking for "tail-end" instruction sequences that end
//! in a terminator and reads/writes a small set of registers in between.
//! The walk is purely linear and deterministic, so the same image always
//! produces the same gadget index.
//!
//! Real-world per-arch decoders live in `crate::arch::*::decode_gadgets`;
//! this module just defines the index data type and an offline-friendly
//! "synthetic" gadget pool used by tests and by the abstract specs that
//! mitigation bypasses emit.

use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;

use super::gadget::{Gadget, GadgetCategory, GadgetSpec, RegisterEffect, Terminator};

/// JSON-friendly wrapper for the `(category, label)` index: JSON object keys
/// must be strings, so keys are stored as `"<category>|<label>"`.
#[derive(Debug, Clone, Default)]
pub struct LabelIndex(FxHashMap<(GadgetCategory, String), Vec<u64>>);

impl omnisec_json::ToJson for LabelIndex {
    fn to_json(&self) -> omnisec_json::JsonValue {
        let entries: Vec<(String, omnisec_json::JsonValue)> = self
            .0
            .iter()
            .map(|((cat, label), v)| (format!("{cat}|{label}"), v.to_json()))
            .collect();
        omnisec_json::JsonValue::Object(entries)
    }
}

impl omnisec_json::FromJson for LabelIndex {
    fn from_json(v: &omnisec_json::JsonValue) -> Result<Self, omnisec_json::JsonError> {
        let mut m = FxHashMap::new();
        if let omnisec_json::JsonValue::Object(entries) = v {
            for (k, val) in entries {
                let (cat, label) = k
                    .split_once('|')
                    .ok_or_else(|| omnisec_json::JsonError(format!("bad label index key: {k}")))?;
                let cat: GadgetCategory = cat
                    .parse()
                    .map_err(|e: String| omnisec_json::JsonError(e))?;
                m.insert((cat, label.to_string()), Vec::<u64>::from_json(val)?);
            }
        }
        Ok(Self(m))
    }
}

/// Gadget index: the assembler queries this when resolving abstract specs.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct GadgetFinder {
    /// All known gadgets, keyed by their address.
    by_address: FxHashMap<u64, Gadget>,
    /// All known gadgets keyed by `(category, label)` for fast spec lookup.
    by_label: LabelIndex,
}

impl GadgetFinder {
    /// Build an empty finder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a gadget, idempotently. Two inserts with the same address
    /// keep the first-seen gadget.
    pub fn insert(&mut self, gadget: Gadget) {
        let address = gadget.address;
        let key = (gadget.category, gadget.label.clone());
        let entry = self.by_address.entry(address).or_insert(gadget);
        let _ = entry;
        let list = self.by_label.0.entry(key).or_default();
        if !list.contains(&address) {
            list.push(address);
            list.sort_unstable();
        }
    }

    /// Look up a gadget by its concrete address.
    #[must_use]
    pub fn lookup(&self, address: u64) -> Option<&Gadget> {
        self.by_address.get(&address)
    }

    /// Resolve a [`GadgetSpec`] to a concrete gadget. If the spec pins an
    /// address, return that. Otherwise pick the lowest-address gadget
    /// matching `(category, label)` for determinism.
    #[must_use]
    pub fn resolve(&self, spec: &GadgetSpec) -> Option<&Gadget> {
        if let Some(addr) = spec.fixed_address {
            return self.lookup(addr);
        }
        let list = self.by_label.0.get(&(spec.category, spec.label.clone()))?;
        list.first().and_then(|a| self.lookup(*a))
    }

    /// All gadgets matching a category, deterministically ordered by
    /// address.
    pub fn by_category(&self, category: GadgetCategory) -> Vec<&Gadget> {
        let mut out: Vec<&Gadget> = self
            .by_address
            .values()
            .filter(|g| g.category == category)
            .collect();
        out.sort_by_key(|g| g.address);
        out
    }

    /// All gadgets that write `reg`, deterministically ordered.
    pub fn writers_of(&self, reg: &str) -> Vec<&Gadget> {
        let mut out: Vec<&Gadget> = self.by_address.values().filter(|g| g.writes(reg)).collect();
        out.sort_by_key(|g| g.address);
        out
    }

    /// Number of gadgets indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// `true` if there are no gadgets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }
}

/// Build the standard "synthetic" gadget pool the offline tests use. It
/// covers `pop rdi/rsi/rdx`, `mov rax,_`, `syscall ; ret`, plus an arch-neutral
/// `paciasp`-style placeholder. Addresses are deterministic constants in
/// the `0x4000_0000..` range.
#[must_use]
pub fn synthetic_pool() -> GadgetFinder {
    let mut f = GadgetFinder::new();
    let mut next_addr = 0x4000_0000u64;
    let mut push = |f: &mut GadgetFinder,
                    label: &str,
                    cat: GadgetCategory,
                    effect: RegisterEffect,
                    term: Terminator| {
        let addr = next_addr;
        next_addr = next_addr.wrapping_add(0x10);
        f.insert(Gadget {
            address: addr,
            effects: vec![effect],
            terminator: term,
            category: cat,
            label: label.into(),
            raw: Vec::new(),
            clobbers: Vec::new(),
        });
    };

    push(
        &mut f,
        "pop rdi ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("rdi", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop rsi ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("rsi", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop rdx ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("rdx", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop rax ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("rax", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop x0 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("x0", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop x1 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("x1", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop x2 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("x2", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop x3 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("x3", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop x8 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("x8", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop sp ; ret",
        GadgetCategory::StackPivot,
        RegisterEffect::load_const("sp", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop rsp ; ret",
        GadgetCategory::StackPivot,
        RegisterEffect::load_const("rsp", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop a0 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("a0", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop a1 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("a1", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop a2 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("a2", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop a7 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("a7", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop $a0 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("$a0", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop $a1 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("$a1", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop $a2 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("$a2", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop $v0 ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("$v0", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop $gp ; ret",
        GadgetCategory::PopReg,
        RegisterEffect::load_const("$gp", 0),
        Terminator::Ret,
    );
    push(
        &mut f,
        "pop $sp ; ret",
        GadgetCategory::StackPivot,
        RegisterEffect::load_const("$sp", 0),
        Terminator::Ret,
    );

    // Direct syscall stub.
    f.insert(Gadget::syscall(next_addr, vec![0x0F, 0x05, 0xC3]));
    next_addr = next_addr.wrapping_add(0x10);

    // PAC abstract.
    f.insert(Gadget {
        address: next_addr,
        effects: Vec::new(),
        terminator: Terminator::Ret,
        category: GadgetCategory::PacForge,
        label: "paciasp".into(),
        raw: Vec::new(),
        clobbers: Vec::new(),
    });
    next_addr = next_addr.wrapping_add(0x10);

    f.insert(Gadget {
        address: next_addr,
        effects: Vec::new(),
        terminator: Terminator::Ret,
        category: GadgetCategory::PacForge,
        label: "autiasp".into(),
        raw: Vec::new(),
        clobbers: Vec::new(),
    });
    next_addr = next_addr.wrapping_add(0x10);
    f.insert(Gadget {
        address: next_addr,
        effects: Vec::new(),
        terminator: Terminator::Ret,
        category: GadgetCategory::PacForge,
        label: "xpaclri".into(),
        raw: Vec::new(),
        clobbers: Vec::new(),
    });

    let mut more = next_addr.wrapping_add(0x10);
    // CFI stubs, stack pivot, syscall labels for various arches.
    for label in [
        "type_confused_call",
        "stack_pivot",
        "mprotect",
        "csrrw_mepc",
        "mret",
        "ghostwrite_stub",
    ] {
        let cat = match label {
            "type_confused_call" => GadgetCategory::CfiCompliant,
            "stack_pivot" => GadgetCategory::StackPivot,
            "mprotect" => GadgetCategory::SyscallStub,
            "csrrw_mepc" | "mret" => GadgetCategory::PrivEscalation,
            "ghostwrite_stub" => GadgetCategory::HardwareFault,
            _ => GadgetCategory::Other,
        };
        f.insert(Gadget {
            address: more,
            effects: Vec::new(),
            terminator: Terminator::Ret,
            category: cat,
            label: label.into(),
            raw: Vec::new(),
            clobbers: Vec::new(),
        });
        more = more.wrapping_add(0x10);
    }

    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finder_resolves_by_label_deterministically() {
        let f = synthetic_pool();
        let spec = GadgetSpec::abstract_(GadgetCategory::PopReg, "pop rdi ; ret");
        let g = f.resolve(&spec).unwrap();
        assert_eq!(g.label, "pop rdi ; ret");
    }

    #[test]
    fn writers_of_returns_lowest_address_first() {
        let f = synthetic_pool();
        let writers = f.writers_of("rdi");
        assert!(!writers.is_empty());
        assert!(writers.iter().all(|g| g.writes("rdi")));
        let mut prev = 0u64;
        for g in writers {
            assert!(g.address >= prev);
            prev = g.address;
        }
    }
}
