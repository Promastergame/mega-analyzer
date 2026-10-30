//! Synthetic Anchor Forge for the first ML-Aetrium vulnerability dataset.

use crate::codebook::{
    CodeBook, ControlFlowTag, LifecycleStage, MemoryAccessTag, SyscallProximity,
};
use crate::{Anchor, AnchorStore, AnchorStoreMetadata, EdgeType, HyperVector, SubgraphEncoder};

const OP_MOVE: u32 = 1;
const OP_ADD: u32 = 2;
const OP_COMPARE: u32 = 20;
const OP_LOAD: u32 = 22;
const OP_STORE: u32 = 23;
const OP_CALL: u32 = 30;
const OP_SYSTEM_CALL: u32 = 37;

/// Synthetic vulnerability families that can be forged into anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyntheticBugKind {
    /// Use-after-free: a heap object is used after a free operation.
    UseAfterFree,
    /// Heap buffer overflow: an unchecked heap write depends on an attacker-controlled index.
    HeapBufferOverflow,
    /// Double free: the same heap allocation flows into two free operations.
    DoubleFree,
    /// Command injection: attacker-controlled data reaches an execution syscall.
    CommandInjection,
    /// Integer overflow leading to heap corruption: multiplication wraps before allocation.
    IntegerOverflow,
    /// Uninitialized memory disclosure: stack struct passed to copy_to_user without full initialization.
    UninitializedMemory,

    // ─── Phase-3 expansion: structural motifs derived from MITRE Top-25 ───
    /// Stack buffer overflow: bounded write to a stack buffer with attacker-controlled size.
    StackBufferOverflow,
    /// Format string vulnerability: untrusted data reaches printf-family formatters.
    FormatString,
    /// Out-of-bounds read: load from a heap address derived from an unchecked index.
    OutOfBoundsRead,
    /// Out-of-bounds write: store to a heap address derived from an unchecked index.
    OutOfBoundsWrite,
    /// Null-pointer dereference: load/store through a pointer not validated against null.
    NullDereference,
    /// Off-by-one error: bounds check using strict comparison where ≤ was required.
    OffByOne,
    /// Integer underflow: signed/unsigned subtraction wraps around past zero.
    IntegerUnderflow,
    /// Time-of-check / time-of-use race: stat/access then open without atomic guarantees.
    TimeOfCheckTimeOfUse,
    /// Improper input validation: tainted data flows into a privileged sink without sanitization.
    ImproperValidation,
    /// Path traversal: attacker-controlled path component reaches an open/openat syscall.
    PathTraversal,
    /// Type confusion: cast between incompatible struct types lets one path read foreign fields.
    TypeConfusion,
    /// SQL injection: untrusted string concatenation reaches a query execution sink.
    SqlInjection,
    /// Race condition (data race): shared mutable memory written without synchronization.
    RaceCondition,
    /// Deserialization of untrusted data: tainted bytes reach a structured-decode sink.
    UnsafeDeserialization,
    /// Hard-coded credentials: literal credential reaches an authentication sink.
    HardcodedCredentials,
    /// Weak / broken cryptography: small key, deprecated cipher, or non-CSPRNG seed.
    WeakCrypto,
    /// SSRF: untrusted URL component reaches a network-fetch sink.
    ServerSideRequestForgery,
    /// XXE: tainted XML reaches a parser with external-entity resolution enabled.
    XmlExternalEntity,
}

impl SyntheticBugKind {
    /// All built-in synthetic vulnerability families.
    pub const ALL: [Self; 24] = [
        Self::UseAfterFree,
        Self::HeapBufferOverflow,
        Self::DoubleFree,
        Self::CommandInjection,
        Self::IntegerOverflow,
        Self::UninitializedMemory,
        Self::StackBufferOverflow,
        Self::FormatString,
        Self::OutOfBoundsRead,
        Self::OutOfBoundsWrite,
        Self::NullDereference,
        Self::OffByOne,
        Self::IntegerUnderflow,
        Self::TimeOfCheckTimeOfUse,
        Self::ImproperValidation,
        Self::PathTraversal,
        Self::TypeConfusion,
        Self::SqlInjection,
        Self::RaceCondition,
        Self::UnsafeDeserialization,
        Self::HardcodedCredentials,
        Self::WeakCrypto,
        Self::ServerSideRequestForgery,
        Self::XmlExternalEntity,
    ];

    /// Stable anchor name for this vulnerability family.
    #[must_use]
    pub const fn anchor_name(self) -> &'static str {
        match self {
            Self::UseAfterFree => "use_after_free",
            Self::HeapBufferOverflow => "heap_buffer_overflow",
            Self::DoubleFree => "double_free",
            Self::CommandInjection => "command_injection",
            Self::IntegerOverflow => "integer_overflow",
            Self::UninitializedMemory => "uninitialized_memory",
            Self::StackBufferOverflow => "stack_buffer_overflow",
            Self::FormatString => "format_string",
            Self::OutOfBoundsRead => "oob_read",
            Self::OutOfBoundsWrite => "oob_write",
            Self::NullDereference => "null_dereference",
            Self::OffByOne => "off_by_one",
            Self::IntegerUnderflow => "integer_underflow",
            Self::TimeOfCheckTimeOfUse => "toctou",
            Self::ImproperValidation => "improper_validation",
            Self::PathTraversal => "path_traversal",
            Self::TypeConfusion => "type_confusion",
            Self::SqlInjection => "sql_injection",
            Self::RaceCondition => "race_condition",
            Self::UnsafeDeserialization => "unsafe_deserialization",
            Self::HardcodedCredentials => "hardcoded_credentials",
            Self::WeakCrypto => "weak_crypto",
            Self::ServerSideRequestForgery => "ssrf",
            Self::XmlExternalEntity => "xxe",
        }
    }

    /// Human-readable CWE description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::UseAfterFree => "CWE-416: Use After Free",
            Self::HeapBufferOverflow => "CWE-122: Heap-based Buffer Overflow",
            Self::DoubleFree => "CWE-415: Double Free",
            Self::CommandInjection => "CWE-78: OS Command Injection",
            Self::IntegerOverflow => "CWE-190: Integer Overflow to Buffer Overflow",
            Self::UninitializedMemory => {
                "CWE-908: Use of Uninitialized Resource (Memory Disclosure)"
            }
            Self::StackBufferOverflow => "CWE-121: Stack-based Buffer Overflow",
            Self::FormatString => "CWE-134: Use of Externally-Controlled Format String",
            Self::OutOfBoundsRead => "CWE-125: Out-of-bounds Read",
            Self::OutOfBoundsWrite => "CWE-787: Out-of-bounds Write",
            Self::NullDereference => "CWE-476: NULL Pointer Dereference",
            Self::OffByOne => "CWE-193: Off-by-one Error",
            Self::IntegerUnderflow => "CWE-191: Integer Underflow",
            Self::TimeOfCheckTimeOfUse => "CWE-367: TOCTOU Race Condition",
            Self::ImproperValidation => "CWE-20: Improper Input Validation",
            Self::PathTraversal => "CWE-22: Path Traversal",
            Self::TypeConfusion => "CWE-843: Access of Resource Using Incompatible Type",
            Self::SqlInjection => "CWE-89: SQL Injection",
            Self::RaceCondition => "CWE-362: Concurrent Execution using Shared Resource",
            Self::UnsafeDeserialization => "CWE-502: Deserialization of Untrusted Data",
            Self::HardcodedCredentials => "CWE-798: Use of Hard-coded Credentials",
            Self::WeakCrypto => "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            Self::ServerSideRequestForgery => "CWE-918: Server-Side Request Forgery (SSRF)",
            Self::XmlExternalEntity => "CWE-611: XML External Entity",
        }
    }

    /// Default severity score.
    #[must_use]
    pub const fn severity(self) -> f64 {
        match self {
            Self::UseAfterFree => 0.92,
            Self::HeapBufferOverflow => 0.90,
            Self::DoubleFree => 0.88,
            Self::CommandInjection => 0.95,
            Self::IntegerOverflow => 0.94,
            Self::UninitializedMemory => 0.91,
            Self::StackBufferOverflow => 0.91,
            Self::FormatString => 0.93,
            Self::OutOfBoundsRead => 0.85,
            Self::OutOfBoundsWrite => 0.93,
            Self::NullDereference => 0.78,
            Self::OffByOne => 0.83,
            Self::IntegerUnderflow => 0.92,
            Self::TimeOfCheckTimeOfUse => 0.86,
            Self::ImproperValidation => 0.87,
            Self::PathTraversal => 0.89,
            Self::TypeConfusion => 0.88,
            Self::SqlInjection => 0.94,
            Self::RaceCondition => 0.84,
            Self::UnsafeDeserialization => 0.92,
            Self::HardcodedCredentials => 0.80,
            Self::WeakCrypto => 0.78,
            Self::ServerSideRequestForgery => 0.90,
            Self::XmlExternalEntity => 0.88,
        }
    }

    /// Default Jaccard threshold for this vulnerability family.
    #[must_use]
    pub const fn threshold(self) -> f64 {
        match self {
            Self::UseAfterFree => 0.82,
            Self::HeapBufferOverflow => 0.11,
            Self::DoubleFree => 0.12,
            Self::CommandInjection => 0.10,
            Self::IntegerOverflow => 0.13,
            Self::UninitializedMemory => 0.14,
            Self::StackBufferOverflow => 0.12,
            Self::FormatString => 0.11,
            Self::OutOfBoundsRead => 0.13,
            Self::OutOfBoundsWrite => 0.12,
            Self::NullDereference => 0.15,
            Self::OffByOne => 0.16,
            Self::IntegerUnderflow => 0.13,
            Self::TimeOfCheckTimeOfUse => 0.14,
            Self::ImproperValidation => 0.15,
            Self::PathTraversal => 0.12,
            Self::TypeConfusion => 0.14,
            Self::SqlInjection => 0.10,
            Self::RaceCondition => 0.16,
            Self::UnsafeDeserialization => 0.12,
            Self::HardcodedCredentials => 0.18,
            Self::WeakCrypto => 0.18,
            Self::ServerSideRequestForgery => 0.11,
            Self::XmlExternalEntity => 0.12,
        }
    }

    /// Explainable motifs attached to matches from this family.
    #[must_use]
    pub fn motifs(self) -> Vec<String> {
        match self {
            Self::UseAfterFree => vec![
                "invalid lifetime dependency".to_string(),
                "free/use topology motif".to_string(),
                "post-free heap access".to_string(),
            ],
            Self::HeapBufferOverflow => vec![
                "unchecked heap write".to_string(),
                "index-to-store data dependency".to_string(),
            ],
            Self::DoubleFree => vec![
                "duplicate deallocation".to_string(),
                "shared heap alias reaches multiple frees".to_string(),
            ],
            Self::CommandInjection => vec![
                "untrusted data reaches exec sink".to_string(),
                "syscall-proximal command argument".to_string(),
            ],
            Self::IntegerOverflow => vec![
                "unsigned wrap-around".to_string(),
                "allocation size overflow".to_string(),
                "input-dependent arithmetic flow".to_string(),
            ],
            Self::UninitializedMemory => vec![
                "stack padding disclosure".to_string(),
                "kernel-to-user memory leak".to_string(),
                "partial initialization before copy_to_user".to_string(),
            ],
            Self::StackBufferOverflow => vec![
                "tainted size reaches stack memcpy".to_string(),
                "fixed-size stack buffer fed variable-length input".to_string(),
            ],
            Self::FormatString => vec![
                "untrusted format specifier".to_string(),
                "printf-family with attacker-controlled first arg".to_string(),
            ],
            Self::OutOfBoundsRead => vec![
                "load through index lacking upper-bound check".to_string(),
                "data flow from input to load address".to_string(),
            ],
            Self::OutOfBoundsWrite => vec![
                "store through index lacking upper-bound check".to_string(),
                "data flow from input to store address".to_string(),
            ],
            Self::NullDereference => vec![
                "load/store after possibly-null call result".to_string(),
                "missing null-check between alloc and use".to_string(),
            ],
            Self::OffByOne => vec![
                "compare-with-strict-< near loop bound".to_string(),
                "iteration-count to size-of mismatch".to_string(),
            ],
            Self::IntegerUnderflow => vec![
                "subtraction wraps below zero on unsigned operand".to_string(),
                "result reused as size or index".to_string(),
            ],
            Self::TimeOfCheckTimeOfUse => vec![
                "stat/access then open with no atomicity".to_string(),
                "non-atomic check-then-act on filesystem object".to_string(),
            ],
            Self::ImproperValidation => vec![
                "tainted argument reaches privileged sink".to_string(),
                "missing range check on user input".to_string(),
            ],
            Self::PathTraversal => vec![
                "untrusted segment reaches openat".to_string(),
                "no canonicalisation between input and fs syscall".to_string(),
            ],
            Self::TypeConfusion => vec![
                "ptr cast across incompatible record types".to_string(),
                "field-offset access after downcast".to_string(),
            ],
            Self::SqlInjection => vec![
                "string concatenation reaches query exec".to_string(),
                "tainted parameter spliced into SQL literal".to_string(),
            ],
            Self::RaceCondition => vec![
                "shared write without lock acquisition".to_string(),
                "interleaved reader and writer on same address".to_string(),
            ],
            Self::UnsafeDeserialization => vec![
                "untrusted bytes reach structured decoder".to_string(),
                "polymorphic decode without type allowlist".to_string(),
            ],
            Self::HardcodedCredentials => vec![
                "literal credential reaches authentication call".to_string(),
                "compile-time secret embedded in binary".to_string(),
            ],
            Self::WeakCrypto => vec![
                "deprecated cipher (DES, MD5) initialized".to_string(),
                "non-CSPRNG seeds key-derivation primitive".to_string(),
            ],
            Self::ServerSideRequestForgery => vec![
                "tainted URL component reaches HTTP fetch".to_string(),
                "input drives outbound request target".to_string(),
            ],
            Self::XmlExternalEntity => vec![
                "external-entity resolution enabled on tainted XML".to_string(),
                "DOCTYPE/ENTITY processed in untrusted document".to_string(),
            ],
        }
    }
}

/// Configuration for synthetic anchor generation.
#[derive(Debug, Clone)]
pub struct ForgeConfig {
    /// Master seed for deterministic codebook generation.
    pub seed: u64,
    /// Number of exact topology examples generated per vulnerability family.
    pub examples_per_kind: usize,
    /// Number of noisy perturbations added per exact topology example.
    pub variants_per_example: usize,
    /// Fraction of HV bits flipped for each noisy perturbation.
    pub noise_ratio: f64,
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            examples_per_kind: 3,
            variants_per_example: 8,
            noise_ratio: 0.025,
        }
    }
}

/// A synthetic edge in a forged vulnerability PDG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticEdge {
    /// Source node index.
    pub source: usize,
    /// Target node index.
    pub target: usize,
    /// Dependency category used by topology-aware HDC binding.
    pub edge_type: EdgeType,
}

impl SyntheticEdge {
    /// Create a new synthetic PDG edge.
    #[must_use]
    pub const fn new(source: usize, target: usize, edge_type: EdgeType) -> Self {
        Self {
            source,
            target,
            edge_type,
        }
    }

    fn as_encoder_tuple(self) -> (usize, usize, EdgeType) {
        (self.source, self.target, self.edge_type)
    }
}

/// A synthetic vulnerability PDG encoded as node HVs plus typed dependencies.
#[derive(Debug, Clone)]
pub struct SyntheticPdg {
    /// Vulnerability family represented by this PDG.
    pub kind: SyntheticBugKind,
    /// Node semantic hypervectors.
    pub node_hvs: Vec<HyperVector>,
    /// Typed topology edges between node indices.
    pub edges: Vec<SyntheticEdge>,
    /// Human-readable motifs represented by this PDG.
    pub motifs: Vec<String>,
}

/// Generates synthetic vulnerability motifs and builds mutated HDC anchors.
#[derive(Debug)]
pub struct AnchorForge {
    config: ForgeConfig,
    codebook: CodeBook,
    subgraph_encoder: SubgraphEncoder,
}

impl AnchorForge {
    /// Create an anchor forge with the given deterministic codebook seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self::with_config(ForgeConfig {
            seed,
            ..ForgeConfig::default()
        })
    }

    /// Create an anchor forge from an explicit configuration.
    #[must_use]
    pub fn with_config(config: ForgeConfig) -> Self {
        Self {
            codebook: CodeBook::new(config.seed),
            subgraph_encoder: SubgraphEncoder::new(),
            config,
        }
    }

    /// Return the active forge configuration.
    #[must_use]
    pub const fn config(&self) -> &ForgeConfig {
        &self.config
    }

    /// Build anchors for every built-in synthetic vulnerability family.
    pub fn build_default_store(&mut self) -> AnchorStore {
        self.build_store(&SyntheticBugKind::ALL)
    }

    /// Build anchors for selected synthetic vulnerability families.
    pub fn build_store(&mut self, kinds: &[SyntheticBugKind]) -> AnchorStore {
        let mut store = AnchorStore::new();
        store.set_metadata(AnchorStoreMetadata {
            generator: "omnisec-hdc::AnchorForge".to_string(),
            codebook_seed: Some(self.config.seed),
            examples_per_kind: Some(self.config.examples_per_kind),
            variants_per_example: Some(self.config.variants_per_example),
            noise_ratio: Some(self.config.noise_ratio),
            ..AnchorStoreMetadata::default()
        });
        for &kind in kinds {
            store.add(self.build_anchor(kind));
        }
        store
    }

    /// Build one mutated anchor from generated exact topology examples.
    pub fn build_anchor(&mut self, kind: SyntheticBugKind) -> Anchor {
        let graphs = self.generate_graphs(kind);
        let examples: Vec<HyperVector> = graphs
            .iter()
            .map(|graph| self.encode_graph(graph))
            .collect();

        AnchorStore::build_mutated_anchor(
            kind.anchor_name(),
            kind.description(),
            &examples,
            self.config.variants_per_example,
            self.config.noise_ratio,
            kind.threshold(),
            kind.severity(),
            kind.motifs(),
        )
    }

    /// Generate exact synthetic PDG motifs for a vulnerability family.
    pub fn generate_graphs(&mut self, kind: SyntheticBugKind) -> Vec<SyntheticPdg> {
        let count = self.config.examples_per_kind.max(1);
        (0..count)
            .map(|variant| self.generate_graph(kind, variant))
            .collect()
    }

    /// Encode a synthetic PDG into a topology-preserving hypervector.
    #[must_use]
    pub fn encode_graph(&self, graph: &SyntheticPdg) -> HyperVector {
        let edges: Vec<(usize, usize, EdgeType)> = graph
            .edges
            .iter()
            .map(|edge| edge.as_encoder_tuple())
            .collect();
        self.subgraph_encoder
            .encode_subgraph_confidence(&graph.node_hvs, &edges)
    }

    fn generate_graph(&mut self, kind: SyntheticBugKind, variant: usize) -> SyntheticPdg {
        match kind {
            SyntheticBugKind::UseAfterFree => self.use_after_free_graph(variant),
            SyntheticBugKind::HeapBufferOverflow => self.heap_buffer_overflow_graph(variant),
            SyntheticBugKind::DoubleFree => self.double_free_graph(variant),
            SyntheticBugKind::CommandInjection => self.command_injection_graph(variant),
            SyntheticBugKind::IntegerOverflow => self.integer_overflow_graph(variant),
            SyntheticBugKind::UninitializedMemory => self.uninitialized_memory_graph(variant),
            SyntheticBugKind::StackBufferOverflow => self.stack_buffer_overflow_graph(variant),
            SyntheticBugKind::FormatString => self.format_string_graph(variant),
            SyntheticBugKind::OutOfBoundsRead => self.oob_read_graph(variant),
            SyntheticBugKind::OutOfBoundsWrite => self.oob_write_graph(variant),
            SyntheticBugKind::NullDereference => self.null_deref_graph(variant),
            SyntheticBugKind::OffByOne => self.off_by_one_graph(variant),
            SyntheticBugKind::IntegerUnderflow => self.integer_underflow_graph(variant),
            SyntheticBugKind::TimeOfCheckTimeOfUse => self.toctou_graph(variant),
            SyntheticBugKind::ImproperValidation => self.improper_validation_graph(variant),
            SyntheticBugKind::PathTraversal => self.path_traversal_graph(variant),
            SyntheticBugKind::TypeConfusion => self.type_confusion_graph(variant),
            SyntheticBugKind::SqlInjection => self.sql_injection_graph(variant),
            SyntheticBugKind::RaceCondition => self.race_condition_graph(variant),
            SyntheticBugKind::UnsafeDeserialization => self.unsafe_deserialization_graph(variant),
            SyntheticBugKind::HardcodedCredentials => self.hardcoded_credentials_graph(variant),
            SyntheticBugKind::WeakCrypto => self.weak_crypto_graph(variant),
            SyntheticBugKind::ServerSideRequestForgery => self.ssrf_graph(variant),
            SyntheticBugKind::XmlExternalEntity => self.xxe_graph(variant),
        }
    }

    fn use_after_free_graph(&mut self, variant: usize) -> SyntheticPdg {
        let mut nodes = vec![
            self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall),
            self.move_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall),
            self.call_node(LifecycleStage::Freed, SyscallProximity::FarFromSyscall),
            self.heap_load_node(
                LifecycleStage::PostFreeUse,
                SyscallProximity::FarFromSyscall,
            ),
        ];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::Data),
            SyntheticEdge::new(0, 2, EdgeType::HeapAlias),
            SyntheticEdge::new(1, 3, EdgeType::Data),
            SyntheticEdge::new(2, 3, EdgeType::HeapAlias),
            // Sequential order within the block.
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
            SyntheticEdge::new(2, 3, EdgeType::Sequential),
        ];

        if variant % 2 == 1 {
            nodes.push(self.compare_node(LifecycleStage::Freed, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(4, 3, EdgeType::Control));
        }

        SyntheticPdg {
            kind: SyntheticBugKind::UseAfterFree,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::UseAfterFree.motifs(),
        }
    }

    fn heap_buffer_overflow_graph(&mut self, variant: usize) -> SyntheticPdg {
        let mut nodes = vec![
            self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall),
            self.add_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall),
            self.heap_store_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall),
        ];
        let mut edges = vec![
            SyntheticEdge::new(0, 2, EdgeType::HeapAlias),
            SyntheticEdge::new(1, 2, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];

        if !variant.is_multiple_of(3) {
            nodes.push(self.compare_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(3, 2, EdgeType::Control));
        }

        SyntheticPdg {
            kind: SyntheticBugKind::HeapBufferOverflow,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::HeapBufferOverflow.motifs(),
        }
    }

    fn double_free_graph(&mut self, variant: usize) -> SyntheticPdg {
        let mut nodes = vec![
            self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall),
            self.move_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall),
            self.call_node(LifecycleStage::Freed, SyscallProximity::FarFromSyscall),
            self.call_node(LifecycleStage::Freed, SyscallProximity::FarFromSyscall),
        ];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::Data),
            SyntheticEdge::new(0, 2, EdgeType::HeapAlias),
            SyntheticEdge::new(0, 3, EdgeType::HeapAlias),
            SyntheticEdge::new(2, 3, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
            SyntheticEdge::new(2, 3, EdgeType::Sequential),
        ];

        if variant.is_multiple_of(2) {
            nodes.push(self.compare_node(LifecycleStage::Freed, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(4, 3, EdgeType::Control));
        }

        SyntheticPdg {
            kind: SyntheticBugKind::DoubleFree,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::DoubleFree.motifs(),
        }
    }

    fn command_injection_graph(&mut self, variant: usize) -> SyntheticPdg {
        let mut nodes = vec![
            self.heap_load_node(LifecycleStage::Unknown, SyscallProximity::NearSyscall),
            self.move_node(LifecycleStage::Unknown, SyscallProximity::PreSyscall),
            self.syscall_node(LifecycleStage::Unknown, SyscallProximity::IsSyscall),
        ];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::Data),
            SyntheticEdge::new(1, 2, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];

        if variant % 2 == 1 {
            nodes.push(self.compare_node(LifecycleStage::Unknown, SyscallProximity::PreSyscall));
            edges.push(SyntheticEdge::new(3, 2, EdgeType::Control));
        }

        SyntheticPdg {
            kind: SyntheticBugKind::CommandInjection,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::CommandInjection.motifs(),
        }
    }

    fn integer_overflow_graph(&mut self, variant: usize) -> SyntheticPdg {
        let mut nodes = vec![
            self.call_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall), // input
            self.add_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall), // mul/add (overflow)
            self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall), // malloc
            self.call_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall),  // memcpy
        ];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::Data), // input -> math
            SyntheticEdge::new(1, 2, EdgeType::Data), // math -> malloc
            SyntheticEdge::new(2, 3, EdgeType::HeapAlias), // malloc -> memcpy (dest)
            SyntheticEdge::new(0, 3, EdgeType::Data), // input -> memcpy (count)
            // Sequential flow
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
            SyntheticEdge::new(2, 3, EdgeType::Sequential),
        ];

        if variant % 2 == 1 {
            nodes
                .push(self.compare_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(4, 1, EdgeType::Control));
        }

        SyntheticPdg {
            kind: SyntheticBugKind::IntegerOverflow,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::IntegerOverflow.motifs(),
        }
    }

    fn uninitialized_memory_graph(&mut self, variant: usize) -> SyntheticPdg {
        let mut nodes = vec![
            self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall), // alloc struct (e.g., alloca or kmalloc)
            self.heap_store_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall), // partial write field 1
            self.heap_store_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall), // partial write field 2
            self.call_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall), // copy_to_user / send
        ];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::HeapAlias), // alloc -> field 1
            SyntheticEdge::new(0, 2, EdgeType::HeapAlias), // alloc -> field 2
            SyntheticEdge::new(0, 3, EdgeType::HeapAlias), // alloc -> copy (entire struct)
            // Note: No Data edge from writes to copy, because copy reads the whole struct, not just written fields.
            // This lack of complete data dependency covering the whole struct size is the core motif.

            // Sequential flow
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
            SyntheticEdge::new(2, 3, EdgeType::Sequential),
        ];

        if variant % 2 == 1 {
            nodes
                .push(self.compare_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(4, 3, EdgeType::Control)); // copy conditionally
        }

        SyntheticPdg {
            kind: SyntheticBugKind::UninitializedMemory,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::UninitializedMemory.motifs(),
        }
    }

    // ─── Phase-3 expansion: tainted-flow-to-sink synthetic motifs ────────
    //
    // The patterns below all share the same skeleton: a source (input/load),
    // an optional propagation step (move/add), and a sink (call/store/load).
    // The codebook tags (LifecycleStage, SyscallProximity, MemoryAccessTag)
    // are what makes them discriminable in HV space — the topology alone is
    // intentionally similar so polymorphic variants land in the right
    // anchor's neighbourhood.

    fn taint_to_sink_graph(
        &mut self,
        kind: SyntheticBugKind,
        variant: usize,
        source: HyperVector,
        sink: HyperVector,
        sink_lifecycle: LifecycleStage,
    ) -> SyntheticPdg {
        let propagate = self.move_node(sink_lifecycle, SyscallProximity::PreSyscall);
        let mut nodes = vec![source, propagate, sink];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::Data),
            SyntheticEdge::new(1, 2, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];
        if variant % 2 == 1 {
            nodes.push(self.compare_node(sink_lifecycle, SyscallProximity::PreSyscall));
            edges.push(SyntheticEdge::new(3, 2, EdgeType::Control));
        }
        SyntheticPdg {
            kind,
            node_hvs: nodes,
            edges,
            motifs: kind.motifs(),
        }
    }

    fn stack_buffer_overflow_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Source: tainted size from input. Sink: stack memcpy / strcpy.
        let source = self.call_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let sink = self.call_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        // Stack BoF differs from heap BoF in lifecycle (Allocated → InUse on a
        // stack frame) and in the absence of a heap-alias edge. Emulate the
        // lack of heap aliasing by using only Data edges.
        let mut sg = self.taint_to_sink_graph(
            SyntheticBugKind::StackBufferOverflow,
            variant,
            source,
            sink,
            LifecycleStage::InUse,
        );
        // Add a tainted-arith node so the index-flow motif lands distinctly
        // from generic command-injection (which goes near syscalls).
        let arith = self.add_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let arith_idx = sg.node_hvs.len();
        sg.node_hvs.push(arith);
        sg.edges
            .push(SyntheticEdge::new(0, arith_idx, EdgeType::Data));
        sg.edges
            .push(SyntheticEdge::new(arith_idx, 2, EdgeType::Data));
        sg
    }

    fn format_string_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Source: tainted string in attacker-controlled register, very near
        // the syscall site. Sink: printf-family (modeled as Call near
        // syscall boundary).
        let source = self.heap_load_node(LifecycleStage::Unknown, SyscallProximity::NearSyscall);
        let sink = self.call_node(LifecycleStage::Unknown, SyscallProximity::NearSyscall);
        self.taint_to_sink_graph(
            SyntheticBugKind::FormatString,
            variant,
            source,
            sink,
            LifecycleStage::Unknown,
        )
    }

    fn oob_read_graph(&mut self, variant: usize) -> SyntheticPdg {
        let base = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        let idx = self.add_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let load = self.heap_load_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![base, idx, load];
        let mut edges = vec![
            SyntheticEdge::new(0, 2, EdgeType::HeapAlias),
            SyntheticEdge::new(1, 2, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];
        if !variant.is_multiple_of(3) {
            nodes
                .push(self.compare_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(3, 2, EdgeType::Control));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::OutOfBoundsRead,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::OutOfBoundsRead.motifs(),
        }
    }

    fn oob_write_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Same skeleton as OOB read but the sink is heap_store rather than
        // heap_load — this single change in opcode + memory tag is what
        // makes the HV similarity meaningful.
        let base = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        let idx = self.add_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let store = self.heap_store_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![base, idx, store];
        let mut edges = vec![
            SyntheticEdge::new(0, 2, EdgeType::HeapAlias),
            SyntheticEdge::new(1, 2, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];
        if !variant.is_multiple_of(3) {
            nodes
                .push(self.compare_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(3, 2, EdgeType::Control));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::OutOfBoundsWrite,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::OutOfBoundsWrite.motifs(),
        }
    }

    fn null_deref_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Allocator may return NULL, no compare-with-zero guards the
        // subsequent load.
        let alloc = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        let load = self.heap_load_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![alloc, load];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::HeapAlias),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
        ];
        // Variants without the protective compare are the "bad" canonical
        // form. Half of variants include a *post*-load compare to model
        // crashes that only manifest later (still a bug, just delayed).
        if variant % 2 == 1 {
            nodes.push(self.compare_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(1, 2, EdgeType::Control));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::NullDereference,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::NullDereference.motifs(),
        }
    }

    fn off_by_one_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Loop bound miscount: cmp uses < but should use <=. We model it as
        // a compare-jump-store loop where the index reaches buffer length.
        let alloc = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        let cmp = self.compare_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let store = self.heap_store_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![alloc, cmp, store];
        let mut edges = vec![
            SyntheticEdge::new(0, 2, EdgeType::HeapAlias),
            SyntheticEdge::new(1, 2, EdgeType::Control),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];
        if variant.is_multiple_of(2) {
            // Add an increment node to make the loop topology richer.
            let inc = self.add_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
            nodes.push(inc);
            let inc_idx = nodes.len() - 1;
            edges.push(SyntheticEdge::new(inc_idx, 1, EdgeType::Data));
            edges.push(SyntheticEdge::new(2, inc_idx, EdgeType::Sequential));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::OffByOne,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::OffByOne.motifs(),
        }
    }

    fn integer_underflow_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Subtraction of two unsigned values where the right side is larger
        // than the left, then the result is used as a size or index.
        let input = self.call_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let sub = self.add_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall); // overloaded for arith
        let sink = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![input, sub, sink];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::Data),
            SyntheticEdge::new(1, 2, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];
        if variant % 2 == 1 {
            nodes
                .push(self.compare_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(3, 1, EdgeType::Control));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::IntegerUnderflow,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::IntegerUnderflow.motifs(),
        }
    }

    fn toctou_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Two syscalls operating on the same path: stat-like check, then
        // open-like use. The shared input edge between them models the
        // race window.
        let stat_call = self.syscall_node(LifecycleStage::Unknown, SyscallProximity::IsSyscall);
        let open_call = self.syscall_node(LifecycleStage::Unknown, SyscallProximity::IsSyscall);
        let path = self.heap_load_node(LifecycleStage::Unknown, SyscallProximity::PreSyscall);
        let mut nodes = vec![path, stat_call, open_call];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::Data),
            SyntheticEdge::new(0, 2, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];
        if variant % 2 == 1 {
            nodes.push(self.compare_node(LifecycleStage::Unknown, SyscallProximity::PreSyscall));
            edges.push(SyntheticEdge::new(3, 2, EdgeType::Control));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::TimeOfCheckTimeOfUse,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::TimeOfCheckTimeOfUse.motifs(),
        }
    }

    fn improper_validation_graph(&mut self, variant: usize) -> SyntheticPdg {
        let source = self.call_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let sink = self.syscall_node(LifecycleStage::Unknown, SyscallProximity::IsSyscall);
        self.taint_to_sink_graph(
            SyntheticBugKind::ImproperValidation,
            variant,
            source,
            sink,
            LifecycleStage::Unknown,
        )
    }

    fn path_traversal_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Tainted path component + openat. Distinguished from
        // command_injection by the lack of an exec sink (we use a generic
        // syscall_node instead) and by NearSyscall lifecycle.
        let source = self.heap_load_node(LifecycleStage::Unknown, SyscallProximity::NearSyscall);
        let sink = self.syscall_node(LifecycleStage::Unknown, SyscallProximity::IsSyscall);
        self.taint_to_sink_graph(
            SyntheticBugKind::PathTraversal,
            variant,
            source,
            sink,
            LifecycleStage::Unknown,
        )
    }

    fn type_confusion_graph(&mut self, variant: usize) -> SyntheticPdg {
        // A Move (cast) followed by a Load through the casted pointer; the
        // `lifecycle = InUse` of the load combined with two distinct
        // alias paths into the same load make this a type-confusion motif.
        let alloc = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        let cast = self.move_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let load = self.heap_load_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![alloc, cast, load];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::HeapAlias),
            SyntheticEdge::new(1, 2, EdgeType::HeapAlias),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];
        if variant.is_multiple_of(2) {
            let alias_load =
                self.heap_load_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
            nodes.push(alias_load);
            edges.push(SyntheticEdge::new(0, 3, EdgeType::HeapAlias));
            edges.push(SyntheticEdge::new(2, 3, EdgeType::Sequential));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::TypeConfusion,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::TypeConfusion.motifs(),
        }
    }

    fn sql_injection_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Differs from command_injection in lifecycle (no syscall) and in
        // the propagation chain (move-add-move models string concat, then
        // a far-from-syscall call at the end is the query exec).
        let source = self.heap_load_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let concat = self.add_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let exec = self.call_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![source, concat, exec];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::Data),
            SyntheticEdge::new(1, 2, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];
        if variant % 2 == 1 {
            nodes
                .push(self.compare_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(3, 1, EdgeType::Control));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::SqlInjection,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::SqlInjection.motifs(),
        }
    }

    fn race_condition_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Two writers + reader to the same heap address with no
        // intervening compare/lock acquisition.
        let alloc = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        let writer1 = self.heap_store_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let writer2 = self.heap_store_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let reader = self.heap_load_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![alloc, writer1, writer2, reader];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::HeapAlias),
            SyntheticEdge::new(0, 2, EdgeType::HeapAlias),
            SyntheticEdge::new(0, 3, EdgeType::HeapAlias),
            // No Sequential edges between the writers ↔ reader is the
            // motif: ordering is unspecified (race).
        ];
        if variant % 2 == 1 {
            nodes.push(self.compare_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(4, 3, EdgeType::Control));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::RaceCondition,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::RaceCondition.motifs(),
        }
    }

    fn unsafe_deserialization_graph(&mut self, variant: usize) -> SyntheticPdg {
        let source = self.heap_load_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let sink = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        self.taint_to_sink_graph(
            SyntheticBugKind::UnsafeDeserialization,
            variant,
            source,
            sink,
            LifecycleStage::Unknown,
        )
    }

    fn hardcoded_credentials_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Compile-time literal (modeled as a Move from immediate, no
        // dependencies on input) reaches a Call sink.
        let literal = self.move_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let auth_call = self.call_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![literal, auth_call];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
        ];
        if variant % 2 == 1 {
            // Add a comparison on the literal — many real-world bugs check
            // it before passing, but the literal itself is still leaked
            // in the binary.
            nodes
                .push(self.compare_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(2, 1, EdgeType::Control));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::HardcodedCredentials,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::HardcodedCredentials.motifs(),
        }
    }

    fn weak_crypto_graph(&mut self, variant: usize) -> SyntheticPdg {
        // Pattern: init() → key/seed move → operate(). The presence of two
        // sequential calls without an intervening RNG/KDF call is the
        // approximation we use for "weak crypto primitive".
        let init = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        let seed = self.move_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let op = self.call_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall);
        let mut nodes = vec![init, seed, op];
        let mut edges = vec![
            SyntheticEdge::new(0, 1, EdgeType::HeapAlias),
            SyntheticEdge::new(1, 2, EdgeType::Data),
            SyntheticEdge::new(0, 1, EdgeType::Sequential),
            SyntheticEdge::new(1, 2, EdgeType::Sequential),
        ];
        if variant.is_multiple_of(2) {
            nodes.push(self.compare_node(LifecycleStage::InUse, SyscallProximity::FarFromSyscall));
            edges.push(SyntheticEdge::new(3, 2, EdgeType::Control));
        }
        SyntheticPdg {
            kind: SyntheticBugKind::WeakCrypto,
            node_hvs: nodes,
            edges,
            motifs: SyntheticBugKind::WeakCrypto.motifs(),
        }
    }

    fn ssrf_graph(&mut self, variant: usize) -> SyntheticPdg {
        let source = self.heap_load_node(LifecycleStage::Unknown, SyscallProximity::PreSyscall);
        let sink = self.syscall_node(LifecycleStage::Unknown, SyscallProximity::IsSyscall);
        self.taint_to_sink_graph(
            SyntheticBugKind::ServerSideRequestForgery,
            variant,
            source,
            sink,
            LifecycleStage::Unknown,
        )
    }

    fn xxe_graph(&mut self, variant: usize) -> SyntheticPdg {
        let source = self.heap_load_node(LifecycleStage::Unknown, SyscallProximity::FarFromSyscall);
        let sink = self.call_node(LifecycleStage::Allocated, SyscallProximity::FarFromSyscall);
        self.taint_to_sink_graph(
            SyntheticBugKind::XmlExternalEntity,
            variant,
            source,
            sink,
            LifecycleStage::Unknown,
        )
    }

    fn call_node(
        &mut self,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        self.instruction(
            OP_CALL,
            &[0],
            &[4],
            &[0],
            MemoryAccessTag::None,
            ControlFlowTag::CallSite,
            lifecycle,
            syscall_prox,
        )
    }

    fn syscall_node(
        &mut self,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        self.instruction(
            OP_SYSTEM_CALL,
            &[0],
            &[0],
            &[0],
            MemoryAccessTag::None,
            ControlFlowTag::SystemCall,
            lifecycle,
            syscall_prox,
        )
    }

    fn move_node(
        &mut self,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        self.instruction(
            OP_MOVE,
            &[0],
            &[0],
            &[0],
            MemoryAccessTag::None,
            ControlFlowTag::Sequential,
            lifecycle,
            syscall_prox,
        )
    }

    fn add_node(
        &mut self,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        self.instruction(
            OP_ADD,
            &[0],
            &[0, 1],
            &[0],
            MemoryAccessTag::None,
            ControlFlowTag::Sequential,
            lifecycle,
            syscall_prox,
        )
    }

    fn compare_node(
        &mut self,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        self.instruction(
            OP_COMPARE,
            &[],
            &[0, 1],
            &[0],
            MemoryAccessTag::None,
            ControlFlowTag::ConditionalBranch,
            lifecycle,
            syscall_prox,
        )
    }

    fn heap_load_node(
        &mut self,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        self.instruction(
            OP_LOAD,
            &[0],
            &[2],
            &[0],
            MemoryAccessTag::HeapRead,
            ControlFlowTag::Sequential,
            lifecycle,
            syscall_prox,
        )
    }

    fn heap_store_node(
        &mut self,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        self.instruction(
            OP_STORE,
            &[2],
            &[0],
            &[0],
            MemoryAccessTag::HeapWrite,
            ControlFlowTag::Sequential,
            lifecycle,
            syscall_prox,
        )
    }

    fn instruction(
        &mut self,
        opcode_id: u32,
        dst_types: &[u8],
        src_types: &[u8],
        reg_classes: &[u8],
        mem_tag: MemoryAccessTag,
        cf_tag: ControlFlowTag,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        self.codebook.encode_instruction(
            opcode_id,
            dst_types,
            src_types,
            reg_classes,
            mem_tag,
            cf_tag,
            lifecycle,
            syscall_prox,
        )
    }
}

impl Default for AnchorForge {
    fn default() -> Self {
        Self::with_config(ForgeConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_store_contains_all_builtin_anchors() {
        let mut forge = AnchorForge::default();
        let store = forge.build_default_store();

        assert_eq!(store.len(), SyntheticBugKind::ALL.len());
        for kind in SyntheticBugKind::ALL {
            assert!(store.get(kind.anchor_name()).is_some());
        }
    }

    #[test]
    fn forged_anchor_detects_exact_synthetic_graph() {
        let mut forge = AnchorForge::default();
        let anchor = forge.build_anchor(SyntheticBugKind::UseAfterFree);
        let mut store = AnchorStore::new();
        store.add(anchor);

        let graph = forge
            .generate_graphs(SyntheticBugKind::UseAfterFree)
            .into_iter()
            .next()
            .unwrap();
        let hv = forge.encode_graph(&graph);
        let results = store.detect(&hv);

        assert!(!results.is_empty());
        assert_eq!(results[0].anchor_name, "use_after_free");
        assert!(
            results[0]
                .matched_motifs
                .iter()
                .any(|motif| motif == "invalid lifetime dependency")
        );
    }

    #[test]
    fn forged_store_serializes_to_json() {
        let mut forge = AnchorForge::default();
        let store = forge.build_default_store();

        let json = store.to_json_string();
        let loaded = AnchorStore::from_json_str(&json).unwrap();

        assert_eq!(loaded.len(), store.len());
        assert!(loaded.get("command_injection").is_some());
    }
}
