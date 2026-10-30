# omnisec-ipdg — Inter-Process Dependency Graph

**Phase 1 (v11.0)** of the ML-Aetrium roadmap: Cross-boundary taint tracking and multi-component vulnerability detection.

## Overview

`omnisec-ipdg` extends traditional Program Dependence Graphs (PDGs) to track data flow across process boundaries, enabling detection of complex, multi-stage vulnerabilities that span multiple components:

- **Android App (Java/Kotlin) → JNI → Native Library (.so)**
- **User-space Application → Syscall → Kernel Driver**
- **Web Server → IPC → Backend Process**

## Architecture

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Process A │────▶│  Boundary   │────▶│   Process B │
│    (PDG)    │     │   (IPC/JNI) │     │    (PDG)    │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                    │
       └───────────────────┴────────────────────┘
                     IPDG (unified view)
```

## Key Features

### 1. Multi-Component Graph Construction

Track execution across different binary formats and privilege levels:

```rust
use omnisec_ipdg::*;

// Create components
let app = Component::new(
    ComponentId(1),
    ComponentKind::AndroidApp,
    "com.example.app".to_string(),
);

let native_lib = Component::new(
    ComponentId(2),
    ComponentKind::NativeLibrary,
    "libvulnerable.so".to_string(),
);

// Build IPDG
let mut ipdg = Ipdg::new();
ipdg.add_component(app);
ipdg.add_component(native_lib);
```

### 2. Boundary Modeling

Model inter-process communication mechanisms with security properties:

```rust
let jni_boundary = Boundary::new(
    BoundaryKind::Jni,
    ComponentId(1),
    ComponentId(2),
)
.with_function("Java_com_example_Native_processInput".to_string())
.with_trust_level(0.3)  // Low trust
.with_validation(false); // No input validation

ipdg.add_boundary(jni_boundary)?;
```

Supported boundary types:
- **JNI** — Java Native Interface
- **Syscall** — User → Kernel transitions
- **IOCTL** — Device driver communication
- **Binder** — Android IPC
- **Unix/Network Sockets**
- **Shared Memory**
- **RPC/COM**

### 3. Cross-Boundary Taint Tracking

Automatically track taint flow from sources to sinks across component boundaries:

```rust
let mut tracker = TaintTracker::new(&ipdg);

// Auto-detect sources and sinks based on function names
tracker.auto_detect_sources_and_sinks();

// Or manually specify
tracker.add_source(source_node, TaintSource::UserInput);
tracker.add_sink(sink_node, TaintSink::Memory);

// Find all taint paths
let paths = tracker.find_taint_paths();

for path in paths {
    println!("Taint flow: {:?} → {:?}", path.source, path.sink);
    println!("Boundary crossings: {}", path.boundary_crossings);
    println!("Risk score: {:.2}", path.risk_score);
}
```

### 4. Global Anchor System

Context-sensitive vulnerability signatures that understand multi-component patterns:

```rust
let anchor_store = GlobalAnchorStore::with_defaults();

// Match patterns against IPDG
let matches = anchor_store.match_all(&ipdg, &taint_paths);

for vuln in matches {
    if vuln.is_critical() {
        println!("CRITICAL: {}", vuln.pattern);
        println!("Confidence: {:.2}", vuln.confidence);
        println!("Severity: {:.2}", vuln.severity);
        println!("\n{}", vuln.explanation);
    }
}
```

Built-in patterns:
- **JNI Use-After-Free** — Memory corruption through JNI boundary
- **Syscall Injection** — Command injection via syscalls
- **IOCTL Buffer Overflow** — Kernel driver exploitation

## Example: Detecting JNI UAF

```rust
use omnisec_ipdg::*;

// 1. Build multi-component graph
let mut ipdg = Ipdg::new();

let app = Component::new(
    ComponentId(1),
    ComponentKind::AndroidApp,
    "com.example.vulnerable".to_string(),
);

let lib = Component::new(
    ComponentId(2),
    ComponentKind::NativeLibrary,
    "libvulnerable.so".to_string(),
);

ipdg.add_component(app);
ipdg.add_component(lib);

// 2. Add JNI boundary
let boundary = Boundary::new(
    BoundaryKind::Jni,
    ComponentId(1),
    ComponentId(2),
).with_trust_level(0.3);

ipdg.add_boundary(boundary)?;

// 3. Add nodes representing the vulnerability
let java_input = IpdgNode {
    component: ComponentId(1),
    function: "getUserInput".to_string(),
    is_source: true,
    is_sink: false,
    node_type: NodeType::Regular,
    // ... other fields
};

let native_memcpy = IpdgNode {
    component: ComponentId(2),
    function: "memcpy".to_string(),
    is_source: false,
    is_sink: true,
    node_type: NodeType::Sensitive,
    // ... other fields
};

// 4. Track taint
let mut tracker = TaintTracker::new(&ipdg);
tracker.add_source(java_input_idx, TaintSource::UserInput);
tracker.add_sink(native_memcpy_idx, TaintSink::Memory);

let paths = tracker.find_taint_paths();

// 5. Detect vulnerabilities
let store = GlobalAnchorStore::with_defaults();
let vulns = store.match_all(&ipdg, &paths);

// Output: JNI UAF detected with high confidence!
```

## Integration with ML-Aetrium

The IPDG integrates seamlessly with the existing ML-Aetrium pipeline:

1. **HDC Anchors** — Global anchors use 2048-bit HyperVectors for structural matching
2. **PDG Integration** — Each component's internal PDG feeds into the unified IPDG
3. **Concolic Execution** — Symbolic constraints can span boundaries
4. **Payload Generation** — Multi-stage exploits leverage cross-boundary paths

## Performance

- **Graph Construction**: O(N + E) where N = nodes, E = edges
- **Taint Tracking**: BFS-based, O(N + E) per source-sink pair
- **Anchor Matching**: O(P × T) where P = patterns, T = taint paths
- **Memory**: ~100 bytes per node, ~50 bytes per edge

## Testing

```bash
cargo test --package omnisec-ipdg
```

See `tests/cross_boundary_integration.rs` for comprehensive examples.

## Future Work (Phase 2+)

- **Multi-Arch Payload Synthesis** — Generate exploits for ARM64, MIPS, RISC-V
- **Autonomous Mitigation Bypass** — Automatic ROP/JOP chain construction
- **Reinforcement Learning** — Self-evolving anchor store based on exploitation success

## References

- [Project roadmap](../../../docs/ROADMAP.md)
- [Architecture](../../../docs/ARCHITECTURE.md) — Go and native engine integration
