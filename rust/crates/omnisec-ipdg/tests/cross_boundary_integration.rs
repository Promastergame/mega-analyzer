//! Integration tests for cross-boundary vulnerability detection.
//!
//! This test suite demonstrates the full IPDG pipeline:
//! 1. Building a multi-component graph (Android App → JNI → Native Library)
//! 2. Tracking taint across boundaries
//! 3. Detecting vulnerabilities using global anchors

use omnisec_ipdg::*;

/// Test scenario: Android app calls native library through JNI,
/// passing user input to a vulnerable memcpy operation.
#[test]
fn test_jni_use_after_free_detection() {
    // Step 1: Create components
    let mut app = Component::new(
        ComponentId(1),
        ComponentKind::AndroidApp,
        "com.example.vulnerable".to_string(),
    );
    app.add_export("nativeProcessInput".to_string());

    let mut native_lib = Component::new(
        ComponentId(2),
        ComponentKind::NativeLibrary,
        "libvulnerable.so".to_string(),
    );
    native_lib.add_import("malloc".to_string());
    native_lib.add_import("free".to_string());
    native_lib.add_import("memcpy".to_string());

    // Step 2: Build IPDG
    let mut ipdg = Ipdg::new();
    ipdg.add_component(app);
    ipdg.add_component(native_lib);

    // Add JNI boundary
    let jni_boundary = Boundary::new(BoundaryKind::Jni, ComponentId(1), ComponentId(2))
        .with_function("Java_com_example_vulnerable_nativeProcessInput".to_string())
        .with_trust_level(0.3)
        .with_validation(false);

    ipdg.add_boundary(jni_boundary.clone()).unwrap();

    // Step 3: Create nodes representing the vulnerability path

    // Java side: user input source
    let java_input = IpdgNode {
        component: ComponentId(1),
        function: "getUserInput".to_string(),
        address: Some(0x1000),
        source_location: Some("MainActivity.java:42".to_string()),
        is_source: true,
        is_sink: false,
        node_type: NodeType::Regular,
    };

    // Java side: JNI call
    let java_jni_call = IpdgNode {
        component: ComponentId(1),
        function: "nativeProcessInput".to_string(),
        address: Some(0x1100),
        source_location: Some("MainActivity.java:45".to_string()),
        is_source: false,
        is_sink: false,
        node_type: NodeType::Boundary,
    };

    // Native side: JNI entry point
    let native_entry = IpdgNode {
        component: ComponentId(2),
        function: "Java_com_example_vulnerable_nativeProcessInput".to_string(),
        address: Some(0x2000),
        source_location: None,
        is_source: false,
        is_sink: false,
        node_type: NodeType::Entry,
    };

    // Native side: malloc
    let native_malloc = IpdgNode {
        component: ComponentId(2),
        function: "malloc".to_string(),
        address: Some(0x2100),
        source_location: None,
        is_source: false,
        is_sink: false,
        node_type: NodeType::Allocation,
    };

    // Native side: free
    let native_free = IpdgNode {
        component: ComponentId(2),
        function: "free".to_string(),
        address: Some(0x2200),
        source_location: None,
        is_source: false,
        is_sink: false,
        node_type: NodeType::Free,
    };

    // Native side: memcpy (use-after-free sink)
    let native_memcpy = IpdgNode {
        component: ComponentId(2),
        function: "memcpy".to_string(),
        address: Some(0x2300),
        source_location: None,
        is_source: false,
        is_sink: true,
        node_type: NodeType::Sensitive,
    };

    // Add nodes to graph
    let idx_java_input = ipdg.add_node(java_input);
    let idx_java_jni = ipdg.add_node(java_jni_call);
    let idx_native_entry = ipdg.add_node(native_entry);
    let idx_native_malloc = ipdg.add_node(native_malloc);
    let idx_native_free = ipdg.add_node(native_free);
    let idx_native_memcpy = ipdg.add_node(native_memcpy);

    // Step 4: Add edges

    // Java: input → JNI call
    ipdg.add_edge(
        idx_java_input,
        idx_java_jni,
        IpdgEdge {
            kind: EdgeKind::Data,
            boundary: None,
            is_tainted: true,
            confidence: 0.95,
        },
    );

    // Cross-boundary: Java JNI call → Native entry
    ipdg.add_edge(
        idx_java_jni,
        idx_native_entry,
        IpdgEdge {
            kind: EdgeKind::CrossBoundary,
            boundary: Some(
                BoundaryEdge::new(jni_boundary)
                    .with_taint(true)
                    .with_confidence(0.9),
            ),
            is_tainted: true,
            confidence: 0.9,
        },
    );

    // Native: entry → malloc
    ipdg.add_edge(
        idx_native_entry,
        idx_native_malloc,
        IpdgEdge {
            kind: EdgeKind::Call,
            boundary: None,
            is_tainted: true,
            confidence: 0.85,
        },
    );

    // Native: malloc → free
    ipdg.add_edge(
        idx_native_malloc,
        idx_native_free,
        IpdgEdge {
            kind: EdgeKind::Data,
            boundary: None,
            is_tainted: true,
            confidence: 0.8,
        },
    );

    // Native: free → memcpy (UAF!)
    ipdg.add_edge(
        idx_native_free,
        idx_native_memcpy,
        IpdgEdge {
            kind: EdgeKind::Data,
            boundary: None,
            is_tainted: true,
            confidence: 0.9,
        },
    );

    // Step 5: Perform taint tracking
    let mut tracker = TaintTracker::new(&ipdg);
    tracker.add_source(idx_java_input, TaintSource::UserInput);
    tracker.add_sink(idx_native_memcpy, TaintSink::Memory);

    let taint_paths = tracker.find_taint_paths();

    // Verify we found the taint path
    assert!(
        !taint_paths.is_empty(),
        "Should find at least one taint path"
    );

    let path = &taint_paths[0];
    assert_eq!(
        path.boundary_crossings, 1,
        "Should cross exactly one boundary (JNI)"
    );
    assert!(path.risk_score > 0.5, "Risk score should be significant");

    // Step 6: Match against global anchors
    let anchor_store = GlobalAnchorStore::with_defaults();
    let matches = anchor_store.match_all(&ipdg, &taint_paths);

    // Verify we detected the JNI UAF vulnerability
    assert!(
        !matches.is_empty(),
        "Should detect at least one vulnerability"
    );

    let vuln = &matches[0];
    assert_eq!(vuln.pattern, "jni_use_after_free");
    assert!(vuln.confidence > 0.6, "Confidence should be reasonable");
    assert!(vuln.severity > 0.8, "JNI UAF should be high severity");

    println!("\n=== Detected Vulnerability ===");
    println!("Pattern: {}", vuln.pattern);
    println!("Confidence: {:.2}", vuln.confidence);
    println!("Severity: {:.2}", vuln.severity);
    println!("\n{}", vuln.explanation);

    // Step 7: Verify graph statistics
    let stats = ipdg.stats();
    assert_eq!(stats.component_count, 2);
    assert_eq!(stats.boundary_count, 1);
    assert_eq!(stats.node_count, 6);
    assert_eq!(stats.cross_boundary_edge_count, 1);
    assert!(stats.tainted_edge_count >= 5);
}

/// Test scenario: User-space application makes syscall with untrusted input.
#[test]
fn test_syscall_injection_detection() {
    let mut ipdg = Ipdg::new();

    // User-space application
    let app = Component::new(
        ComponentId(1),
        ComponentKind::NativeExecutable,
        "vulnerable_app".to_string(),
    );

    // Kernel (simplified representation)
    let kernel = Component::new(
        ComponentId(2),
        ComponentKind::KernelModule,
        "kernel".to_string(),
    );

    ipdg.add_component(app);
    ipdg.add_component(kernel);

    // Syscall boundary
    let syscall_boundary = Boundary::new(BoundaryKind::Syscall, ComponentId(1), ComponentId(2))
        .with_function("execve".to_string())
        .with_trust_level(0.2)
        .with_validation(false);

    ipdg.add_boundary(syscall_boundary.clone()).unwrap();

    // Create nodes
    let network_recv = IpdgNode {
        component: ComponentId(1),
        function: "recv".to_string(),
        address: Some(0x1000),
        source_location: None,
        is_source: true,
        is_sink: false,
        node_type: NodeType::Regular,
    };

    let syscall_node = IpdgNode {
        component: ComponentId(2),
        function: "sys_execve".to_string(),
        address: Some(0x2000),
        source_location: None,
        is_source: false,
        is_sink: true,
        node_type: NodeType::Sensitive,
    };

    let idx_recv = ipdg.add_node(network_recv);
    let idx_syscall = ipdg.add_node(syscall_node);

    // Add cross-boundary edge
    ipdg.add_edge(
        idx_recv,
        idx_syscall,
        IpdgEdge {
            kind: EdgeKind::CrossBoundary,
            boundary: Some(
                BoundaryEdge::new(syscall_boundary)
                    .with_taint(true)
                    .with_confidence(0.85),
            ),
            is_tainted: true,
            confidence: 0.85,
        },
    );

    // Taint tracking
    let mut tracker = TaintTracker::new(&ipdg);
    tracker.add_source(idx_recv, TaintSource::Network);
    tracker.add_sink(idx_syscall, TaintSink::CommandExecution);

    let taint_paths = tracker.find_taint_paths();
    assert!(!taint_paths.is_empty());

    let path = &taint_paths[0];
    assert!(
        path.crosses_privilege_boundary,
        "Should cross privilege boundary"
    );
    assert!(
        path.risk_score > 0.8,
        "Syscall injection should be high risk"
    );

    // Match against anchors
    let anchor_store = GlobalAnchorStore::with_defaults();
    let matches = anchor_store.match_all(&ipdg, &taint_paths);

    assert!(!matches.is_empty());

    let vuln = &matches[0];
    assert_eq!(vuln.pattern, "syscall_injection");
    assert!(vuln.is_critical(), "Syscall injection should be critical");

    println!("\n=== Detected Critical Vulnerability ===");
    println!("Pattern: {}", vuln.pattern);
    println!("Confidence: {:.2}", vuln.confidence);
    println!("Severity: {:.2}", vuln.severity);
    println!("\n{}", vuln.explanation);
}

/// Test auto-detection of sources and sinks.
#[test]
fn test_auto_detection() {
    let mut ipdg = Ipdg::new();

    let comp = Component::new(
        ComponentId(1),
        ComponentKind::NativeExecutable,
        "app".to_string(),
    );
    ipdg.add_component(comp);

    // Add various nodes with recognizable function names
    let nodes = vec![
        ("recv_socket", true, false),
        ("read_file", true, false),
        ("getenv", true, false),
        ("malloc", false, true),
        ("system", false, true),
        ("strcpy", false, true),
    ];

    for (func, is_source, is_sink) in nodes {
        let node = IpdgNode {
            component: ComponentId(1),
            function: func.to_string(),
            address: Some(0x1000),
            source_location: None,
            is_source,
            is_sink,
            node_type: NodeType::Regular,
        };
        ipdg.add_node(node);
    }

    let mut tracker = TaintTracker::new(&ipdg);
    tracker.auto_detect_sources_and_sinks();

    // Verify auto-detection worked
    assert_eq!(tracker.sources.len(), 3, "Should detect 3 sources");
    assert_eq!(tracker.sinks.len(), 3, "Should detect 3 sinks");
}
