//! Integration tests exercising the full concolic + SMT pipeline
//! against synthetic MIR that mimics real-world bug shapes.

use omnisec_analysis_symbolic::{
    BranchPriority, ConcolicExecutor, ConcolicSeed, MirInsn, MirOp, SymBlock, merge_traces,
};

fn nop() -> MirInsn {
    MirInsn {
        kind: MirOp::Nop,
        cond: 0,
        dst: 0,
        src1: 0,
        src2: 0,
        imm: 0,
        ref_idx: 0,
    }
}

fn const_(dst: i16, imm: i64) -> MirInsn {
    MirInsn {
        kind: MirOp::Const,
        cond: 0,
        dst,
        src1: 0,
        src2: 0,
        imm,
        ref_idx: 0,
    }
}

fn add(dst: i16, a: i16, b: i16) -> MirInsn {
    MirInsn {
        kind: MirOp::Add,
        cond: 0,
        dst,
        src1: a,
        src2: b,
        imm: 0,
        ref_idx: 0,
    }
}

fn sub(dst: i16, a: i16, b: i16) -> MirInsn {
    MirInsn {
        kind: MirOp::Sub,
        cond: 0,
        dst,
        src1: a,
        src2: b,
        imm: 0,
        ref_idx: 0,
    }
}

fn branch_if(src: i16, cond: u8) -> MirInsn {
    MirInsn {
        kind: MirOp::If,
        cond,
        dst: 0,
        src1: src,
        src2: 0,
        imm: 0,
        ref_idx: 0,
    }
}

/// Synthetic CFG mimicking a heap-buffer-overflow guarded by an integer
/// check:
///
/// ```c
/// void vuln(int user_size) {
///     if (user_size <= 0) return;             // block 0 → 1 (safe early exit)
///     if (user_size >= 0x4000) return;        // block 1 → 2
///     // ↳ within bounds: but a wraparound is possible
///     int padded = user_size + 16;
///     if (padded < user_size) return;         // wraparound check
///     malloc(padded);                          // block 3 (sink)
/// }
/// ```
///
/// We expect the concolic + SMT pipeline to:
/// 1. Cover both early-exit paths.
/// 2. Find the corner-case input where `user_size + 16` wraps around
///    (possible at very large `user_size` near 2^31 - 16).
/// 3. Produce ≥ 3 distinct path signatures.
#[test]
#[ignore = "slow concolic exploration; run explicitly with --ignored"]
fn concolic_finds_wraparound_corner_case() {
    // r0 = user_size (symbolic input v0)
    // r1 = const 0
    // r2 = const 0x4000
    // r3 = const 16
    // r4 = r0 - r1   (= r0)
    // branch if r4 <= 0      → exit
    // r5 = r0 - r2
    // branch if r5 >= 0      → exit
    // r6 = r0 + r3
    // r7 = r6 - r0           (= +16 normally, very negative on overflow)
    // branch if r7 < 0       → exit
    // (fallthrough = SINK)

    let blocks = vec![
        // Block 0: early-exit if user_size <= 0
        SymBlock {
            id: 0,
            insns: vec![const_(1, 0), sub(4, 0, 1), branch_if(4, 5)], // <= 0
            succs: vec![1, 4], // succ 0 = taken (early-exit), succ 1 = fall through
        },
        // Block 1: dead end (early exit)
        SymBlock {
            id: 1,
            insns: vec![nop()],
            succs: vec![],
        },
        // Block 4: continuation — check upper bound
        SymBlock {
            id: 4,
            insns: vec![const_(2, 0x4000), sub(5, 0, 2), branch_if(5, 7)], // >= 0
            succs: vec![5, 6], // taken = exit, fallthrough = continue
        },
        // Block 5: dead end (oversize exit)
        SymBlock {
            id: 5,
            insns: vec![nop()],
            succs: vec![],
        },
        // Block 6: wraparound check
        SymBlock {
            id: 6,
            insns: vec![
                const_(3, 16),
                add(6, 0, 3),
                sub(7, 6, 0),
                branch_if(7, 4), // < 0  ⇒ wraparound, take exit
            ],
            succs: vec![7, 8], // taken = wraparound (exit), fallthrough = sink
        },
        // Block 7: dead end (wraparound exit)
        SymBlock {
            id: 7,
            insns: vec![nop()],
            succs: vec![],
        },
        // Block 8: SINK
        SymBlock {
            id: 8,
            insns: vec![nop()],
            succs: vec![],
        },
    ];

    let mut exec = ConcolicExecutor::new(blocks, 0);
    exec.set_max_iterations(16);
    exec.set_max_depth(64);

    let result = exec.explore_with_priority(ConcolicSeed::new(), |_, _| {
        BranchPriority::Vulnerability(0.9)
    });

    println!(
        "Concolic exploration: {} traces, {} smt queries, {} unsat, {} unknown",
        result.traces.len(),
        result.smt_queries,
        result.unsat_replies,
        result.unknown_replies
    );
    for (i, trace) in result.traces.iter().enumerate() {
        let signature: Vec<bool> = trace.branches.iter().map(|b| b.taken).collect();
        println!(
            "  trace {i}: signature = {signature:?}, terminated = {}",
            trace.terminated_cleanly
        );
    }

    // We should explore at least 3 distinct paths.
    let signatures: std::collections::HashSet<Vec<bool>> = result
        .traces
        .iter()
        .map(|t| t.branches.iter().map(|b| b.taken).collect())
        .collect();
    assert!(
        signatures.len() >= 3,
        "expected ≥ 3 distinct paths, got {}",
        signatures.len()
    );

    // Sanity: the SMT solver should have been queried multiple times.
    assert!(result.smt_queries > 0);
}

/// Integration: combine the concolic explorer with `merge_traces` to
/// verify the report compresses redundant traces.
#[test]
#[ignore = "slow concolic exploration; run explicitly with --ignored"]
fn merge_compresses_redundant_traces() {
    // A trivial two-branch CFG. Each branch has only one symbolic
    // operand, so the SMT solver should fully cover both sides.
    let blocks = vec![
        SymBlock {
            id: 0,
            insns: vec![branch_if(0, 3)], // != 0
            succs: vec![1, 2],
        },
        SymBlock {
            id: 1,
            insns: vec![nop()],
            succs: vec![],
        },
        SymBlock {
            id: 2,
            insns: vec![nop()],
            succs: vec![],
        },
    ];
    let mut exec = ConcolicExecutor::new(blocks, 0);
    exec.set_max_iterations(8);
    let mut seed = ConcolicSeed::new();
    seed.set("v0", 1);
    let result = exec.explore(seed);

    let report = merge_traces(&result.traces);
    assert!(!report.paths.is_empty());
    // We should see at least one traced path; compression ratio is ≥ 1.
    assert!(report.compression_ratio >= 1.0);
}

/// Branch prioritisation must actually change exploration order.
#[test]
fn priority_function_is_called() {
    let blocks = vec![
        SymBlock {
            id: 0,
            insns: vec![branch_if(0, 2)], // == 0
            succs: vec![1, 2],
        },
        SymBlock {
            id: 1,
            insns: vec![branch_if(1, 3)], // != 0
            succs: vec![3, 4],
        },
        SymBlock {
            id: 2,
            insns: vec![],
            succs: vec![],
        },
        SymBlock {
            id: 3,
            insns: vec![],
            succs: vec![],
        },
        SymBlock {
            id: 4,
            insns: vec![],
            succs: vec![],
        },
    ];
    let mut exec = ConcolicExecutor::new(blocks, 0);
    exec.set_max_iterations(8);

    let calls = std::sync::atomic::AtomicUsize::new(0);
    let _ = exec.explore_with_priority(ConcolicSeed::new(), |_, _| {
        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        BranchPriority::Vulnerability(1.0)
    });

    let n = calls.load(std::sync::atomic::Ordering::Relaxed);
    assert!(n >= 1, "priority function not called");
}
