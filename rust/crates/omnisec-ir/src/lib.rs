//! OmniIR — the OmniSec universal intermediate representation.
//!
//! Every architecture (x86/x64/ARM/MIPS/RISC-V/...) and every managed VM
//! (Dalvik/JVM/CIL/WASM) is *lifted* into OmniIR by its corresponding
//! `omnisec-disasm-*` or `omnisec-loader-*` crate. From that point on the
//! rest of the pipeline (CFG, SSA, taint, vulndisc, exploit) only depends
//! on the IR.
//!
//! ## Design goals
//!
//! - **Coarse but complete**. We cover the operations every modern ISA has
//!   in its general-purpose subset (data movement, arithmetic, logic,
//!   compare/branch, call/return, memory, stack, sync/fence, traps).
//!   Per-ISA exotica (SIMD, FPU, crypto extensions) live behind
//!   `OpCode::Custom(u32)` until we need them.
//! - **Lossless w.r.t. addresses**. `Instruction.address` and `size` keep
//!   the original instruction byte location, so we can always go back.
//! - **Pure data**. No `Box<dyn>`, no implicit references — every IR node is
//!   `Clone + Serialize`. This keeps parallelism and snapshotting cheap.
//!
//! Phase 1 lifters only emit a *subset* of [`OpCode`]; the rest is reserved
//! for incremental coverage during Phase 2-onwards.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod instruction;
pub mod opcode;
pub mod operand;

pub use instruction::{Instruction, InstructionFlags};
pub use opcode::{Condition, OpCode};
pub use operand::{MemoryAddress, Operand, Register, RegisterClass, ValueType};

/// Re-export `Arch` for convenience.
pub use omnisec_core::Arch;
