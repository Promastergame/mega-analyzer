//! # OmniSec x86 Micro-Emulator
//!
//! A lightweight x86/x64 emulator for static analysis tasks that require
//! limited dynamic execution:
//!
//! - **Crypto unpacking**: run XOR/RC4 decryption loops to reveal hidden code
//! - **String decryption**: execute string decryption routines to extract plaintext
//! - **Shellcode analysis**: emulate shellcode to determine its behavior
//! - **API resolution**: resolve GetProcAddress chains for dynamic imports
//!
//! This is NOT a full system emulator (no OS, no syscalls). It emulates
//! a minimal subset of x86 instructions operating on virtual memory.
//!
//! ## Supported Instructions
//!
//! - Data: MOV, PUSH, POP, LEA, XCHG
//! - Arithmetic: ADD, SUB, MUL, IMUL, DIV, INC, DEC, NEG
//! - Logic: AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR
//! - Control: JMP, JCC (all conditions), CALL, RET, LOOP
//! - String: REP MOVSB/STOSB
//! - Misc: NOP, CMP, TEST, INT3 (breakpoint)

mod cpu;
mod decoder;
mod memory;

pub use cpu::{Cpu, CpuState, EmulationResult, Flag, Register, StopReason};
pub use decoder::{decode_all, decode_one, format_insn, mnemonic};
pub use memory::{MemoryError, MemoryRegion, Permission, VirtualMemory};

/// Maximum instructions to execute before forced stop (anti-infinite-loop).
pub const MAX_INSTRUCTIONS: u64 = 10_000_000;

/// Default stack size (1 MB).
pub const DEFAULT_STACK_SIZE: usize = 1024 * 1024;
