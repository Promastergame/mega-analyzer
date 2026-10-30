//! # OmniSec ARM64 Micro-Emulator
//!
//! A lightweight pure-Rust ARM64 emulator for mobile shellcode analysis,
//! dynamic string decryption, and unpackers.
//!
//! Emulates a basic subset of A64 (AArch64) instructions operating on virtual memory.

mod cpu;

pub use cpu::{Cpu, CpuState, EmulationResult, Flag, Register, StopReason};

// Re-export VirtualMemory and memory errors from omnisec-emu-x86 to keep the system modular and clean
pub use omnisec_emu_x86::{MemoryError, MemoryRegion, Permission, VirtualMemory};

/// Maximum instructions to execute before forced stop (anti-infinite-loop).
pub const MAX_INSTRUCTIONS: u64 = 10_000_000;

/// Default stack size (1 MB).
pub const DEFAULT_STACK_SIZE: usize = 1024 * 1024;
