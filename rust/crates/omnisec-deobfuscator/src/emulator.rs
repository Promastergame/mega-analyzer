//! Lightweight emulator for resolving encrypted strings and constants.
//!
//! This is **not** a full CPU emulator. It is a targeted "abstract machine"
//! that can execute short straight-line sequences of OmniIR instructions
//! (typically ≤ 200 insns) to recover:
//!
//! - XOR-encrypted strings
//! - RC4/custom cipher decryption loops
//! - Constant unfolding chains (`x = 0x1234; x ^= 0x5678; x += 0x9ABC; ...`)
//!
//! ## Design
//!
//! - 256 virtual registers, each holding an [`AbstractValue`].
//! - A flat `Vec<u8>` memory model (64KB max, enough for string buffers).
//! - Hard execution limit (configurable, default 10_000 steps) to prevent
//!   infinite loops from killing the analysis.

use crate::lattice::{AbstractValue, BinOp, UnOp};
use omnisec_ir::{Instruction, OpCode, Operand};
use std::collections::HashMap as FxHashMap;
use std::fmt;

/// Configuration for the mini-emulator.
#[derive(Debug, Clone)]
pub struct EmulatorConfig {
    /// Maximum number of instructions to execute before bailing out.
    pub max_steps: usize,
    /// Size of the flat memory in bytes.
    pub memory_size: usize,
    /// Maximum number of registers.
    pub max_registers: usize,
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self {
            max_steps: 10_000,
            memory_size: 65_536, // 64KB
            max_registers: 256,
        }
    }
}

/// The state of the mini-emulator at any point during execution.
#[derive(Debug, Clone)]
pub struct EmulatorState {
    /// Register file: register native_id -> value.
    pub registers: FxHashMap<u32, i64>,
    /// Flat memory.
    pub memory: Vec<u8>,
    /// Number of instructions executed so far.
    pub steps: usize,
    /// Whether the emulator halted cleanly.
    pub halted: bool,
    /// Strings recovered during emulation.
    pub recovered_strings: Vec<RecoveredString>,
    /// Execution trace (address -> register state snapshot).
    pub trace: Vec<TraceEntry>,
}

/// A string recovered by the emulator.
#[derive(Debug, Clone)]
pub struct RecoveredString {
    /// Address where the decryption routine was found.
    pub origin_address: u64,
    /// The decrypted string bytes.
    pub bytes: Vec<u8>,
    /// The decrypted string as UTF-8 (if valid).
    pub text: Option<String>,
    /// Encryption method detected.
    pub method: EncryptionMethod,
}

/// Detected encryption method for a recovered string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    /// Simple XOR with a single-byte key.
    XorSingleByte,
    /// XOR with a multi-byte key (repeating).
    XorMultiByte,
    /// RC4 stream cipher.
    Rc4,
    /// AES (detected but not emulated — needs external help).
    Aes,
    /// Custom / unknown cipher — emulated brute-force.
    Custom,
    /// Simple arithmetic chain (add/sub/xor sequence).
    ArithmeticChain,
}

impl fmt::Display for EncryptionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XorSingleByte => write!(f, "XOR (single-byte key)"),
            Self::XorMultiByte => write!(f, "XOR (multi-byte key)"),
            Self::Rc4 => write!(f, "RC4"),
            Self::Aes => write!(f, "AES"),
            Self::Custom => write!(f, "Custom cipher"),
            Self::ArithmeticChain => write!(f, "Arithmetic chain"),
        }
    }
}

/// A single trace entry: snapshot of state at one instruction.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    /// Address of the instruction that was executed.
    pub address: u64,
    /// Registers that changed (id -> new value).
    pub register_changes: Vec<(u32, i64)>,
}

impl EmulatorState {
    /// Create a fresh emulator state with the given config.
    #[must_use]
    pub fn new(config: &EmulatorConfig) -> Self {
        Self {
            registers: FxHashMap::default(),
            memory: vec![0; config.memory_size],
            steps: 0,
            halted: false,
            recovered_strings: Vec::new(),
            trace: Vec::new(),
        }
    }

    /// Read a register value. Returns 0 for uninitialized registers.
    #[must_use]
    pub fn read_reg(&self, id: u32) -> i64 {
        self.registers.get(&id).copied().unwrap_or(0)
    }

    /// Write a value to a register.
    pub fn write_reg(&mut self, id: u32, value: i64) {
        self.registers.insert(id, value);
    }

    /// Read a byte from memory. Returns 0 for out-of-bounds.
    #[must_use]
    pub fn read_byte(&self, addr: u64) -> u8 {
        self.memory.get(addr as usize).copied().unwrap_or(0)
    }

    /// Write a byte to memory. Silently ignores out-of-bounds writes.
    pub fn write_byte(&mut self, addr: u64, value: u8) {
        if (addr as usize) < self.memory.len() {
            self.memory[addr as usize] = value;
        }
    }

    /// Read a 32-bit little-endian value from memory.
    #[must_use]
    pub fn read_u32_le(&self, addr: u64) -> u32 {
        let a = addr as usize;
        if a + 4 <= self.memory.len() {
            u32::from_le_bytes([
                self.memory[a],
                self.memory[a + 1],
                self.memory[a + 2],
                self.memory[a + 3],
            ])
        } else {
            0
        }
    }

    /// Write a 32-bit little-endian value to memory.
    pub fn write_u32_le(&mut self, addr: u64, value: u32) {
        let a = addr as usize;
        if a + 4 <= self.memory.len() {
            let bytes = value.to_le_bytes();
            self.memory[a..a + 4].copy_from_slice(&bytes);
        }
    }

    /// Extract a zero-terminated string from memory starting at `addr`.
    #[must_use]
    pub fn read_cstring(&self, addr: u64) -> Vec<u8> {
        let mut result = Vec::new();
        let mut a = addr as usize;
        while a < self.memory.len() {
            let b = self.memory[a];
            if b == 0 {
                break;
            }
            result.push(b);
            a += 1;
        }
        result
    }
}

/// The mini-emulator itself.
pub struct MiniEmulator {
    /// Configuration.
    pub config: EmulatorConfig,
}

impl MiniEmulator {
    /// Create a new emulator with the given config.
    #[must_use]
    pub fn new(config: EmulatorConfig) -> Self {
        Self { config }
    }

    /// Create a new emulator with default config.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(EmulatorConfig::default())
    }

    /// Execute a straight-line sequence of OmniIR instructions.
    ///
    /// Returns the final emulator state. Does **not** follow branches —
    /// the caller is expected to feed it a linearized basic-block sequence.
    pub fn execute(&self, instructions: &[Instruction], state: &mut EmulatorState) {
        for insn in instructions {
            if state.steps >= self.config.max_steps {
                omnisec_log::warn!(
                    "Emulator hit step limit ({}) at address {:#x}",
                    self.config.max_steps,
                    insn.address
                );
                state.halted = true;
                return;
            }

            self.execute_one(insn, state);
            state.steps += 1;
        }
    }

    /// Execute a single instruction.
    fn execute_one(&self, insn: &Instruction, state: &mut EmulatorState) {
        let mut changes = Vec::new();

        match insn.opcode {
            OpCode::Move => {
                if let (Some(dst), Some(src)) =
                    (self.dst_reg(insn), self.src_imm_or_reg(insn, state, 0))
                {
                    state.write_reg(dst, src);
                    changes.push((dst, src));
                }
            }
            OpCode::Add
            | OpCode::Sub
            | OpCode::Mul
            | OpCode::Div
            | OpCode::Rem
            | OpCode::And
            | OpCode::Or
            | OpCode::Xor
            | OpCode::Shl
            | OpCode::Shr
            | OpCode::Sar
            | OpCode::Rol
            | OpCode::Ror => {
                if let Some(dst) = self.dst_reg(insn) {
                    let a = self.src_imm_or_reg(insn, state, 0).unwrap_or(0);
                    let b = self.src_imm_or_reg(insn, state, 1).unwrap_or(0);
                    let av = AbstractValue::Const(a);
                    let bv = AbstractValue::Const(b);
                    let binop = match insn.opcode {
                        OpCode::Add => BinOp::Add,
                        OpCode::Sub => BinOp::Sub,
                        OpCode::Mul => BinOp::Mul,
                        OpCode::Div => BinOp::Div,
                        OpCode::Rem => BinOp::Rem,
                        OpCode::And => BinOp::And,
                        OpCode::Or => BinOp::Or,
                        OpCode::Xor => BinOp::Xor,
                        OpCode::Shl => BinOp::Shl,
                        OpCode::Shr => BinOp::Shr,
                        OpCode::Sar => BinOp::Sar,
                        OpCode::Rol => BinOp::Rol,
                        OpCode::Ror => BinOp::Ror,
                        _ => unreachable!(),
                    };
                    if let AbstractValue::Const(result) = av.eval_binop(binop, bv) {
                        state.write_reg(dst, result);
                        changes.push((dst, result));
                    }
                }
            }
            OpCode::Neg | OpCode::Not => {
                if let Some(dst) = self.dst_reg(insn) {
                    let src = self.src_imm_or_reg(insn, state, 0).unwrap_or(0);
                    let unop = match insn.opcode {
                        OpCode::Neg => UnOp::Neg,
                        OpCode::Not => UnOp::Not,
                        _ => unreachable!(),
                    };
                    if let AbstractValue::Const(result) = AbstractValue::Const(src).eval_unop(unop)
                    {
                        state.write_reg(dst, result);
                        changes.push((dst, result));
                    }
                }
            }
            OpCode::Load => {
                // Simple: load from absolute address into dst register
                if let Some(dst) = self.dst_reg(insn)
                    && let Some(addr) = self.src_mem_addr(insn)
                {
                    let val = state.read_u32_le(addr) as i64;
                    state.write_reg(dst, val);
                    changes.push((dst, val));
                }
            }
            OpCode::Store => {
                // Store src register value to absolute address
                if let Some(addr) = self.dst_mem_addr(insn) {
                    let val = self.src_imm_or_reg(insn, state, 0).unwrap_or(0);
                    state.write_u32_le(addr, val as u32);
                }
            }
            OpCode::Return | OpCode::Halt | OpCode::Trap => {
                state.halted = true;
            }
            // We don't follow branches — the caller linearizes the path
            _ => {}
        }

        state.trace.push(TraceEntry {
            address: insn.address,
            register_changes: changes,
        });
    }

    /// Extract the destination register id from the first dst operand.
    fn dst_reg(&self, insn: &Instruction) -> Option<u32> {
        insn.dst.first().and_then(|op| match op {
            Operand::Register(r) => Some(r.native_id),
            _ => None,
        })
    }

    /// Get the value of the Nth source operand (immediate or register lookup).
    fn src_imm_or_reg(&self, insn: &Instruction, state: &EmulatorState, idx: usize) -> Option<i64> {
        insn.src.get(idx).map(|op| match op {
            Operand::Immediate(v) => *v,
            Operand::Register(r) => state.read_reg(r.native_id),
            _ => 0,
        })
    }

    /// Extract memory address from the first src operand (for Load).
    fn src_mem_addr(&self, insn: &Instruction) -> Option<u64> {
        insn.src.first().and_then(|op| match op {
            Operand::Memory(m) => Some(m.displacement as u64),
            Operand::Immediate(v) => Some(*v as u64),
            _ => None,
        })
    }

    /// Extract memory address from the first dst operand (for Store).
    fn dst_mem_addr(&self, insn: &Instruction) -> Option<u64> {
        insn.dst.first().and_then(|op| match op {
            Operand::Memory(m) => Some(m.displacement as u64),
            _ => None,
        })
    }

    /// Attempt XOR-based string decryption on a memory region.
    ///
    /// Tries single-byte XOR keys 0x01..=0xFF and returns any result that
    /// produces mostly printable ASCII.
    pub fn try_xor_decrypt(&self, encrypted: &[u8]) -> Vec<RecoveredString> {
        let mut results = Vec::new();

        // Single-byte XOR brute-force
        for key in 1u8..=255 {
            let decrypted: Vec<u8> = encrypted.iter().map(|b| b ^ key).collect();
            if is_mostly_printable(&decrypted) {
                results.push(RecoveredString {
                    origin_address: 0,
                    bytes: decrypted.clone(),
                    text: String::from_utf8(decrypted).ok(),
                    method: EncryptionMethod::XorSingleByte,
                });
            }
        }

        // Multi-byte XOR key detection (up to 32 bytes)
        for key_len in 2..=32.min(encrypted.len()) {
            if let Some(key) = detect_repeating_xor_key(encrypted, key_len) {
                let decrypted: Vec<u8> = encrypted
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key[i % key.len()])
                    .collect();
                if is_mostly_printable(&decrypted) {
                    results.push(RecoveredString {
                        origin_address: 0,
                        bytes: decrypted.clone(),
                        text: String::from_utf8(decrypted).ok(),
                        method: EncryptionMethod::XorMultiByte,
                    });
                }
            }
        }

        results
    }

    /// Attempt RC4 decryption with a candidate key.
    pub fn try_rc4_decrypt(&self, encrypted: &[u8], key: &[u8]) -> RecoveredString {
        let decrypted = rc4_crypt(encrypted, key);
        let text = String::from_utf8(decrypted.clone()).ok();
        RecoveredString {
            origin_address: 0,
            bytes: decrypted,
            text,
            method: EncryptionMethod::Rc4,
        }
    }
}

/// Check if a byte slice is mostly printable ASCII (> 80%).
fn is_mostly_printable(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let printable = data.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    (printable as f64 / data.len() as f64) >= 0.8
}

/// Attempt to detect a repeating XOR key of `key_len` bytes.
///
/// Uses frequency analysis: for each key position, the most common XOR'd
/// byte is likely a space (0x20) or null (0x00) in the plaintext.
fn detect_repeating_xor_key(data: &[u8], key_len: usize) -> Option<Vec<u8>> {
    if data.len() < key_len * 3 {
        return None; // Not enough data for reliable detection
    }

    let mut key = Vec::with_capacity(key_len);
    for pos in 0..key_len {
        let mut freq = [0u32; 256];
        for i in (pos..data.len()).step_by(key_len) {
            freq[data[i] as usize] += 1;
        }
        // The most frequent byte XOR'd with space gives us the key byte
        let most_common = freq.iter().enumerate().max_by_key(|&(_, &c)| c).unwrap().0;
        key.push(most_common as u8 ^ 0x20);
    }

    Some(key)
}

/// RC4 (ARC4) stream cipher implementation.
fn rc4_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }

    // KSA (Key Scheduling Algorithm)
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: u8 = 0;
    for i in 0..=255usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // PRGA (Pseudo-Random Generation Algorithm)
    let mut i: u8 = 0;
    j = 0;
    data.iter()
        .map(|&byte| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            byte ^ k
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_single_byte_roundtrip() {
        let plaintext = b"Hello, World!";
        let key = 0x42u8;
        let encrypted: Vec<u8> = plaintext.iter().map(|b| b ^ key).collect();

        let emu = MiniEmulator::with_defaults();
        let results = emu.try_xor_decrypt(&encrypted);
        assert!(!results.is_empty());

        let found = results
            .iter()
            .any(|r| r.text.as_deref() == Some("Hello, World!"));
        assert!(found, "Should find the original plaintext");
    }

    #[test]
    fn rc4_roundtrip() {
        let plaintext = b"Deobfuscation engine test!";
        let key = b"secret_key";
        let encrypted = rc4_crypt(plaintext, key);
        assert_ne!(encrypted, plaintext);

        let decrypted = rc4_crypt(&encrypted, key);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn emulator_arithmetic() {
        use omnisec_core::Arch;
        use omnisec_ir::operand::Register;
        use omnisec_ir::operand::RegisterClass;
        use omnisec_ir::{Instruction, OpCode, Operand};

        let r0 = Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: 0,
            bit_width: 64,
            name: "r0".into(),
        };
        // mov r0, 100
        let mov = Instruction::new(OpCode::Move, 0, 4, Arch::X86_64)
            .with_dst([Operand::Register(r0.clone())])
            .with_src([Operand::Immediate(100)]);

        // add r0, r0, 42 (immediate)
        let add = Instruction::new(OpCode::Add, 4, 4, Arch::X86_64)
            .with_dst([Operand::Register(r0.clone())])
            .with_src([Operand::Register(r0.clone()), Operand::Immediate(42)]);

        let emu = MiniEmulator::with_defaults();
        let mut state = EmulatorState::new(&emu.config);
        emu.execute(&[mov, add], &mut state);

        assert_eq!(state.read_reg(0), 142); // 100 + 42
    }

    #[test]
    fn emulator_step_limit() {
        use omnisec_core::Arch;
        use omnisec_ir::{Instruction, OpCode};

        let nop = Instruction::new(OpCode::Nop, 0, 1, Arch::X86_64);
        let insns: Vec<_> = (0..100).map(|_| nop.clone()).collect();

        let config = EmulatorConfig {
            max_steps: 10,
            ..Default::default()
        };
        let emu = MiniEmulator::new(config);
        let mut state = EmulatorState::new(&emu.config);
        emu.execute(&insns, &mut state);

        assert!(state.halted);
        assert_eq!(state.steps, 10);
    }
}
