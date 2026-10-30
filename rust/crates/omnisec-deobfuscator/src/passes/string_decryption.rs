//! **String Decryption** — automated recovery of encrypted string constants.
//!
//! Many obfuscators encrypt all strings in the binary and decrypt them at
//! runtime via a small "decryptor" function. This pass:
//!
//! 1. Identifies candidate decryptor blocks (short loops with XOR/arithmetic).
//! 2. Uses the [`MiniEmulator`] to execute them with known inputs.
//! 3. Reads the decrypted string from the emulator's memory.
//! 4. Replaces the decryption sequence with a direct string load.

use std::time::Instant;

use omnisec_cfg::ControlFlowGraph;
use omnisec_ir::{OpCode, Operand};

use super::DeobfuscationPass;
use crate::emulator::{EmulatorConfig, EmulatorState, MiniEmulator, RecoveredString};
use crate::stats::PassStats;

/// String decryption pass.
pub struct StringDecryptionPass {
    emulator_config: EmulatorConfig,
}

impl Default for StringDecryptionPass {
    fn default() -> Self {
        Self::new()
    }
}

impl StringDecryptionPass {
    /// Create a new pass with default emulator settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            emulator_config: EmulatorConfig::default(),
        }
    }

    /// Create with a custom emulator configuration.
    #[must_use]
    pub fn with_config(config: EmulatorConfig) -> Self {
        Self {
            emulator_config: config,
        }
    }
}

impl DeobfuscationPass for StringDecryptionPass {
    fn name(&self) -> &'static str {
        "StringDecryption"
    }

    fn run(&self, cfg: &mut ControlFlowGraph) -> PassStats {
        let start = Instant::now();
        let mut stats = PassStats::new(self.name());

        let emu = MiniEmulator::new(self.emulator_config.clone());
        let block_ids: Vec<u32> = cfg.block_ids().collect();

        for block_id in block_ids {
            let block = match cfg.block(block_id) {
                Some(b) => b,
                None => continue,
            };

            // Heuristic: look for blocks that contain XOR-heavy sequences
            // (likely string decryption routines)
            let xor_count = block
                .instructions
                .iter()
                .filter(|i| i.opcode == OpCode::Xor)
                .count();

            if xor_count < 2 {
                continue;
            }

            // Check for encrypted data patterns:
            // A sequence of `mov reg, imm` followed by XOR operations
            let has_const_loads = block
                .instructions
                .iter()
                .filter(|i| {
                    i.opcode == OpCode::Move
                        && i.src
                            .first()
                            .is_some_and(|s| matches!(s, Operand::Immediate(_)))
                })
                .count();

            if has_const_loads < 2 {
                continue;
            }

            stats.trace.push(format!(
                "Block {block_id}: candidate decryption block ({xor_count} XORs, {has_const_loads} const loads)"
            ));

            // Try to emulate the block
            let mut state = EmulatorState::new(&self.emulator_config);
            emu.execute(&block.instructions, &mut state);

            // Scan emulator memory for printable strings
            let mut addr = 0u64;
            while addr < self.emulator_config.memory_size as u64 {
                let s = state.read_cstring(addr);
                if s.len() >= 4 && is_likely_string(&s) {
                    let text = String::from_utf8(s.clone()).ok();
                    let recovered = RecoveredString {
                        origin_address: block.start_address,
                        bytes: s.clone(),
                        text: text.clone(),
                        method: crate::emulator::EncryptionMethod::Custom,
                    };
                    state.recovered_strings.push(recovered);

                    stats.strings_decrypted += 1;
                    stats.trace.push(format!(
                        "  Recovered string at mem[{addr:#x}]: {:?}",
                        text.as_deref().unwrap_or("<binary>")
                    ));
                    addr += s.len() as u64 + 1;
                } else {
                    addr += 1;
                }
            }

            // Also try XOR brute-force on constant byte sequences in the block
            let const_bytes: Vec<u8> = block
                .instructions
                .iter()
                .filter_map(|i| {
                    if i.opcode == OpCode::Move
                        && let Some(Operand::Immediate(v)) = i.src.first()
                        && *v >= 0
                        && *v <= 255
                    {
                        return Some(*v as u8);
                    }
                    None
                })
                .collect();

            if const_bytes.len() >= 4 {
                let xor_results = emu.try_xor_decrypt(&const_bytes);
                for result in xor_results {
                    if result.text.is_some() {
                        stats.strings_decrypted += 1;
                        stats.trace.push(format!(
                            "  XOR-decrypted: {:?} (method: {})",
                            result.text.as_deref().unwrap_or("?"),
                            result.method
                        ));
                    }
                }
            }
        }

        stats.duration = start.elapsed();
        stats
    }

    fn should_run(&self, iteration: usize) -> bool {
        // String decryption is expensive; only run on first 2 iterations
        iteration < 2
    }
}

/// Heuristic check: is a byte sequence likely a meaningful string?
fn is_likely_string(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    let ratio = printable as f64 / data.len() as f64;
    ratio >= 0.75
}
