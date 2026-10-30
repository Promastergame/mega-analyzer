//! x86-64 instruction decoder backed by `iced-x86`.
//!
//! Provides single-instruction and bulk decoding with Intel-syntax formatting.

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════

/// Decodes a single x86-64 instruction from `data` at virtual address `ip`.
///
/// Returns `None` if the first byte(s) do not form a valid instruction.
pub fn decode_one(data: &[u8], ip: u64) -> Option<Instruction> {
    let mut decoder = Decoder::with_ip(64, data, ip, DecoderOptions::NONE);
    let insn = decoder.decode();
    if insn.is_invalid() { None } else { Some(insn) }
}

/// Decodes all consecutive valid instructions in `data` starting at `ip`.
///
/// Stops at the first invalid instruction or when `data` is exhausted.
pub fn decode_all(data: &[u8], ip: u64) -> Vec<Instruction> {
    let mut decoder = Decoder::with_ip(64, data, ip, DecoderOptions::NONE);
    let mut out = Vec::new();
    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

/// Formats an instruction to Intel-syntax string (e.g. `mov rax, rbx`).
pub fn format_insn(insn: &Instruction) -> String {
    let mut formatter = IntelFormatter::new();
    let mut output = String::new();
    formatter.format(insn, &mut output);
    output
}

/// Returns the mnemonic name of an instruction (e.g. `"mov"`, `"add"`).
pub fn mnemonic(insn: &Instruction) -> String {
    let text = format_insn(insn);
    text.split_whitespace().next().unwrap_or("???").to_string()
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_mov_rax_rbx() {
        // mov rax, rbx
        let bytes = [0x48, 0x89, 0xD8];
        let insn = decode_one(&bytes, 0x1000).expect("valid mov");
        assert_eq!(mnemonic(&insn), "mov");
        let text = format_insn(&insn);
        assert!(text.contains("rax"));
        assert!(text.contains("rbx"));
    }

    #[test]
    fn decode_nop() {
        let insn = decode_one(&[0x90], 0x1000).expect("valid nop");
        assert_eq!(mnemonic(&insn), "nop");
    }

    #[test]
    fn decode_invalid_returns_none() {
        // 0xFF alone is not a complete instruction
        assert!(decode_one(&[0xFF], 0x1000).is_none());
    }

    #[test]
    fn decode_all_sequence() {
        // nop; nop; nop
        let insns = decode_all(&[0x90, 0x90, 0x90], 0x1000);
        assert_eq!(insns.len(), 3);
        for insn in &insns {
            assert_eq!(mnemonic(insn), "nop");
        }
    }

    #[test]
    fn decode_xor_loop() {
        // xor eax, eax; inc eax; cmp eax, 10
        let bytes = [
            0x31, 0xC0, // xor eax, eax
            0xFF, 0xC0, // inc eax
            0x83, 0xF8, 0x0A, // cmp eax, 0xA
        ];
        let insns = decode_all(&bytes, 0x1000);
        assert_eq!(insns.len(), 3);
        assert_eq!(mnemonic(&insns[0]), "xor");
        assert_eq!(mnemonic(&insns[1]), "inc");
        assert_eq!(mnemonic(&insns[2]), "cmp");
    }
}
