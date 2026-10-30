//! The [`Disassembler`] trait — abstract over per-ISA decoders.

use omnisec_ir::Instruction;

/// A linear-sweep decoder for one ISA.
pub trait Disassembler: Send + Sync {
    /// Lift `bytes` (mapped at `base_addr`) into a stream of OmniIR
    /// instructions. Implementations should:
    /// - decode greedily (no recursive traversal);
    /// - emit one `Instruction` per source instruction;
    /// - emit `OpCode::Invalid` for undecodable byte runs (preserving the
    ///   raw bytes via `Instruction.raw`) instead of giving up.
    fn disassemble(&self, bytes: &[u8], base_addr: u64) -> Vec<Instruction>;
}
