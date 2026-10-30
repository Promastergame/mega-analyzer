use omnisec_core::Arch;
use omnisec_ir::{Condition, Instruction, OpCode, Operand, Register, RegisterClass};

pub const MIR_INSN_SIZE: usize = 40;

/// Dalvik implementation of the OmniIR lifter.
pub struct DalvikLifter;

impl DalvikLifter {
    /// Lift a buffer of serialized MIR instructions.
    #[must_use]
    pub fn lift_method(buf: &[u8]) -> Vec<Instruction> {
        // [DEBUG CLEANUP] eprintln!("RUST: lift_method called with buf.len() = {}", buf.len());
        if !buf.len().is_multiple_of(MIR_INSN_SIZE) {
            // [DEBUG CLEANUP] eprintln!("RUST: ERROR! buf.len() is not a multiple of 40!");
            return Vec::new();
        }

        let count = buf.len() / MIR_INSN_SIZE;
        // [DEBUG CLEANUP] eprintln!("RUST: count = {}", count);
        let mut out = Vec::with_capacity(count);

        for i in 0..count {
            let chunk = &buf[i * MIR_INSN_SIZE..(i + 1) * MIR_INSN_SIZE];
            let insn = lift_one(chunk, i);
            out.push(insn);
        }

        out
    }
}

fn dalvik_reg(idx: u32) -> Register {
    Register {
        arch: Arch::Dalvik,
        class: RegisterClass::GeneralPurpose,
        native_id: idx,
        bit_width: 32,
        name: format!("v{}", idx),
    }
}

fn dalvik_cond(cond: u8) -> Option<Condition> {
    match cond {
        1 => Some(Condition::Equal),
        2 => Some(Condition::NotEqual),
        3 => Some(Condition::SignedLess),
        4 => Some(Condition::SignedGreaterEq),
        5 => Some(Condition::SignedGreater),
        6 => Some(Condition::SignedLessEq),
        _ => None,
    }
}

fn mir_kind_to_opcode(kind: u8) -> OpCode {
    match kind {
        0 => OpCode::Nop,
        1..=4 => OpCode::Move,
        5 => OpCode::Add,
        6 => OpCode::Sub,
        7 => OpCode::Mul,
        8 => OpCode::Div,
        9 => OpCode::Rem,
        10 => OpCode::Neg,
        11 => OpCode::Not,
        12 => OpCode::And,
        13 => OpCode::Or,
        14 => OpCode::Xor,
        15 => OpCode::Shl,
        16..=17 => OpCode::Shr,
        18 => OpCode::Compare,
        19 => OpCode::BranchIf,
        20 => OpCode::Jump,
        21 => OpCode::Call,
        22 => OpCode::Return,
        23 => OpCode::Trap,
        _ => OpCode::Nop,
    }
}

fn lift_one(b: &[u8], idx: usize) -> Instruction {
    let kind = b[0];
    let cond_byte = b[2];

    let offset = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let dst = i16::from_le_bytes([b[8], b[9]]);
    let src1 = i16::from_le_bytes([b[10], b[11]]);
    let src2 = i16::from_le_bytes([b[12], b[13]]);
    let imm = i64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]);

    let address = if offset == 0 {
        idx as u64
    } else {
        u64::from(offset)
    };

    let opcode = mir_kind_to_opcode(kind);
    let mut insn = Instruction::new(opcode, address, 2, Arch::Dalvik);

    if dst >= 0 {
        insn.dst = vec![Operand::Register(dalvik_reg(dst as u32))];
    }

    match kind {
        4 => {
            insn.src = vec![Operand::Immediate(imm)];
        }
        5..=15 => {
            let mut sources = vec![];
            if src1 >= 0 {
                sources.push(Operand::Register(dalvik_reg(src1 as u32)));
            }
            if src2 >= 0 {
                sources.push(Operand::Register(dalvik_reg(src2 as u32)));
            } else if imm != 0 || kind == 5 {
                sources.push(Operand::Immediate(imm));
            }
            insn.src = sources;
        }
        19 => {
            let mut sources = vec![];
            if src1 >= 0 {
                sources.push(Operand::Register(dalvik_reg(src1 as u32)));
            }
            if src2 >= 0 {
                sources.push(Operand::Register(dalvik_reg(src2 as u32)));
            }
            sources.push(Operand::Immediate(imm));
            insn.src = sources;
            insn.condition = dalvik_cond(cond_byte);
        }
        20 => {
            insn.src = vec![Operand::Immediate(imm)];
        }
        22 if src1 >= 0 => {
            insn.src = vec![Operand::Register(dalvik_reg(src1 as u32))];
        }
        _ => {}
    }

    insn
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lift_const_instruction() {
        let mut buf = [0u8; 40];
        buf[0] = 4;
        buf[8] = 0;
        let imm_bytes = 100i64.to_le_bytes();
        buf[16..24].copy_from_slice(&imm_bytes);

        let insns = DalvikLifter::lift_method(&buf);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].opcode, OpCode::Move);
        assert_eq!(insns[0].src[0], Operand::Immediate(100));
    }

    #[test]
    fn lift_add_instruction() {
        let mut buf = [0u8; 40];
        buf[0] = 5;
        buf[8] = 0;
        buf[10] = 1;
        buf[12] = 2;

        let insns = DalvikLifter::lift_method(&buf);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].opcode, OpCode::Add);
        assert_eq!(insns[0].src.len(), 2);
    }
}
