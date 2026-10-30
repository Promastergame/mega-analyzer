use omnisec_arm64_decode::decode;
use omnisec_disasm_arm64::Arm64Lifter;
use omnisec_ir::{OpCode, Operand};

#[test]
fn test_decode_ret() {
    let d = decode(0xD65F_03C0, 0x1000); // ret
    assert_eq!(d.mnemonic, "RET");
}

fn lift(bytes: &[u8]) -> Vec<omnisec_ir::Instruction> {
    Arm64Lifter::new().lift(0x1000, bytes).expect("lift")
}

#[test]
fn ret_nop_jump() {
    let insts = lift(&[
        0xC0, 0x03, 0x5F, 0xD6, // ret
        0x1F, 0x20, 0x03, 0xD5, // nop
        0x00, 0x00, 0x00, 0x14, // b #0
    ]);
    assert_eq!(insts.len(), 3);
    assert_eq!(insts[0].opcode, OpCode::Return);
    assert_eq!(insts[1].opcode, OpCode::Nop);
    assert_eq!(insts[2].opcode, OpCode::Jump);
}

#[test]
fn add_immediate_and_register() {
    // add x0, x1, x2
    let insts = lift(&[0x20, 0x00, 0x02, 0x8B]);
    assert_eq!(insts.len(), 1);
    assert_eq!(insts[0].opcode, OpCode::Add);
    assert_eq!(insts[0].dst.len(), 1);
    assert!(matches!(&insts[0].dst[0], Operand::Register(r) if r.name == "x0"));
}

#[test]
fn ldr_str_memory_operands() {
    // ldr x0, [x1] / str x0, [x1]
    let insts = lift(&[0x20, 0x00, 0x40, 0xF8, 0x20, 0x00, 0x00, 0xF8]);
    assert_eq!(insts.len(), 2);
    assert_eq!(insts[0].opcode, OpCode::Load);
    assert!(matches!(&insts[0].src[0], Operand::Memory(_)));
    assert_eq!(insts[1].opcode, OpCode::Store);
    // Store convention: memory is the destination, value is a source.
    assert!(matches!(&insts[1].dst[0], Operand::Memory(_)));
    assert!(matches!(&insts[1].src[0], Operand::Register(_)));
}

#[test]
fn movz_zero_register() {
    // movz x0, #0
    let insts = lift(&[0x00, 0x00, 0x80, 0xD2]);
    assert_eq!(insts.len(), 1);
    assert_eq!(insts[0].opcode, OpCode::Move);
}

#[test]
fn prologue_lifts_to_call_graph_shapes() {
    // stp x29, x30, [sp, #-16]! ; mov x29, sp ; bl #8 ; ldp x29, x30, [sp], #16 ; ret
    let insts = lift(&[
        0xFD, 0x7B, 0xBF, 0xA9, // stp x29, x30, [sp, #-16]!
        0xFD, 0x03, 0x00, 0x91, // mov x29, sp (add x29, sp, #0)
        0x02, 0x00, 0x00, 0x94, // bl #8
        0xFD, 0x7B, 0xC1, 0xA8, // ldp x29, x30, [sp], #16
        0xC0, 0x03, 0x5F, 0xD6, // ret
    ]);
    assert_eq!(insts.len(), 5);
    assert_eq!(insts[0].opcode, OpCode::Store);
    assert_eq!(insts[1].opcode, OpCode::Move); // mov x29, sp
    assert_eq!(insts[2].opcode, OpCode::Call);
    assert_eq!(insts[3].opcode, OpCode::Load);
    assert_eq!(insts[4].opcode, OpCode::Return);
}
