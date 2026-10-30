//! CPU state and execution engine for the ARM64 micro-emulator.

use omnisec_arm64_decode::{Operand as DOp, decode};
use omnisec_emu_x86::{MemoryError, Permission, VirtualMemory};
use omnisec_json::{FromJson, ToJson};

/// ARM64 64-bit general-purpose registers + SP + PC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum Register {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    SP = 31,
    PC = 32,
}

impl Register {
    /// Helper to convert index to Register.
    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => Register::X0,
            1 => Register::X1,
            2 => Register::X2,
            3 => Register::X3,
            4 => Register::X4,
            5 => Register::X5,
            6 => Register::X6,
            7 => Register::X7,
            8 => Register::X8,
            9 => Register::X9,
            10 => Register::X10,
            11 => Register::X11,
            12 => Register::X12,
            13 => Register::X13,
            14 => Register::X14,
            15 => Register::X15,
            16 => Register::X16,
            17 => Register::X17,
            18 => Register::X18,
            19 => Register::X19,
            20 => Register::X20,
            21 => Register::X21,
            22 => Register::X22,
            23 => Register::X23,
            24 => Register::X24,
            25 => Register::X25,
            26 => Register::X26,
            27 => Register::X27,
            28 => Register::X28,
            29 => Register::X29,
            30 => Register::X30,
            31 => Register::SP,
            32 => Register::PC,
            _ => Register::X0,
        }
    }
}

/// ARM64 processor status flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson, Default)]
pub struct Flag {
    /// Zero flag
    pub zf: bool,
    /// Negative flag
    pub nf: bool,
    /// Carry flag
    pub cf: bool,
    /// Overflow flag
    pub vf: bool,
}

/// Full CPU state snapshot.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct CpuState {
    /// 31 GPRs + SP + PC
    pub regs: Vec<u64>,
    /// Processor flags
    pub flags: Flag,
    /// Instructions executed so far
    pub insn_count: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            regs: vec![0; 33],
            flags: Flag::default(),
            insn_count: 0,
        }
    }
}

impl CpuState {
    fn reg_index(r: Register) -> usize {
        r as usize
    }

    /// Get register value.
    pub fn get(&self, r: Register) -> u64 {
        self.regs[Self::reg_index(r)]
    }

    /// Set register value.
    pub fn set(&mut self, r: Register, val: u64) {
        self.regs[Self::reg_index(r)] = val;
    }
}

/// Reason the emulator stopped.
#[derive(Debug, Clone, ToJson, FromJson)]
pub enum StopReason {
    /// Reached max instruction count
    MaxInstructions,
    /// Hit a breakpoint (not used in NIF yet)
    Breakpoint { address: u64 },
    /// Hit an invalid/unsupported instruction
    InvalidInstruction { address: u64, raw: u32 },
    /// Memory access fault
    MemoryFault { address: u64, reason: String },
    /// Execution completed normally (RET from entry)
    Completed,
}

/// Result of emulation.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct EmulationResult {
    /// Final CPU state
    pub state: CpuState,
    /// Why the emulator stopped
    pub stop_reason: StopReason,
    /// Dynamic strings decrypted
    pub decrypted_strings: Vec<(u64, String)>,
    /// Memory regions written
    pub written_regions: Vec<(u64, usize)>,
}

/// The ARM64 micro-emulator.
pub struct Cpu {
    /// CPU state
    pub state: CpuState,
    /// Virtual memory
    pub memory: VirtualMemory,
    /// Decrypted strings
    decrypted: Vec<(u64, String)>,
    /// Tracking writes
    write_log: Vec<(u64, usize)>,
    /// Entry SP
    entry_sp: u64,
}

impl Cpu {
    /// Create a new CPU with code loaded at the given address.
    pub fn new(code: &[u8], entry_point: u64) -> Self {
        let mut memory = VirtualMemory::new();

        // Map code
        let code_size = code.len().div_ceil(4096) * 4096;
        memory.map_region(entry_point, code_size as u64, Permission::RWX, "code");
        let _ = memory.write(entry_point, code);

        // Map stack (1 MB below 0x7FFF_0000)
        let stack_base = 0x7FFE_0000_u64;
        let stack_size = 0x0010_0000_u64; // 1 MB
        memory.map_region(stack_base, stack_size, Permission::RW, "stack");
        let stack_top = stack_base + stack_size - 16; // 16-byte aligned stack top

        let mut state = CpuState::default();
        state.set(Register::PC, entry_point);
        state.set(Register::SP, stack_top);
        state.set(Register::X30, 0); // LR = 0 to detect completion on RET

        Self {
            entry_sp: stack_top,
            state,
            memory,
            decrypted: Vec::new(),
            write_log: Vec::new(),
        }
    }

    /// Map additional data into the emulator's memory.
    pub fn map_data(&mut self, addr: u64, data: &[u8]) {
        let size = data.len().div_ceil(4096) * 4096;
        self.memory
            .map_region(addr, size as u64, Permission::RW, "data");
        let _ = self.memory.write(addr, data);
    }

    /// Run emulation until a stop condition is met.
    pub fn run(&mut self, max_insns: u64) -> EmulationResult {
        let limit = max_insns.min(crate::MAX_INSTRUCTIONS);

        loop {
            if self.state.insn_count >= limit {
                return self.make_result(StopReason::MaxInstructions);
            }

            let pc = self.state.get(Register::PC);

            // Fetch 4-byte little-endian ARM64 instruction
            let mut buf = [0u8; 4];
            for i in 0..4 {
                match self.memory.read_u8(pc + i as u64) {
                    Ok(b) => buf[i] = b,
                    Err(e) => {
                        return self.make_result(StopReason::MemoryFault {
                            address: pc + i as u64,
                            reason: e.to_string(),
                        });
                    }
                }
            }

            let raw_insn = u32::from_le_bytes(buf);

            // Execute
            match self.execute_one(buf, raw_insn, pc) {
                Ok(None) => { /* continue */ }
                Ok(Some(stop)) => return self.make_result(stop),
                Err(e) => {
                    return self.make_result(StopReason::MemoryFault {
                        address: pc,
                        reason: e.to_string(),
                    });
                }
            }

            self.state.insn_count += 1;
        }
    }

    fn make_result(&self, stop_reason: StopReason) -> EmulationResult {
        EmulationResult {
            state: self.state.clone(),
            stop_reason,
            decrypted_strings: self.decrypted.clone(),
            written_regions: self.write_log.clone(),
        }
    }

    fn execute_one(
        &mut self,
        buf: [u8; 4],
        raw_insn: u32,
        pc: u64,
    ) -> Result<Option<StopReason>, MemoryError> {
        let _ = buf;
        let d = decode(raw_insn, pc);

        // Move PC forward by default (4 bytes)
        let next_pc = pc + 4;
        self.state.set(Register::PC, next_pc);

        match d.mnemonic {
            "NOP" | "HINT" | "UNKNOWN" => {}

            "RET" => {
                let lr = self.state.get(Register::X30);
                if lr == 0 || pc == self.entry_sp {
                    return Ok(Some(StopReason::Completed));
                }
                self.state.set(Register::PC, lr);
            }

            "MOV" | "MOVZ" => {
                if let [DOp::Reg { id: dst, .. }, src, ..] = d.ops {
                    let val = self.op_val(src);
                    self.set_reg(dst, val);
                }
            }

            "MOVN" => {
                if let [DOp::Reg { id: dst, width, .. }, DOp::Imm(v), ..] = d.ops {
                    let mask = if width == 32 { 0xFFFF_FFFF } else { u64::MAX };
                    self.set_reg(dst, !(v as u64) & mask);
                }
            }

            "MOVK" => {
                if let [DOp::Reg { id: dst, .. }, DOp::Imm(v), ..] = d.ops {
                    // Insert the (already shifted) halfword. The shift slot
                    // is not carried, so derive it when unambiguous.
                    let v = v as u64;
                    let cur = self.op_val(DOp::Reg {
                        id: dst,
                        width: 64,
                        is_sp: false,
                    });
                    let new = if v == 0 {
                        cur
                    } else {
                        let pos = (v.trailing_zeros() / 16) * 16;
                        (cur & !(0xFFFF << pos)) | v
                    };
                    self.set_reg(dst, new);
                }
            }

            "ADR" | "ADRP" => {
                if let [DOp::Reg { id: dst, .. }, DOp::Imm(t), ..] = d.ops {
                    self.set_reg(dst, t as u64);
                }
            }

            "ADD" | "SUB" | "AND" | "ORR" | "EOR" => {
                if let [DOp::Reg { id: dst, .. }, s1, s2, ..] = d.ops {
                    let val1 = self.op_val(s1);
                    let val2 = self.op_val(s2);
                    let res = match d.mnemonic {
                        "ADD" => val1.wrapping_add(val2),
                        "SUB" => val1.wrapping_sub(val2),
                        "AND" => val1 & val2,
                        "ORR" => val1 | val2,
                        _ => val1 ^ val2,
                    };
                    self.set_reg(dst, res);
                }
            }

            "CMP" => {
                let [s1, s2, ..] = d.ops;
                {
                    let val1 = self.op_val(s1);
                    let val2 = self.op_val(s2);
                    let (res, borrow) = val1.overflowing_sub(val2);
                    self.state.flags.zf = res == 0;
                    self.state.flags.nf = (res as i64) < 0;
                    self.state.flags.cf = !borrow;
                    self.state.flags.vf = (((val1 as i64) < 0) != ((val2 as i64) < 0))
                        && (((res as i64) < 0) != ((val1 as i64) < 0));
                }
            }

            "LDR" | "LDUR" | "STR" | "STUR" => {
                if let [DOp::Reg { id: r, .. }, mem, ..] = d.ops
                    && let Some(addr) = self.mem_addr(mem)
                    && let Some(reg) = reg_of(r)
                {
                    if d.mnemonic.as_bytes()[0] == b'L' {
                        let val = self.memory.read_u64(addr)?;
                        self.state.set(reg, val);

                        // Auto-check dynamic string decrypted loops
                        if let Ok(s) = self.memory.read_string(val)
                            && s.len() > 3
                            && !self.decrypted.iter().any(|(_, x)| x == &s)
                        {
                            self.decrypted.push((val, s));
                        }
                    } else {
                        let val = self.state.get(reg);
                        self.memory.write_u64(addr, val)?;
                        self.write_log.push((addr, 8));
                    }
                }
            }

            "CBZ" | "CBNZ" => {
                if let [r, DOp::Imm(target), ..] = d.ops {
                    let taken = (self.op_val(r) == 0) == (d.mnemonic == "CBZ");
                    if taken {
                        self.state.set(Register::PC, target as u64);
                    }
                }
            }

            "B_cond" => {
                if let [DOp::Imm(target), ..] = d.ops {
                    if self.cond_taken(d.cond) {
                        self.state.set(Register::PC, target as u64);
                    }
                }
            }

            "B" | "BL" => {
                if let [DOp::Imm(target), ..] = d.ops {
                    if d.mnemonic == "BL" {
                        self.state.set(Register::X30, next_pc);
                    }
                    self.state.set(Register::PC, target as u64);
                }
            }

            "SVC" => {
                // System call number is usually in X8 on ARM64 Linux
                let sys_no = self.state.get(Register::X8);

                // Simple intercept for connect(X0=fd, X1=addr, X2=len) -> sys_no 203 (connect on aarch64 linux)
                // sendto -> sys_no 206
                // recvfrom -> sys_no 207
                if sys_no == 203 || sys_no == 206 || sys_no == 207 {
                    // This is where we hook network syscalls and wrap them in omnisec_net_obfs
                    // For a real emulator, we'd do the actual socket mapping and encryption here.
                    // We will just log it for now to prove it intercepts for network obfuscation.
                    // println!("Intercepted network syscall {} for obfuscation", sys_no);
                }
            }

            _ => {
                // Unsupported instructions are treated as NOPs in simple shellcode emulation
            }
        }

        Ok(None)
    }

    /// Evaluate a B.cond condition code against current flags.
    fn cond_taken(&self, cond: u8) -> bool {
        match cond {
            0 => self.state.flags.zf,                         // eq
            1 => !self.state.flags.zf,                        // ne
            2 => self.state.flags.cf,                         // cs/hs
            3 => !self.state.flags.cf,                        // cc/lo
            4 => self.state.flags.nf,                         // mi
            5 => !self.state.flags.nf,                        // pl
            6 => self.state.flags.vf,                         // vs
            7 => !self.state.flags.vf,                        // vc
            8 => self.state.flags.cf && !self.state.flags.zf, // hi
            9 => !self.state.flags.cf || self.state.flags.zf, // ls
            10 => self.state.flags.nf == self.state.flags.vf, // ge
            11 => self.state.flags.nf != self.state.flags.vf, // lt
            12 => !self.state.flags.zf && (self.state.flags.nf == self.state.flags.vf), // gt
            13 => self.state.flags.zf || (self.state.flags.nf != self.state.flags.vf), // le
            _ => true,                                        // al (14) and nv (15): always
        }
    }

    /// Read an operand value (registers are width-masked, XZR reads zero).
    fn op_val(&self, op: DOp) -> u64 {
        match op {
            DOp::Reg { id, width, .. } => {
                let v = if id >= 31 {
                    0
                } else {
                    self.state.get(Register::from_index(id as usize))
                };
                if width == 32 { v & 0xFFFF_FFFF } else { v }
            }
            DOp::Imm(v) => v as u64,
            DOp::Mem { .. } | DOp::None => 0,
        }
    }

    /// Write a register (writes to XZR are dropped).
    fn set_reg(&mut self, id: u8, val: u64) {
        if id < 31 {
            self.state.set(Register::from_index(id as usize), val);
        }
    }

    /// Resolve a memory operand to an address.
    fn mem_addr(&self, op: DOp) -> Option<u64> {
        if let DOp::Mem {
            base,
            base_is_sp,
            disp,
        } = op
        {
            let b = if base >= 31 {
                if base_is_sp {
                    self.state.get(Register::SP)
                } else {
                    0
                }
            } else {
                self.state.get(Register::from_index(base as usize))
            };
            Some(b.wrapping_add(disp as u64))
        } else {
            None
        }
    }
}

/// Map a data-register id to the emulator register (None for XZR).
fn reg_of(id: u8) -> Option<Register> {
    if id < 31 {
        Some(Register::from_index(id as usize))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm64_alu() {
        // mov x0, #10
        // mov x1, #20
        // add x2, x0, x1
        // sub x3, x2, #5
        // ret
        let code = [
            0x40, 0x01, 0x80, 0xd2, // mov x0, #10
            0x81, 0x02, 0x80, 0xd2, // mov x1, #20
            0x02, 0x00, 0x01, 0x8b, // add x2, x0, x1
            0x43, 0x14, 0x00, 0xd1, // sub x3, x2, #5
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ];

        let mut cpu = Cpu::new(&code, 0x1000);
        let res = cpu.run(10);

        assert!(matches!(res.stop_reason, StopReason::Completed));
        assert_eq!(res.state.get(Register::X0), 10);
        assert_eq!(res.state.get(Register::X1), 20);
        assert_eq!(res.state.get(Register::X2), 30);
        assert_eq!(res.state.get(Register::X3), 25);
    }
}
