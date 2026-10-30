//! CPU state and execution engine for the x86 micro-emulator.

use crate::memory::{MemoryError, Permission, VirtualMemory};
use omnisec_json::{FromJson, ToJson};

/// x86-64 general-purpose registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum Register {
    RAX,
    RBX,
    RCX,
    RDX,
    RSI,
    RDI,
    RSP,
    RBP,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    RIP,
}

/// CPU flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson, Default)]
pub struct Flag {
    /// Zero flag
    pub zf: bool,
    /// Sign flag
    pub sf: bool,
    /// Carry flag
    pub cf: bool,
    /// Overflow flag
    pub of: bool,
}

/// Full CPU state snapshot.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct CpuState {
    /// General-purpose registers
    pub regs: [u64; 17], // RAX..R15 + RIP
    /// Flags
    pub flags: Flag,
    /// Instructions executed so far
    pub insn_count: u64,
}

impl CpuState {
    fn reg_index(r: Register) -> usize {
        match r {
            Register::RAX => 0,
            Register::RBX => 1,
            Register::RCX => 2,
            Register::RDX => 3,
            Register::RSI => 4,
            Register::RDI => 5,
            Register::RSP => 6,
            Register::RBP => 7,
            Register::R8 => 8,
            Register::R9 => 9,
            Register::R10 => 10,
            Register::R11 => 11,
            Register::R12 => 12,
            Register::R13 => 13,
            Register::R14 => 14,
            Register::R15 => 15,
            Register::RIP => 16,
        }
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
    /// Hit a breakpoint (INT3)
    Breakpoint { address: u64 },
    /// Hit an invalid/unsupported instruction
    InvalidInstruction { address: u64, opcode: u8 },
    /// Memory access fault
    MemoryFault { address: u64, reason: String },
    /// RET with empty stack
    StackUnderflow,
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
    /// Strings decrypted during emulation (addr → string)
    pub decrypted_strings: Vec<(u64, String)>,
    /// Memory regions written during emulation
    pub written_regions: Vec<(u64, usize)>,
}

/// The x86 micro-emulator.
pub struct Cpu {
    /// CPU state
    pub state: CpuState,
    /// Virtual memory
    pub memory: VirtualMemory,
    /// Decoded strings
    decrypted: Vec<(u64, String)>,
    /// Tracking writes
    write_log: Vec<(u64, usize)>,
    /// Entry RSP (to detect RET from entry)
    entry_rsp: u64,
}

impl Cpu {
    /// Create a new CPU with code loaded at the given address.
    pub fn new(code: &[u8], entry_point: u64) -> Self {
        let mut memory = VirtualMemory::new();

        // Map code
        let code_size = code.len().div_ceil(4096) * 4096;
        memory.map_region(entry_point, code_size as u64, Permission::RX, "code");
        // Temporarily set write to load the code
        memory.map_region(entry_point, code_size as u64, Permission::RWX, "code");
        let _ = memory.write(entry_point, code);

        // Map stack (1 MB below 0x7FFF_0000)
        let stack_base = 0x7FFE_0000_u64;
        let stack_size = 0x0010_0000_u64; // 1 MB
        memory.map_region(stack_base, stack_size, Permission::RW, "stack");
        let stack_top = stack_base + stack_size - 8;

        let mut state = CpuState {
            regs: [0; 17],
            flags: Flag::default(),
            insn_count: 0,
        };
        state.set(Register::RIP, entry_point);
        state.set(Register::RSP, stack_top);
        state.set(Register::RBP, stack_top);

        Self {
            entry_rsp: stack_top,
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

            let rip = self.state.get(Register::RIP);

            // Fetch opcode
            let opcode = match self.memory.read_u8(rip) {
                Ok(b) => b,
                Err(e) => {
                    return self.make_result(StopReason::MemoryFault {
                        address: rip,
                        reason: e.to_string(),
                    });
                }
            };

            // Execute
            match self.execute_one(opcode, rip) {
                Ok(None) => { /* continue */ }
                Ok(Some(stop)) => return self.make_result(stop),
                Err(e) => {
                    return self.make_result(StopReason::MemoryFault {
                        address: rip,
                        reason: e.to_string(),
                    });
                }
            }

            self.state.insn_count += 1;
        }
    }

    /// Helper to get iced-x86 register value
    fn get_reg_val(&self, r: iced_x86::Register) -> u64 {
        match r {
            // 64-bit
            iced_x86::Register::RAX => self.state.get(Register::RAX),
            iced_x86::Register::RBX => self.state.get(Register::RBX),
            iced_x86::Register::RCX => self.state.get(Register::RCX),
            iced_x86::Register::RDX => self.state.get(Register::RDX),
            iced_x86::Register::RSI => self.state.get(Register::RSI),
            iced_x86::Register::RDI => self.state.get(Register::RDI),
            iced_x86::Register::RSP => self.state.get(Register::RSP),
            iced_x86::Register::RBP => self.state.get(Register::RBP),
            iced_x86::Register::R8 => self.state.get(Register::R8),
            iced_x86::Register::R9 => self.state.get(Register::R9),
            iced_x86::Register::R10 => self.state.get(Register::R10),
            iced_x86::Register::R11 => self.state.get(Register::R11),
            iced_x86::Register::R12 => self.state.get(Register::R12),
            iced_x86::Register::R13 => self.state.get(Register::R13),
            iced_x86::Register::R14 => self.state.get(Register::R14),
            iced_x86::Register::R15 => self.state.get(Register::R15),
            iced_x86::Register::RIP => self.state.get(Register::RIP),

            // 32-bit
            iced_x86::Register::EAX => self.state.get(Register::RAX) as u32 as u64,
            iced_x86::Register::EBX => self.state.get(Register::RBX) as u32 as u64,
            iced_x86::Register::ECX => self.state.get(Register::RCX) as u32 as u64,
            iced_x86::Register::EDX => self.state.get(Register::RDX) as u32 as u64,
            iced_x86::Register::ESI => self.state.get(Register::RSI) as u32 as u64,
            iced_x86::Register::EDI => self.state.get(Register::RDI) as u32 as u64,
            iced_x86::Register::ESP => self.state.get(Register::RSP) as u32 as u64,
            iced_x86::Register::EBP => self.state.get(Register::RBP) as u32 as u64,
            iced_x86::Register::R8D => self.state.get(Register::R8) as u32 as u64,
            iced_x86::Register::R9D => self.state.get(Register::R9) as u32 as u64,
            iced_x86::Register::R10D => self.state.get(Register::R10) as u32 as u64,
            iced_x86::Register::R11D => self.state.get(Register::R11) as u32 as u64,
            iced_x86::Register::R12D => self.state.get(Register::R12) as u32 as u64,
            iced_x86::Register::R13D => self.state.get(Register::R13) as u32 as u64,
            iced_x86::Register::R14D => self.state.get(Register::R14) as u32 as u64,
            iced_x86::Register::R15D => self.state.get(Register::R15) as u32 as u64,

            // 16-bit
            iced_x86::Register::AX => self.state.get(Register::RAX) as u16 as u64,
            iced_x86::Register::BX => self.state.get(Register::RBX) as u16 as u64,
            iced_x86::Register::CX => self.state.get(Register::RCX) as u16 as u64,
            iced_x86::Register::DX => self.state.get(Register::RDX) as u16 as u64,
            iced_x86::Register::SI => self.state.get(Register::RSI) as u16 as u64,
            iced_x86::Register::DI => self.state.get(Register::RDI) as u16 as u64,
            iced_x86::Register::SP => self.state.get(Register::RSP) as u16 as u64,
            iced_x86::Register::BP => self.state.get(Register::RBP) as u16 as u64,
            iced_x86::Register::R8W => self.state.get(Register::R8) as u16 as u64,
            iced_x86::Register::R9W => self.state.get(Register::R9) as u16 as u64,
            iced_x86::Register::R10W => self.state.get(Register::R10) as u16 as u64,
            iced_x86::Register::R11W => self.state.get(Register::R11) as u16 as u64,
            iced_x86::Register::R12W => self.state.get(Register::R12) as u16 as u64,
            iced_x86::Register::R13W => self.state.get(Register::R13) as u16 as u64,
            iced_x86::Register::R14W => self.state.get(Register::R14) as u16 as u64,
            iced_x86::Register::R15W => self.state.get(Register::R15) as u16 as u64,

            // 8-bit low
            iced_x86::Register::AL => self.state.get(Register::RAX) as u8 as u64,
            iced_x86::Register::BL => self.state.get(Register::RBX) as u8 as u64,
            iced_x86::Register::CL => self.state.get(Register::RCX) as u8 as u64,
            iced_x86::Register::DL => self.state.get(Register::RDX) as u8 as u64,
            iced_x86::Register::SIL => self.state.get(Register::RSI) as u8 as u64,
            iced_x86::Register::DIL => self.state.get(Register::RDI) as u8 as u64,
            iced_x86::Register::SPL => self.state.get(Register::RSP) as u8 as u64,
            iced_x86::Register::BPL => self.state.get(Register::RBP) as u8 as u64,
            iced_x86::Register::R8L => self.state.get(Register::R8) as u8 as u64,
            iced_x86::Register::R9L => self.state.get(Register::R9) as u8 as u64,
            iced_x86::Register::R10L => self.state.get(Register::R10) as u8 as u64,
            iced_x86::Register::R11L => self.state.get(Register::R11) as u8 as u64,
            iced_x86::Register::R12L => self.state.get(Register::R12) as u8 as u64,
            iced_x86::Register::R13L => self.state.get(Register::R13) as u8 as u64,
            iced_x86::Register::R14L => self.state.get(Register::R14) as u8 as u64,
            iced_x86::Register::R15L => self.state.get(Register::R15) as u8 as u64,

            // 8-bit high
            iced_x86::Register::AH => (self.state.get(Register::RAX) >> 8) as u8 as u64,
            iced_x86::Register::BH => (self.state.get(Register::RBX) >> 8) as u8 as u64,
            iced_x86::Register::CH => (self.state.get(Register::RCX) >> 8) as u8 as u64,
            iced_x86::Register::DH => (self.state.get(Register::RDX) >> 8) as u8 as u64,

            _ => 0,
        }
    }

    /// Helper to set iced-x86 register value
    fn set_reg_val(&mut self, r: iced_x86::Register, val: u64) {
        match r {
            // 64-bit
            iced_x86::Register::RAX => self.state.set(Register::RAX, val),
            iced_x86::Register::RBX => self.state.set(Register::RBX, val),
            iced_x86::Register::RCX => self.state.set(Register::RCX, val),
            iced_x86::Register::RDX => self.state.set(Register::RDX, val),
            iced_x86::Register::RSI => self.state.set(Register::RSI, val),
            iced_x86::Register::RDI => self.state.set(Register::RDI, val),
            iced_x86::Register::RSP => self.state.set(Register::RSP, val),
            iced_x86::Register::RBP => self.state.set(Register::RBP, val),
            iced_x86::Register::R8 => self.state.set(Register::R8, val),
            iced_x86::Register::R9 => self.state.set(Register::R9, val),
            iced_x86::Register::R10 => self.state.set(Register::R10, val),
            iced_x86::Register::R11 => self.state.set(Register::R11, val),
            iced_x86::Register::R12 => self.state.set(Register::R12, val),
            iced_x86::Register::R13 => self.state.set(Register::R13, val),
            iced_x86::Register::R14 => self.state.set(Register::R14, val),
            iced_x86::Register::R15 => self.state.set(Register::R15, val),
            iced_x86::Register::RIP => self.state.set(Register::RIP, val),

            // 32-bit zero-extends to 64-bit!
            iced_x86::Register::EAX => self.state.set(Register::RAX, val as u32 as u64),
            iced_x86::Register::EBX => self.state.set(Register::RBX, val as u32 as u64),
            iced_x86::Register::ECX => self.state.set(Register::RCX, val as u32 as u64),
            iced_x86::Register::EDX => self.state.set(Register::RDX, val as u32 as u64),
            iced_x86::Register::ESI => self.state.set(Register::RSI, val as u32 as u64),
            iced_x86::Register::EDI => self.state.set(Register::RDI, val as u32 as u64),
            iced_x86::Register::ESP => self.state.set(Register::RSP, val as u32 as u64),
            iced_x86::Register::EBP => self.state.set(Register::RBP, val as u32 as u64),
            iced_x86::Register::R8D => self.state.set(Register::R8, val as u32 as u64),
            iced_x86::Register::R9D => self.state.set(Register::R9, val as u32 as u64),
            iced_x86::Register::R10D => self.state.set(Register::R10, val as u32 as u64),
            iced_x86::Register::R11D => self.state.set(Register::R11, val as u32 as u64),
            iced_x86::Register::R12D => self.state.set(Register::R12, val as u32 as u64),
            iced_x86::Register::R13D => self.state.set(Register::R13, val as u32 as u64),
            iced_x86::Register::R14D => self.state.set(Register::R14, val as u32 as u64),
            iced_x86::Register::R15D => self.state.set(Register::R15, val as u32 as u64),

            // 16-bit leaves higher bits intact
            iced_x86::Register::AX => {
                let cur = self.state.get(Register::RAX) & !0xFFFF;
                self.state.set(Register::RAX, cur | (val & 0xFFFF));
            }
            iced_x86::Register::BX => {
                let cur = self.state.get(Register::RBX) & !0xFFFF;
                self.state.set(Register::RBX, cur | (val & 0xFFFF));
            }
            iced_x86::Register::CX => {
                let cur = self.state.get(Register::RCX) & !0xFFFF;
                self.state.set(Register::RCX, cur | (val & 0xFFFF));
            }
            iced_x86::Register::DX => {
                let cur = self.state.get(Register::RDX) & !0xFFFF;
                self.state.set(Register::RDX, cur | (val & 0xFFFF));
            }
            iced_x86::Register::SI => {
                let cur = self.state.get(Register::RSI) & !0xFFFF;
                self.state.set(Register::RSI, cur | (val & 0xFFFF));
            }
            iced_x86::Register::DI => {
                let cur = self.state.get(Register::RDI) & !0xFFFF;
                self.state.set(Register::RDI, cur | (val & 0xFFFF));
            }
            iced_x86::Register::SP => {
                let cur = self.state.get(Register::RSP) & !0xFFFF;
                self.state.set(Register::RSP, cur | (val & 0xFFFF));
            }
            iced_x86::Register::BP => {
                let cur = self.state.get(Register::RBP) & !0xFFFF;
                self.state.set(Register::RBP, cur | (val & 0xFFFF));
            }
            iced_x86::Register::R8W => {
                let cur = self.state.get(Register::R8) & !0xFFFF;
                self.state.set(Register::R8, cur | (val & 0xFFFF));
            }
            iced_x86::Register::R9W => {
                let cur = self.state.get(Register::R9) & !0xFFFF;
                self.state.set(Register::R9, cur | (val & 0xFFFF));
            }
            iced_x86::Register::R10W => {
                let cur = self.state.get(Register::R10) & !0xFFFF;
                self.state.set(Register::R10, cur | (val & 0xFFFF));
            }
            iced_x86::Register::R11W => {
                let cur = self.state.get(Register::R11) & !0xFFFF;
                self.state.set(Register::R11, cur | (val & 0xFFFF));
            }
            iced_x86::Register::R12W => {
                let cur = self.state.get(Register::R12) & !0xFFFF;
                self.state.set(Register::R12, cur | (val & 0xFFFF));
            }
            iced_x86::Register::R13W => {
                let cur = self.state.get(Register::R13) & !0xFFFF;
                self.state.set(Register::R13, cur | (val & 0xFFFF));
            }
            iced_x86::Register::R14W => {
                let cur = self.state.get(Register::R14) & !0xFFFF;
                self.state.set(Register::R14, cur | (val & 0xFFFF));
            }
            iced_x86::Register::R15W => {
                let cur = self.state.get(Register::R15) & !0xFFFF;
                self.state.set(Register::R15, cur | (val & 0xFFFF));
            }

            // 8-bit low leaves higher bits intact
            iced_x86::Register::AL => {
                let cur = self.state.get(Register::RAX) & !0xFF;
                self.state.set(Register::RAX, cur | (val & 0xFF));
            }
            iced_x86::Register::BL => {
                let cur = self.state.get(Register::RBX) & !0xFF;
                self.state.set(Register::RBX, cur | (val & 0xFF));
            }
            iced_x86::Register::CL => {
                let cur = self.state.get(Register::RCX) & !0xFF;
                self.state.set(Register::RCX, cur | (val & 0xFF));
            }
            iced_x86::Register::DL => {
                let cur = self.state.get(Register::RDX) & !0xFF;
                self.state.set(Register::RDX, cur | (val & 0xFF));
            }
            iced_x86::Register::SIL => {
                let cur = self.state.get(Register::RSI) & !0xFF;
                self.state.set(Register::RSI, cur | (val & 0xFF));
            }
            iced_x86::Register::DIL => {
                let cur = self.state.get(Register::RDI) & !0xFF;
                self.state.set(Register::RDI, cur | (val & 0xFF));
            }
            iced_x86::Register::SPL => {
                let cur = self.state.get(Register::RSP) & !0xFF;
                self.state.set(Register::RSP, cur | (val & 0xFF));
            }
            iced_x86::Register::BPL => {
                let cur = self.state.get(Register::RBP) & !0xFF;
                self.state.set(Register::RBP, cur | (val & 0xFF));
            }
            iced_x86::Register::R8L => {
                let cur = self.state.get(Register::R8) & !0xFF;
                self.state.set(Register::R8, cur | (val & 0xFF));
            }
            iced_x86::Register::R9L => {
                let cur = self.state.get(Register::R9) & !0xFF;
                self.state.set(Register::R9, cur | (val & 0xFF));
            }
            iced_x86::Register::R10L => {
                let cur = self.state.get(Register::R10) & !0xFF;
                self.state.set(Register::R10, cur | (val & 0xFF));
            }
            iced_x86::Register::R11L => {
                let cur = self.state.get(Register::R11) & !0xFF;
                self.state.set(Register::R11, cur | (val & 0xFF));
            }
            iced_x86::Register::R12L => {
                let cur = self.state.get(Register::R12) & !0xFF;
                self.state.set(Register::R12, cur | (val & 0xFF));
            }
            iced_x86::Register::R13L => {
                let cur = self.state.get(Register::R13) & !0xFF;
                self.state.set(Register::R13, cur | (val & 0xFF));
            }
            iced_x86::Register::R14L => {
                let cur = self.state.get(Register::R14) & !0xFF;
                self.state.set(Register::R14, cur | (val & 0xFF));
            }
            iced_x86::Register::R15L => {
                let cur = self.state.get(Register::R15) & !0xFF;
                self.state.set(Register::R15, cur | (val & 0xFF));
            }

            // 8-bit high leaves other bits intact
            iced_x86::Register::AH => {
                let cur = self.state.get(Register::RAX) & !0xFF00;
                self.state.set(Register::RAX, cur | ((val & 0xFF) << 8));
            }
            iced_x86::Register::BH => {
                let cur = self.state.get(Register::RBX) & !0xFF00;
                self.state.set(Register::RBX, cur | ((val & 0xFF) << 8));
            }
            iced_x86::Register::CH => {
                let cur = self.state.get(Register::RCX) & !0xFF00;
                self.state.set(Register::RCX, cur | ((val & 0xFF) << 8));
            }
            iced_x86::Register::DH => {
                let cur = self.state.get(Register::RDX) & !0xFF00;
                self.state.set(Register::RDX, cur | ((val & 0xFF) << 8));
            }

            _ => {}
        }
    }

    /// Resolve memory operand address
    fn get_mem_addr(&self, instr: &iced_x86::Instruction, _op_idx: u32) -> u64 {
        let base = instr.memory_base();
        let index = instr.memory_index();
        let scale = instr.memory_index_scale();
        let displacement = instr.memory_displacement64();

        let mut addr = displacement;
        if base != iced_x86::Register::None {
            addr = addr.wrapping_add(self.get_reg_val(base));
        }
        if index != iced_x86::Register::None {
            addr = addr.wrapping_add(self.get_reg_val(index).wrapping_mul(scale as u64));
        }

        addr
    }

    /// Resolve memory operand size
    fn get_mem_size(&self, instr: &iced_x86::Instruction) -> usize {
        instr.memory_size().size()
    }

    /// Read value from memory with exact size
    fn read_mem(&self, addr: u64, size: usize) -> Result<u64, MemoryError> {
        match size {
            1 => self.memory.read_u8(addr).map(|v| v as u64),
            2 => self
                .memory
                .read(addr, 2)
                .map(|v| u16::from_le_bytes(v.try_into().unwrap()) as u64),
            4 => self
                .memory
                .read(addr, 4)
                .map(|v| u32::from_le_bytes(v.try_into().unwrap()) as u64),
            8 => self
                .memory
                .read(addr, 8)
                .map(|v| u64::from_le_bytes(v.try_into().unwrap())),
            _ => Err(MemoryError::Unmapped { addr }),
        }
    }

    /// Write value to memory with exact size
    fn write_mem(&mut self, addr: u64, size: usize, val: u64) -> Result<(), MemoryError> {
        let bytes = match size {
            1 => vec![val as u8],
            2 => (val as u16).to_le_bytes().to_vec(),
            4 => (val as u32).to_le_bytes().to_vec(),
            8 => val.to_le_bytes().to_vec(),
            _ => return Err(MemoryError::Unmapped { addr }),
        };
        self.memory.write(addr, &bytes)?;
        self.write_log.push((addr, size));
        Ok(())
    }

    /// Determine operand size in bits
    fn get_op_size_in_bits(&self, instr: &iced_x86::Instruction, op_idx: u32) -> usize {
        match instr.op_kind(op_idx) {
            iced_x86::OpKind::Register => {
                let r = instr.op_register(op_idx);
                if r.is_gpr64() {
                    64
                } else if r.is_gpr32() {
                    32
                } else if r.is_gpr16() {
                    16
                } else if r.is_gpr8() {
                    8
                } else {
                    64
                }
            }
            iced_x86::OpKind::Memory => instr.memory_size().size() * 8,
            _ => 32, // fallback
        }
    }

    /// Read value from operand (register, memory, or immediate)
    fn get_op_val(&self, instr: &iced_x86::Instruction, op_idx: u32) -> Result<u64, MemoryError> {
        match instr.op_kind(op_idx) {
            iced_x86::OpKind::Register => Ok(self.get_reg_val(instr.op_register(op_idx))),
            iced_x86::OpKind::Memory => {
                let addr = self.get_mem_addr(instr, op_idx);
                let size = self.get_mem_size(instr);
                self.read_mem(addr, size)
            }
            iced_x86::OpKind::Immediate8 => Ok(u64::from(instr.immediate8())),
            iced_x86::OpKind::Immediate16 => Ok(u64::from(instr.immediate16())),
            iced_x86::OpKind::Immediate32 => Ok(u64::from(instr.immediate32())),
            iced_x86::OpKind::Immediate64 => Ok(instr.immediate64()),
            iced_x86::OpKind::Immediate8to16 => Ok(instr.immediate8to16() as u16 as u64),
            iced_x86::OpKind::Immediate8to32 => Ok(instr.immediate8to32() as u32 as u64),
            iced_x86::OpKind::Immediate8to64 => Ok(instr.immediate8to64() as u64),
            iced_x86::OpKind::Immediate32to64 => Ok(instr.immediate32to64() as u64),
            _ => Ok(0),
        }
    }

    /// Write value to operand (register or memory)
    fn set_op_val(
        &mut self,
        instr: &iced_x86::Instruction,
        op_idx: u32,
        val: u64,
    ) -> Result<(), MemoryError> {
        match instr.op_kind(op_idx) {
            iced_x86::OpKind::Register => {
                self.set_reg_val(instr.op_register(op_idx), val);
                Ok(())
            }
            iced_x86::OpKind::Memory => {
                let addr = self.get_mem_addr(instr, op_idx);
                let size = self.get_mem_size(instr);
                self.write_mem(addr, size, val)
            }
            _ => Ok(()),
        }
    }

    /// Helper to evaluate conditional jump conditions
    fn eval_condition(&self, m: iced_x86::Mnemonic) -> bool {
        let f = &self.state.flags;
        match m {
            iced_x86::Mnemonic::Je => f.zf,
            iced_x86::Mnemonic::Jne => !f.zf,
            iced_x86::Mnemonic::Js => f.sf,
            iced_x86::Mnemonic::Jns => !f.sf,
            iced_x86::Mnemonic::Jg => !f.zf && (f.sf == f.of),
            iced_x86::Mnemonic::Jge => f.sf == f.of,
            iced_x86::Mnemonic::Jl => f.sf != f.of,
            iced_x86::Mnemonic::Jle => f.zf || (f.sf != f.of),
            iced_x86::Mnemonic::Ja => !f.cf && !f.zf,
            iced_x86::Mnemonic::Jae => !f.cf,
            iced_x86::Mnemonic::Jb => f.cf,
            iced_x86::Mnemonic::Jbe => f.cf || f.zf,
            iced_x86::Mnemonic::Jo => f.of,
            iced_x86::Mnemonic::Jno => !f.of,
            iced_x86::Mnemonic::Jp => f.cf, // treat jp as cf/zf for simple shellcode
            iced_x86::Mnemonic::Jnp => !f.cf,
            _ => false,
        }
    }

    /// Helper to update flags dynamically for arithmetic
    fn update_flags_arith(&mut self, op1: u64, op2: u64, res: u64, is_sub: bool) {
        self.state.flags.zf = res == 0;
        self.state.flags.sf = (res as i64) < 0;

        let op1_s = (op1 as i64) < 0;
        let op2_s = (op2 as i64) < 0;
        let res_s = (res as i64) < 0;

        self.state.flags.of = if is_sub {
            (op1_s != op2_s) && (res_s == op2_s)
        } else {
            (op1_s == op2_s) && (res_s != op1_s)
        };
    }

    /// Execute a single instruction. Returns Some(StopReason) to stop.
    fn execute_one(&mut self, opcode: u8, rip: u64) -> Result<Option<StopReason>, MemoryError> {
        let mut buf = [0u8; 15];
        let mut len = 0;
        for i in 0..15 {
            if let Ok(b) = self.memory.read_u8(rip + i as u64) {
                buf[i] = b;
                len += 1;
            } else {
                break;
            }
        }
        if len == 0 {
            return Err(MemoryError::Unmapped { addr: rip });
        }

        let mut decoder =
            iced_x86::Decoder::with_ip(64, &buf[..len], rip, iced_x86::DecoderOptions::NONE);
        let mut instr = iced_x86::Instruction::default();
        decoder.decode_out(&mut instr);

        if instr.is_invalid() {
            return Ok(Some(StopReason::InvalidInstruction {
                address: rip,
                opcode,
            }));
        }

        let instr_len = instr.len();
        let mut next_rip = rip + instr_len as u64;
        self.state.set(Register::RIP, next_rip);

        let m = instr.mnemonic();

        match m {
            iced_x86::Mnemonic::Nop => {}

            iced_x86::Mnemonic::Mov | iced_x86::Mnemonic::Movsx | iced_x86::Mnemonic::Movzx => {
                let src = self.get_op_val(&instr, 1)?;
                let src_size = self.get_op_size_in_bits(&instr, 1);
                let val = if m == iced_x86::Mnemonic::Movsx {
                    sign_extend(src, src_size)
                } else if m == iced_x86::Mnemonic::Movzx {
                    zero_extend(src, src_size)
                } else {
                    src
                };
                self.set_op_val(&instr, 0, val)?;
            }

            iced_x86::Mnemonic::Push => {
                let val = self.get_op_val(&instr, 0)?;
                let rsp = self.state.get(Register::RSP) - 8;
                self.state.set(Register::RSP, rsp);
                self.write_mem(rsp, 8, val)?;
            }

            iced_x86::Mnemonic::Pop => {
                let rsp = self.state.get(Register::RSP);
                let val = self.read_mem(rsp, 8)?;
                self.state.set(Register::RSP, rsp + 8);
                self.set_op_val(&instr, 0, val)?;
            }

            iced_x86::Mnemonic::Lea => {
                let addr = self.get_mem_addr(&instr, 1);
                self.set_op_val(&instr, 0, addr)?;
            }

            iced_x86::Mnemonic::Xchg => {
                let val1 = self.get_op_val(&instr, 0)?;
                let val2 = self.get_op_val(&instr, 1)?;
                self.set_op_val(&instr, 0, val2)?;
                self.set_op_val(&instr, 1, val1)?;
            }

            iced_x86::Mnemonic::Add => {
                let dest = self.get_op_val(&instr, 0)?;
                let src = self.get_op_val(&instr, 1)?;
                let (res, carry) = dest.overflowing_add(src);
                self.set_op_val(&instr, 0, res)?;
                self.update_flags_arith(dest, src, res, false);
                self.state.flags.cf = carry;
            }

            iced_x86::Mnemonic::Sub => {
                let dest = self.get_op_val(&instr, 0)?;
                let src = self.get_op_val(&instr, 1)?;
                let (res, carry) = dest.overflowing_sub(src);
                self.set_op_val(&instr, 0, res)?;
                self.update_flags_arith(dest, src, res, true);
                self.state.flags.cf = carry;
            }

            iced_x86::Mnemonic::Cmp => {
                let dest = self.get_op_val(&instr, 0)?;
                let src = self.get_op_val(&instr, 1)?;
                let (res, carry) = dest.overflowing_sub(src);
                self.update_flags_arith(dest, src, res, true);
                self.state.flags.cf = carry;
            }

            iced_x86::Mnemonic::Test => {
                let dest = self.get_op_val(&instr, 0)?;
                let src = self.get_op_val(&instr, 1)?;
                let res = dest & src;
                self.state.flags.zf = res == 0;
                self.state.flags.sf = (res as i64) < 0;
                self.state.flags.cf = false;
                self.state.flags.of = false;
            }

            iced_x86::Mnemonic::And | iced_x86::Mnemonic::Or | iced_x86::Mnemonic::Xor => {
                let dest = self.get_op_val(&instr, 0)?;
                let src = self.get_op_val(&instr, 1)?;
                let res = match m {
                    iced_x86::Mnemonic::And => dest & src,
                    iced_x86::Mnemonic::Or => dest | src,
                    iced_x86::Mnemonic::Xor => dest ^ src,
                    _ => 0,
                };
                self.set_op_val(&instr, 0, res)?;
                self.state.flags.zf = res == 0;
                self.state.flags.sf = (res as i64) < 0;
                self.state.flags.cf = false;
                self.state.flags.of = false;
            }

            iced_x86::Mnemonic::Not => {
                let dest = self.get_op_val(&instr, 0)?;
                self.set_op_val(&instr, 0, !dest)?;
            }

            iced_x86::Mnemonic::Neg => {
                let dest = self.get_op_val(&instr, 0)?;
                let res = 0u64.wrapping_sub(dest);
                self.set_op_val(&instr, 0, res)?;
                self.state.flags.zf = res == 0;
                self.state.flags.sf = (res as i64) < 0;
                self.state.flags.cf = dest != 0;
                self.state.flags.of = dest == 0x8000_0000_0000_0000;
            }

            iced_x86::Mnemonic::Inc | iced_x86::Mnemonic::Dec => {
                let dest = self.get_op_val(&instr, 0)?;
                let res = match m {
                    iced_x86::Mnemonic::Inc => dest.wrapping_add(1),
                    iced_x86::Mnemonic::Dec => dest.wrapping_sub(1),
                    _ => dest,
                };
                self.set_op_val(&instr, 0, res)?;
                self.update_flags_arith(dest, 1, res, m == iced_x86::Mnemonic::Dec);
            }

            iced_x86::Mnemonic::Mul | iced_x86::Mnemonic::Imul => {
                if instr.op_count() == 1 {
                    let op = self.get_op_val(&instr, 0)?;
                    let rax = self.state.get(Register::RAX);
                    if m == iced_x86::Mnemonic::Mul {
                        let res = (rax as u128).wrapping_mul(op as u128);
                        self.state.set(Register::RAX, res as u64);
                        self.state.set(Register::RDX, (res >> 64) as u64);
                        self.state.flags.cf = (res >> 64) != 0;
                        self.state.flags.of = (res >> 64) != 0;
                    } else {
                        let res = (rax as i64 as i128).wrapping_mul(op as i64 as i128);
                        self.state.set(Register::RAX, res as u64);
                        self.state.set(Register::RDX, (res >> 64) as u64);
                        let high = (res >> 64) as i64;
                        let low = res as u64 as i64;
                        let overflow = high != (if low < 0 { -1 } else { 0 });
                        self.state.flags.cf = overflow;
                        self.state.flags.of = overflow;
                    }
                } else if instr.op_count() == 2 {
                    let dest = self.get_op_val(&instr, 0)?;
                    let src = self.get_op_val(&instr, 1)?;
                    let res = (dest as i64).wrapping_mul(src as i64) as u64;
                    self.set_op_val(&instr, 0, res)?;
                } else if instr.op_count() == 3 {
                    let src1 = self.get_op_val(&instr, 1)?;
                    let src2 = self.get_op_val(&instr, 2)?;
                    let res = (src1 as i64).wrapping_mul(src2 as i64) as u64;
                    self.set_op_val(&instr, 0, res)?;
                }
            }

            iced_x86::Mnemonic::Div | iced_x86::Mnemonic::Idiv => {
                let op = self.get_op_val(&instr, 0)?;
                if op == 0 {
                    return Ok(Some(StopReason::InvalidInstruction {
                        address: rip,
                        opcode,
                    }));
                }
                let rax = self.state.get(Register::RAX);
                let rdx = self.state.get(Register::RDX);
                let dividend = ((rdx as u128) << 64) | (rax as u128);
                if m == iced_x86::Mnemonic::Div {
                    let quot = dividend / (op as u128);
                    let rem = dividend % (op as u128);
                    self.state.set(Register::RAX, quot as u64);
                    self.state.set(Register::RDX, rem as u64);
                } else {
                    let dividend_s = dividend as i128;
                    let op_s = op as i64 as i128;
                    let quot = dividend_s / op_s;
                    let rem = dividend_s % op_s;
                    self.state.set(Register::RAX, quot as u64);
                    self.state.set(Register::RDX, rem as u64);
                }
            }

            iced_x86::Mnemonic::Shl
            | iced_x86::Mnemonic::Shr
            | iced_x86::Mnemonic::Sar
            | iced_x86::Mnemonic::Rol
            | iced_x86::Mnemonic::Ror => {
                let dest = self.get_op_val(&instr, 0)?;
                let count = self.get_op_val(&instr, 1)? & 0x3F;
                if count > 0 {
                    let res = match m {
                        iced_x86::Mnemonic::Shl => dest.wrapping_shl(count as u32),
                        iced_x86::Mnemonic::Shr => dest.wrapping_shr(count as u32),
                        iced_x86::Mnemonic::Sar => (dest as i64).wrapping_shr(count as u32) as u64,
                        iced_x86::Mnemonic::Rol => dest.rotate_left(count as u32),
                        iced_x86::Mnemonic::Ror => dest.rotate_right(count as u32),
                        _ => dest,
                    };
                    self.set_op_val(&instr, 0, res)?;
                    self.state.flags.zf = res == 0;
                    self.state.flags.sf = (res as i64) < 0;
                }
            }

            iced_x86::Mnemonic::Jmp => {
                let target = self.get_op_val(&instr, 0)?;
                self.state.set(Register::RIP, target);
                next_rip = target;
            }

            iced_x86::Mnemonic::Je
            | iced_x86::Mnemonic::Jne
            | iced_x86::Mnemonic::Js
            | iced_x86::Mnemonic::Jns
            | iced_x86::Mnemonic::Jg
            | iced_x86::Mnemonic::Jge
            | iced_x86::Mnemonic::Jl
            | iced_x86::Mnemonic::Jle
            | iced_x86::Mnemonic::Ja
            | iced_x86::Mnemonic::Jae
            | iced_x86::Mnemonic::Jb
            | iced_x86::Mnemonic::Jbe
            | iced_x86::Mnemonic::Jo
            | iced_x86::Mnemonic::Jno
            | iced_x86::Mnemonic::Jp
            | iced_x86::Mnemonic::Jnp => {
                if self.eval_condition(m) {
                    let target = self.get_op_val(&instr, 0)?;
                    self.state.set(Register::RIP, target);
                    next_rip = target;
                }
            }

            iced_x86::Mnemonic::Call => {
                let target = self.get_op_val(&instr, 0)?;
                let rsp = self.state.get(Register::RSP) - 8;
                self.state.set(Register::RSP, rsp);
                self.write_mem(rsp, 8, next_rip)?;
                self.state.set(Register::RIP, target);
                next_rip = target;
            }

            iced_x86::Mnemonic::Ret => {
                let rsp = self.state.get(Register::RSP);
                if rsp >= self.entry_rsp {
                    return Ok(Some(StopReason::Completed));
                }
                let ret_addr = self.read_mem(rsp, 8)?;
                self.state.set(Register::RSP, rsp + 8);
                self.state.set(Register::RIP, ret_addr);
                next_rip = ret_addr;
            }

            iced_x86::Mnemonic::Loop | iced_x86::Mnemonic::Loope | iced_x86::Mnemonic::Loopne => {
                let mut rcx = self.state.get(Register::RCX);
                rcx = rcx.wrapping_sub(1);
                self.state.set(Register::RCX, rcx);
                let mut cond = rcx != 0;
                if m == iced_x86::Mnemonic::Loope {
                    cond = cond && self.state.flags.zf;
                } else if m == iced_x86::Mnemonic::Loopne {
                    cond = cond && !self.state.flags.zf;
                }
                if cond {
                    let target = self.get_op_val(&instr, 0)?;
                    self.state.set(Register::RIP, target);
                    next_rip = target;
                }
            }

            iced_x86::Mnemonic::Movsb | iced_x86::Mnemonic::Stosb => {
                let has_rep = instr.has_rep_prefix();
                match m {
                    iced_x86::Mnemonic::Movsb => {
                        let count = if has_rep {
                            self.state.get(Register::RCX)
                        } else {
                            1
                        };
                        for _ in 0..count {
                            let rsi = self.state.get(Register::RSI);
                            let rdi = self.state.get(Register::RDI);
                            let val = self.memory.read_u8(rsi)?;
                            self.write_mem(rdi, 1, val as u64)?;
                            self.state.set(Register::RSI, rsi + 1);
                            self.state.set(Register::RDI, rdi + 1);
                        }
                        if has_rep {
                            self.state.set(Register::RCX, 0);
                        }
                    }
                    iced_x86::Mnemonic::Stosb => {
                        let count = if has_rep {
                            self.state.get(Register::RCX)
                        } else {
                            1
                        };
                        let al = self.state.get(Register::RAX) as u8;
                        for _ in 0..count {
                            let rdi = self.state.get(Register::RDI);
                            self.write_mem(rdi, 1, al as u64)?;
                            self.state.set(Register::RDI, rdi + 1);
                        }
                        if has_rep {
                            self.state.set(Register::RCX, 0);
                        }
                    }
                    _ => {}
                }
            }

            iced_x86::Mnemonic::Int3 => {
                return Ok(Some(StopReason::Breakpoint { address: rip }));
            }

            _ => {
                return Ok(Some(StopReason::InvalidInstruction {
                    address: rip,
                    opcode,
                }));
            }
        }

        Ok(None)
    }

    fn make_result(&self, stop: StopReason) -> EmulationResult {
        EmulationResult {
            state: self.state.clone(),
            stop_reason: stop,
            decrypted_strings: self.decrypted.clone(),
            written_regions: self.write_log.clone(),
        }
    }
}

fn sign_extend(val: u64, bits: usize) -> u64 {
    match bits {
        8 => val as u8 as i8 as i64 as u64,
        16 => val as u16 as i16 as i64 as u64,
        32 => val as u32 as i32 as i64 as u64,
        _ => val,
    }
}

fn zero_extend(val: u64, bits: usize) -> u64 {
    match bits {
        8 => val as u8 as u64,
        16 => val as u16 as u64,
        32 => val as u32 as u64,
        _ => val,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nop_sled() {
        // 3 NOPs + INT3
        let code = [0x90, 0x90, 0x90, 0xCC];
        let mut cpu = Cpu::new(&code, 0x1000);
        let result = cpu.run(100);

        assert_eq!(result.state.insn_count, 3);
        matches!(result.stop_reason, StopReason::Breakpoint { .. });
    }

    #[test]
    fn xor_zeroes_register() {
        // XOR EAX, EAX (0x31 0xC0) + INT3
        let code = [0x31, 0xC0, 0xCC];
        let mut cpu = Cpu::new(&code, 0x1000);
        cpu.state.set(Register::RAX, 0xDEAD_BEEF);

        let result = cpu.run(100);
        assert_eq!(result.state.get(Register::RAX), 0);
        assert!(result.state.flags.zf);
    }

    #[test]
    fn ret_from_entry() {
        // RET (0xC3) — should complete since stack is at entry_rsp
        let code = [0xC3];
        let mut cpu = Cpu::new(&code, 0x1000);
        let result = cpu.run(100);
        matches!(result.stop_reason, StopReason::Completed);
    }

    #[test]
    fn max_instructions_stop() {
        // Infinite NOP sled
        let code = vec![0x90; 1000];
        let mut cpu = Cpu::new(&code, 0x1000);
        let result = cpu.run(50);
        matches!(result.stop_reason, StopReason::MaxInstructions);
        assert_eq!(result.state.insn_count, 50);
    }
}
