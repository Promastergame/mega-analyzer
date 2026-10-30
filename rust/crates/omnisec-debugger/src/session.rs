//! Debugger session — owns the execution engine, breakpoints, and loaded binary metadata.

use std::path::Path;

use omnisec_core::Arch;
use omnisec_emu_x86::Permission;
use omnisec_loader::{LoadedBinary, LoaderRegistry, SectionFlags};
use omnisec_loader_elf::ElfLoader;
use omnisec_loader_macho::MachOLoader;
use omnisec_loader_pe::PeLoader;

use crate::breakpoint::BreakpointManager;
use crate::commands::DisassemblyFlavor;
use crate::engine::{ExecutionEngine, StepResult, StopReason};
use crate::hdc_scanner::HDCHit;
use crate::ml_annotator::Strategy;

/// Configuration for a debugging session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Architecture to emulate (must match the binary).
    pub arch: Arch,
    /// Entry point override (None = use binary's entry point).
    pub entry_point: Option<u64>,
    /// Max instructions before forced stop in `continue`.
    pub max_instructions: u64,
    /// Initial stack size.
    pub stack_size: usize,
    /// Disassembly syntax flavor.
    pub disassembly_flavor: DisassemblyFlavor,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            arch: Arch::X86_64,
            entry_point: None,
            max_instructions: 1_000_000,
            stack_size: 1024 * 1024,
            disassembly_flavor: DisassemblyFlavor::Intel,
        }
    }
}

/// A live debugging session.
#[derive(Debug)]
pub struct DebuggerSession {
    /// Configuration.
    pub config: SessionConfig,
    /// Loaded binary metadata.
    pub binary: Option<LoadedBinary>,
    /// Execution engine.
    pub engine: ExecutionEngine,
    /// Breakpoint manager.
    pub breakpoints: BreakpointManager,
    /// File bytes (for section mapping).
    file_bytes: Vec<u8>,
    /// Is the session running (between `continue` and stop)?
    pub running: bool,
    /// Last stop reason (for display).
    pub last_stop: Option<StopReason>,
}

impl DebuggerSession {
    /// Load a binary and create a new session.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or is an unsupported arch.
    pub fn from_file(path: &Path, config: SessionConfig) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read file: {e}"))?;

        let mut registry = LoaderRegistry::new();
        registry.register(ElfLoader::new());
        registry.register(PeLoader::new());
        registry.register(MachOLoader::new());
        let bin = registry
            .dispatch(&bytes)
            .map_err(|e| format!("loader error: {e}"))?;

        if !matches!(bin.arch, Arch::X86 | Arch::X86_64) {
            return Err(format!("arch {} not yet supported by debugger", bin.arch));
        }

        let entry = config.entry_point.or(bin.entry_point).unwrap_or(0x1000);

        let mut engine = ExecutionEngine::new(&bytes, entry, bin.arch);

        // Map sections into emulator memory
        for sec in &bin.sections {
            let off = sec.file_offset as usize;
            let len = sec.file_size as usize;
            if off + len > bytes.len() {
                continue;
            }
            let data = &bytes[off..off + len];
            let perm = if sec.flags.contains(SectionFlags::WRITE) {
                Permission::RW
            } else if sec.flags.contains(SectionFlags::EXECUTE) {
                Permission::RX
            } else {
                Permission::RW
            };
            engine
                .memory
                .map_region(sec.virtual_address, sec.virtual_size, perm, &sec.name);
            let _ = engine.memory.write(sec.virtual_address, data);
        }

        Ok(Self {
            config,
            binary: Some(bin),
            engine,
            breakpoints: BreakpointManager::new(),
            file_bytes: bytes,
            running: false,
            last_stop: None,
        })
    }

    /// Create a session from raw bytes (e.g. shellcode analysis).
    pub fn from_bytes(bytes: &[u8], entry: u64, arch: Arch) -> Self {
        let engine = ExecutionEngine::new(bytes, entry, arch);
        Self {
            config: SessionConfig {
                arch,
                entry_point: Some(entry),
                ..Default::default()
            },
            binary: None,
            engine,
            breakpoints: BreakpointManager::new(),
            file_bytes: bytes.to_vec(),
            running: false,
            last_stop: None,
        }
    }

    /// Resolve a symbol name to its virtual address.
    #[must_use]
    pub fn resolve_symbol(&self, name: &str) -> Option<u64> {
        self.binary.as_ref()?.symbols.iter().find_map(|s| {
            if s.name == name {
                Some(s.address)
            } else {
                None
            }
        })
    }

    /// Add a software breakpoint at `address`.
    ///
    /// # Errors
    /// Returns an error if the address is not mapped or already has a bp.
    pub fn add_breakpoint(&mut self, address: u64) -> Result<u32, String> {
        if self.breakpoints.at(address).is_some() {
            return Err(format!("breakpoint already at {address:#x}"));
        }
        let original = self
            .engine
            .memory
            .read_u8(address)
            .map_err(|e| format!("{e}"))?;
        let id = self.breakpoints.add(address, original);
        // Patch memory with INT3 (bypassing permission checks)
        self.engine
            .memory
            .write_raw(address, &[0xCC])
            .map_err(|e| format!("{e}"))?;
        if let Some(bp) = self.breakpoints.get_mut(id) {
            bp.enabled = true;
        }
        Ok(id.0)
    }

    /// Remove a breakpoint by id.
    pub fn remove_breakpoint(&mut self, id: u32) -> Result<(), String> {
        let bid = crate::breakpoint::BreakpointId(id);
        let bp = self
            .breakpoints
            .remove(bid)
            .ok_or_else(|| format!("no breakpoint #{id}"))?;
        // Restore original byte
        self.engine
            .memory
            .write_raw(bp.address, &[bp.original_byte])
            .map_err(|e| format!("{e}"))?;
        Ok(())
    }

    /// Remove breakpoint by address.
    pub fn remove_breakpoint_at(&mut self, address: u64) -> Result<(), String> {
        let bp = self
            .breakpoints
            .remove_at(address)
            .ok_or_else(|| format!("no breakpoint at {address:#x}"))?;
        self.engine
            .memory
            .map_region(bp.address, 1, Permission::RWX, "bp-restore");
        self.engine
            .memory
            .write(bp.address, &[bp.original_byte])
            .map_err(|e| format!("{e}"))?;
        Ok(())
    }

    /// Step one instruction.
    pub fn step(&mut self) -> StepResult {
        self.running = true;
        let result = self.engine.step();
        self.running = false;
        self.last_stop = Some(result.stop_reason.clone());
        if let StopReason::Breakpoint { address } = result.stop_reason {
            self.breakpoints.record_hit(address);
        }
        result
    }

    /// Step over (next) — step one instruction, skip calls.
    pub fn next(&mut self) -> StepResult {
        let rip = self.engine.state.get(omnisec_emu_x86::Register::RIP);

        // Peek at current instruction
        if let Ok(bytes) = self.engine.memory.read(rip, 15) {
            let mut decoder = iced_x86::Decoder::with_ip(
                if self.config.arch == omnisec_core::Arch::X86_64 {
                    64
                } else {
                    32
                },
                &bytes,
                rip,
                iced_x86::DecoderOptions::NONE,
            );
            let mut insn = iced_x86::Instruction::default();
            decoder.decode_out(&mut insn);

            if insn.flow_control() == iced_x86::FlowControl::Call {
                let next_rip = rip + insn.len() as u64;
                self.engine.set_temp_breakpoint(next_rip);
                return self.continue_run();
            }
        }

        // Not a call — just step
        self.step()
    }

    /// Continue execution until stop.
    pub fn continue_run(&mut self) -> StepResult {
        self.running = true;
        let result = self.engine.run(self.config.max_instructions);
        self.running = false;
        self.last_stop = Some(result.stop_reason.clone());
        if let StopReason::Breakpoint { address } = result.stop_reason {
            self.breakpoints.record_hit(address);
        }
        result
    }

    /// Read bytes from the original file (for disassembly outside mapped regions).
    #[must_use]
    pub fn file_bytes(&self) -> &[u8] {
        &self.file_bytes
    }

    /// Step one instruction with full ML annotation.
    pub fn step_ml(&mut self) -> StepResult {
        self.running = true;
        let result = self.engine.step_ml();
        self.running = false;
        self.last_stop = Some(result.stop_reason.clone());
        if let StopReason::Breakpoint { address } = result.stop_reason {
            self.breakpoints.record_hit(address);
        }
        result
    }

    /// Search memory using the HDC scanner.
    pub fn find_hdc(
        &self,
        address: u64,
        size: usize,
        anchor_name: Option<&str>,
        threshold: f64,
    ) -> Vec<HDCHit> {
        self.engine.find_hdc(address, size, anchor_name, threshold)
    }

    /// Execute auto-exploration using an ML-guided strategy.
    pub fn explore(&mut self, strategy: Strategy, max_steps: u64) -> StepResult {
        self.running = true;
        let result = self.engine.explore(strategy, max_steps);
        self.running = false;
        self.last_stop = Some(result.stop_reason.clone());
        if let StopReason::Breakpoint { address } = result.stop_reason {
            self.breakpoints.record_hit(address);
        }
        result
    }

    /// Save a CPU and ML state checkpoint.
    pub fn save_checkpoint(&mut self, name: &str) -> u32 {
        let state = self.engine.state.clone();
        let ann = self
            .engine
            .trace_db
            .last()
            .map(|e| e.annotation.clone())
            .unwrap_or_default();
        self.engine.trace_db.save_checkpoint(name, state, ann)
    }

    /// Restore the session to a previously saved checkpoint.
    pub fn restore_checkpoint(&mut self, id: u32) -> bool {
        self.engine.restore_checkpoint(id)
    }

    /// Reverse-step one instruction.
    pub fn reverse_step(&mut self) -> Option<StepResult> {
        self.running = true;
        let result = self.engine.reverse_step();
        self.running = false;
        if let Some(ref r) = result {
            self.last_stop = Some(r.stop_reason.clone());
            if let StopReason::Breakpoint { address } = r.stop_reason {
                self.breakpoints.record_hit(address);
            }
        }
        result
    }

    /// Continue execution until the given address is reached.
    pub fn until(&mut self, address: u64, max_instructions: u64) -> StepResult {
        self.running = true;
        let result = self.engine.until(address, max_instructions);
        self.running = false;
        self.last_stop = Some(result.stop_reason.clone());
        if let StopReason::Breakpoint { address } = result.stop_reason {
            self.breakpoints.record_hit(address);
        }
        result
    }
}
