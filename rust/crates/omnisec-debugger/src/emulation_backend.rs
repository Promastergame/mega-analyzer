//! Emulation-based DebugBackend implementation.

use crate::backend::{
    BreakpointId, DebugBackend, DebugEvent, DebugVariable, SourceLocation, StackFrame, ThreadId,
    WatchAccess, WatchpointId, WatchpointType,
};
use crate::breakpoint::BreakpointManager;
use crate::dwarf::DwarfSymbolicator;
use crate::engine::{ExecutionEngine, StopReason};
use crate::hdc_scanner::HDCHit;
use crate::ml_annotator::{MLAnnotation, Strategy};
use crate::trace_db::Checkpoint;
use crate::watchpoint::WatchType;
use omnisec_core::Result;
use std::fmt::Debug;

/// Debug backend that runs x86 code in emulation.
#[derive(Debug)]
pub struct EmulationBackend {
    /// Inner execution engine.
    pub engine: ExecutionEngine,
    /// Breakpoint manager.
    pub breakpoints: BreakpointManager,
    /// DWARF symbolicator.
    pub symbolicator: Option<DwarfSymbolicator>,
}

impl EmulationBackend {
    /// Create a new emulation backend wrapping the execution engine.
    pub fn new(engine: ExecutionEngine, symbolicator: Option<DwarfSymbolicator>) -> Self {
        Self {
            engine,
            breakpoints: BreakpointManager::new(),
            symbolicator,
        }
    }
}

impl DebugBackend for EmulationBackend {
    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        self.engine
            .memory
            .read(addr, size)
            .map_err(|e| omnisec_core::Error::internal(e.to_string()))
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.engine
            .memory
            .write_raw(addr, data)
            .map_err(|e| omnisec_core::Error::internal(e.to_string()))
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<BreakpointId> {
        if self.breakpoints.at(addr).is_some() {
            return Err(omnisec_core::Error::internal(format!(
                "breakpoint already at {addr:#x}"
            )));
        }
        let original = self
            .engine
            .memory
            .read_u8(addr)
            .map_err(|e| omnisec_core::Error::internal(e.to_string()))?;
        let id = self.breakpoints.add(addr, original);
        // Patch memory with INT3 (0xCC)
        self.engine
            .memory
            .write_raw(addr, &[0xCC])
            .map_err(|e| omnisec_core::Error::internal(e.to_string()))?;
        if let Some(bp) = self.breakpoints.get_mut(id) {
            bp.enabled = true;
        }
        Ok(id.0)
    }

    fn remove_breakpoint(&mut self, id: BreakpointId) -> Result<()> {
        let bid = crate::breakpoint::BreakpointId(id);
        let bp = self
            .breakpoints
            .remove(bid)
            .ok_or_else(|| omnisec_core::Error::internal(format!("no breakpoint #{id}")))?;
        // Restore original byte
        self.engine
            .memory
            .write_raw(bp.address, &[bp.original_byte])
            .map_err(|e| omnisec_core::Error::internal(e.to_string()))?;
        Ok(())
    }

    fn set_watchpoint(
        &mut self,
        addr: u64,
        size: usize,
        access: WatchAccess,
    ) -> Result<WatchpointId> {
        let kind = match access {
            WatchAccess::Read => WatchType::Read,
            WatchAccess::Write => WatchType::Write,
            WatchAccess::Access => WatchType::Access,
        };
        let id = self.engine.watchpoints.add(addr, size as u64, kind);
        Ok(id)
    }

    fn remove_watchpoint(&mut self, id: WatchpointId) -> Result<()> {
        self.engine
            .watchpoints
            .remove(id)
            .ok_or_else(|| omnisec_core::Error::internal(format!("no watchpoint #{id}")))?;
        Ok(())
    }

    fn step(&mut self, _thread_id: ThreadId) -> Result<DebugEvent> {
        let res = self.engine.step();
        let pc = self.engine.state.get(omnisec_emu_x86::Register::RIP);

        match res.stop_reason {
            StopReason::Breakpoint { address } => {
                self.breakpoints.record_hit(address);
                let id = self.breakpoints.at(address).map_or(0, |b| b.id.0);
                Ok(DebugEvent::BreakpointHit { id, pc: address })
            }
            StopReason::TempBreakpoint { address } => {
                Ok(DebugEvent::BreakpointHit { id: 0, pc: address })
            }
            StopReason::Watchpoint { address, .. } => {
                let id = self
                    .engine
                    .watchpoints
                    .check(address, 1, true)
                    .or_else(|| self.engine.watchpoints.check(address, 1, false))
                    .unwrap_or(0);
                Ok(DebugEvent::WatchpointHit {
                    id,
                    addr: address,
                    pc,
                    kind: WatchpointType::Emulator,
                })
            }
            StopReason::MemoryFault { address, reason } => Ok(DebugEvent::ExceptionCaught {
                kind: format!("MemoryFault: {reason}"),
                pc: address,
            }),
            StopReason::InvalidInstruction { address, opcode } => Ok(DebugEvent::ExceptionCaught {
                kind: format!("InvalidInstruction (opcode {opcode:#x})"),
                pc: address,
            }),
            _ => Ok(DebugEvent::Stopped),
        }
    }

    fn continue_exec(&mut self, _thread_id: Option<ThreadId>) -> Result<DebugEvent> {
        // Run with maximum instructions
        let res = self.engine.run(1_000_000);
        let pc = self.engine.state.get(omnisec_emu_x86::Register::RIP);

        match res.stop_reason {
            StopReason::Breakpoint { address } => {
                self.breakpoints.record_hit(address);
                let id = self.breakpoints.at(address).map_or(0, |b| b.id.0);
                Ok(DebugEvent::BreakpointHit { id, pc: address })
            }
            StopReason::TempBreakpoint { address } => {
                Ok(DebugEvent::BreakpointHit { id: 0, pc: address })
            }
            StopReason::Watchpoint { address, .. } => {
                let id = self
                    .engine
                    .watchpoints
                    .check(address, 1, true)
                    .or_else(|| self.engine.watchpoints.check(address, 1, false))
                    .unwrap_or(0);
                Ok(DebugEvent::WatchpointHit {
                    id,
                    addr: address,
                    pc,
                    kind: WatchpointType::Emulator,
                })
            }
            StopReason::MemoryFault { address, reason } => Ok(DebugEvent::ExceptionCaught {
                kind: format!("MemoryFault: {reason}"),
                pc: address,
            }),
            StopReason::InvalidInstruction { address, opcode } => Ok(DebugEvent::ExceptionCaught {
                kind: format!("InvalidInstruction (opcode {opcode:#x})"),
                pc: address,
            }),
            _ => Ok(DebugEvent::Stopped),
        }
    }

    fn backtrace(&self, _thread_id: ThreadId) -> Result<Vec<StackFrame>> {
        let mut frames = Vec::new();
        let rip = self.engine.state.get(omnisec_emu_x86::Register::RIP);

        let (sym, loc) = if let Some(ref sym) = self.symbolicator {
            if let Some((name, file, line)) = sym.resolve(rip) {
                (
                    Some(name),
                    Some(SourceLocation {
                        file,
                        line,
                        column: 0,
                    }),
                )
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        frames.push(StackFrame {
            pc: rip,
            symbol: sym,
            source_location: loc,
        });

        let mut rbp = self.engine.state.get(omnisec_emu_x86::Register::RBP);
        let mut depth = 0;
        while rbp != 0 && depth < 32 {
            if let Ok(saved_rip) = self.engine.memory.read_u64(rbp + 8) {
                let (sym, loc) = if let Some(ref sym) = self.symbolicator {
                    if let Some((name, file, line)) = sym.resolve(saved_rip) {
                        (
                            Some(name),
                            Some(SourceLocation {
                                file,
                                line,
                                column: 0,
                            }),
                        )
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };
                frames.push(StackFrame {
                    pc: saved_rip,
                    symbol: sym,
                    source_location: loc,
                });
            } else {
                break;
            }
            if let Ok(next_rbp) = self.engine.memory.read_u64(rbp) {
                if next_rbp <= rbp {
                    break;
                }
                rbp = next_rbp;
            } else {
                break;
            }
            depth += 1;
        }
        Ok(frames)
    }

    fn local_variables(&self, _thread_id: ThreadId) -> Result<Vec<DebugVariable>> {
        Ok(Vec::new())
    }

    fn read_register(&self, _thread_id: ThreadId, reg: &str) -> Result<u64> {
        let r = match reg.to_lowercase().as_str() {
            "rax" => omnisec_emu_x86::Register::RAX,
            "rbx" => omnisec_emu_x86::Register::RBX,
            "rcx" => omnisec_emu_x86::Register::RCX,
            "rdx" => omnisec_emu_x86::Register::RDX,
            "rsi" => omnisec_emu_x86::Register::RSI,
            "rdi" => omnisec_emu_x86::Register::RDI,
            "rbp" => omnisec_emu_x86::Register::RBP,
            "rsp" => omnisec_emu_x86::Register::RSP,
            "r8" => omnisec_emu_x86::Register::R8,
            "r9" => omnisec_emu_x86::Register::R9,
            "r10" => omnisec_emu_x86::Register::R10,
            "r11" => omnisec_emu_x86::Register::R11,
            "r12" => omnisec_emu_x86::Register::R12,
            "r13" => omnisec_emu_x86::Register::R13,
            "r14" => omnisec_emu_x86::Register::R14,
            "r15" => omnisec_emu_x86::Register::R15,
            "rip" => omnisec_emu_x86::Register::RIP,
            _ => {
                return Err(omnisec_core::Error::internal(format!(
                    "unknown register: {}",
                    reg
                )));
            }
        };
        Ok(self.engine.state.get(r))
    }

    fn write_register(&mut self, _thread_id: ThreadId, reg: &str, val: u64) -> Result<()> {
        let r = match reg.to_lowercase().as_str() {
            "rax" => omnisec_emu_x86::Register::RAX,
            "rbx" => omnisec_emu_x86::Register::RBX,
            "rcx" => omnisec_emu_x86::Register::RCX,
            "rdx" => omnisec_emu_x86::Register::RDX,
            "rsi" => omnisec_emu_x86::Register::RSI,
            "rdi" => omnisec_emu_x86::Register::RDI,
            "rbp" => omnisec_emu_x86::Register::RBP,
            "rsp" => omnisec_emu_x86::Register::RSP,
            "r8" => omnisec_emu_x86::Register::R8,
            "r9" => omnisec_emu_x86::Register::R9,
            "r10" => omnisec_emu_x86::Register::R10,
            "r11" => omnisec_emu_x86::Register::R11,
            "r12" => omnisec_emu_x86::Register::R12,
            "r13" => omnisec_emu_x86::Register::R13,
            "r14" => omnisec_emu_x86::Register::R14,
            "r15" => omnisec_emu_x86::Register::R15,
            "rip" => omnisec_emu_x86::Register::RIP,
            _ => {
                return Err(omnisec_core::Error::internal(format!(
                    "unknown register: {}",
                    reg
                )));
            }
        };
        let engine = &mut self.engine;
        engine.state.set(r, val);
        Ok(())
    }

    fn enable_tracing(&mut self) -> Result<()> {
        self.engine.enable_tracing();
        Ok(())
    }

    fn disable_tracing(&mut self) -> Result<()> {
        self.engine.disable_tracing();
        Ok(())
    }

    fn reverse_step(&mut self) -> Result<Option<DebugEvent>> {
        let res = self.engine.reverse_step();
        if let Some(r) = res {
            let pc = self.engine.state.get(omnisec_emu_x86::Register::RIP);
            let evt = match r.stop_reason {
                StopReason::Breakpoint { address } => {
                    let id = self.breakpoints.at(address).map_or(0, |b| b.id.0);
                    DebugEvent::BreakpointHit { id, pc: address }
                }
                StopReason::Watchpoint { address, .. } => {
                    let id = self
                        .engine
                        .watchpoints
                        .check(address, 1, true)
                        .or_else(|| self.engine.watchpoints.check(address, 1, false))
                        .unwrap_or(0);
                    DebugEvent::WatchpointHit {
                        id,
                        addr: address,
                        pc,
                        kind: WatchpointType::Emulator,
                    }
                }
                StopReason::MemoryFault { address, reason } => DebugEvent::ExceptionCaught {
                    kind: format!("MemoryFault: {reason}"),
                    pc: address,
                },
                StopReason::InvalidInstruction { address, opcode } => DebugEvent::ExceptionCaught {
                    kind: format!("InvalidInstruction (opcode {opcode:#x})"),
                    pc: address,
                },
                _ => DebugEvent::Stopped,
            };
            Ok(Some(evt))
        } else {
            Ok(None)
        }
    }

    fn reverse_continue(&mut self) -> Result<Option<DebugEvent>> {
        let res = self.engine.reverse_continue();
        if let Some(r) = res {
            let pc = self.engine.state.get(omnisec_emu_x86::Register::RIP);
            let evt = match r.stop_reason {
                StopReason::Breakpoint { address } => {
                    let id = self.breakpoints.at(address).map_or(0, |b| b.id.0);
                    DebugEvent::BreakpointHit { id, pc: address }
                }
                StopReason::Watchpoint { address, .. } => {
                    let id = self
                        .engine
                        .watchpoints
                        .check(address, 1, true)
                        .or_else(|| self.engine.watchpoints.check(address, 1, false))
                        .unwrap_or(0);
                    DebugEvent::WatchpointHit {
                        id,
                        addr: address,
                        pc,
                        kind: WatchpointType::Emulator,
                    }
                }
                StopReason::MemoryFault { address, reason } => DebugEvent::ExceptionCaught {
                    kind: format!("MemoryFault: {reason}"),
                    pc: address,
                },
                StopReason::InvalidInstruction { address, opcode } => DebugEvent::ExceptionCaught {
                    kind: format!("InvalidInstruction (opcode {opcode:#x})"),
                    pc: address,
                },
                _ => DebugEvent::Stopped,
            };
            Ok(Some(evt))
        } else {
            Ok(None)
        }
    }

    fn save_checkpoint(&mut self, name: &str) -> Result<u32> {
        let state = self.engine.state.clone();
        let ann = self
            .engine
            .trace_db
            .last()
            .map(|e| e.annotation.clone())
            .unwrap_or_default();
        Ok(self.engine.trace_db.save_checkpoint(name, state, ann))
    }

    fn restore_checkpoint(&mut self, id: u32) -> Result<bool> {
        Ok(self.engine.restore_checkpoint(id))
    }

    fn get_checkpoints(&self) -> Result<Vec<Checkpoint>> {
        Ok(self.engine.trace_db.iter_checkpoints().cloned().collect())
    }

    fn trace_db_len(&self) -> usize {
        self.engine.trace_db.len()
    }

    fn step_ml(&mut self, _thread_id: ThreadId) -> Result<(DebugEvent, MLAnnotation)> {
        let r = self.engine.step_ml();
        let pc = self.engine.state.get(omnisec_emu_x86::Register::RIP);
        let evt = match r.stop_reason {
            StopReason::Breakpoint { address } => {
                let id = self.breakpoints.at(address).map_or(0, |b| b.id.0);
                DebugEvent::BreakpointHit { id, pc: address }
            }
            StopReason::Watchpoint { address, .. } => {
                let id = self
                    .engine
                    .watchpoints
                    .check(address, 1, true)
                    .or_else(|| self.engine.watchpoints.check(address, 1, false))
                    .unwrap_or(0);
                DebugEvent::WatchpointHit {
                    id,
                    addr: address,
                    pc,
                    kind: WatchpointType::Emulator,
                }
            }
            StopReason::MemoryFault { address, reason } => DebugEvent::ExceptionCaught {
                kind: format!("MemoryFault: {reason}"),
                pc: address,
            },
            StopReason::InvalidInstruction { address, opcode } => DebugEvent::ExceptionCaught {
                kind: format!("InvalidInstruction (opcode {opcode:#x})"),
                pc: address,
            },
            _ => DebugEvent::Stopped,
        };
        Ok((evt, r.annotation))
    }

    fn explore(
        &mut self,
        strategy: Strategy,
        max_steps: u64,
    ) -> Result<(DebugEvent, MLAnnotation)> {
        let r = self.engine.explore(strategy, max_steps);
        let pc = self.engine.state.get(omnisec_emu_x86::Register::RIP);
        let evt = match r.stop_reason {
            StopReason::Breakpoint { address } => {
                let id = self.breakpoints.at(address).map_or(0, |b| b.id.0);
                DebugEvent::BreakpointHit { id, pc: address }
            }
            StopReason::Watchpoint { address, .. } => {
                let id = self
                    .engine
                    .watchpoints
                    .check(address, 1, true)
                    .or_else(|| self.engine.watchpoints.check(address, 1, false))
                    .unwrap_or(0);
                DebugEvent::WatchpointHit {
                    id,
                    addr: address,
                    pc,
                    kind: WatchpointType::Emulator,
                }
            }
            StopReason::MemoryFault { address, reason } => DebugEvent::ExceptionCaught {
                kind: format!("MemoryFault: {reason}"),
                pc: address,
            },
            StopReason::InvalidInstruction { address, opcode } => DebugEvent::ExceptionCaught {
                kind: format!("InvalidInstruction (opcode {opcode:#x})"),
                pc: address,
            },
            _ => DebugEvent::Stopped,
        };
        Ok((evt, r.annotation))
    }

    fn find_hdc(
        &self,
        address: u64,
        size: usize,
        anchor_name: Option<&str>,
        threshold: f64,
    ) -> Result<Vec<HDCHit>> {
        Ok(self.engine.find_hdc(address, size, anchor_name, threshold))
    }
}
