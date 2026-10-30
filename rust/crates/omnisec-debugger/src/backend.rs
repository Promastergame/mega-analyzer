use omnisec_core::Result;
use std::fmt::Debug;

use crate::hdc_scanner::HDCHit;
use crate::ml_annotator::{MLAnnotation, Strategy};
use crate::trace_db::Checkpoint;

/// Unique thread identifier.
pub type ThreadId = u64;
/// Unique breakpoint identifier.
pub type BreakpointId = u32;
/// Unique watchpoint identifier.
pub type WatchpointId = u32;

/// Watchpoint access condition type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchAccess {
    /// Break on memory read access.
    Read,
    /// Break on memory write access.
    Write,
    /// Break on memory read or write access.
    Access,
}

/// Watchpoint engine implementation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchpointType {
    /// CPU hardware debug registers (DR0-DR3).
    Hardware,
    /// Programmatic emulator memory hooks.
    Software,
    /// Hardware page-guard emulation.
    Emulator,
}

/// A debug event triggered by single-stepping or execution continuation.
#[derive(Debug, Clone)]
pub enum DebugEvent {
    /// General execution stop without specific reason.
    Stopped,
    /// Breakpoint triggered.
    BreakpointHit {
        /// Breakpoint ID.
        id: BreakpointId,
        /// Instruction pointer (PC) when stopped.
        pc: u64,
    },
    /// Watchpoint triggered.
    WatchpointHit {
        /// Watchpoint ID.
        id: WatchpointId,
        /// Accessed memory address.
        addr: u64,
        /// Instruction pointer (PC) when stopped.
        pc: u64,
        /// Dynamic type of watchpoint engine.
        kind: WatchpointType,
    },
    /// OS-level or hardware exception caught.
    ExceptionCaught {
        /// Description of the exception (e.g. "STATUS_ACCESS_VIOLATION").
        kind: String,
        /// Instruction pointer (PC) when stopped.
        pc: u64,
    },
    /// Thread created.
    ThreadCreated(ThreadId),
    /// Thread exited.
    ThreadExit(ThreadId),
}

/// A parsed stack frame in a backtrace.
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Program counter / RIP.
    pub pc: u64,
    /// Associated symbol name.
    pub symbol: Option<String>,
    /// Associated source location mapping.
    pub source_location: Option<SourceLocation>,
}

/// Source code location details.
#[derive(Debug, Clone)]
pub struct SourceLocation {
    /// Path to file.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Column number.
    pub column: u32,
}

/// Inspected debug variable description.
#[derive(Debug, Clone)]
pub struct DebugVariable {
    /// Variable name.
    pub name: String,
    /// Variable type.
    pub type_name: String,
    /// Hexadecimal string value description.
    pub value_hex: String,
}

/// Trait defining core debugger operations, abstracted from emulation or live target state.
pub trait DebugBackend: Send + Debug {
    /// Read raw memory block of target size.
    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>>;
    /// Write raw byte block to target memory.
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()>;

    /// Set breakpoint at target address.
    fn set_breakpoint(&mut self, addr: u64) -> Result<BreakpointId>;
    /// Remove breakpoint by ID.
    fn remove_breakpoint(&mut self, id: BreakpointId) -> Result<()>;

    /// Set a memory watchpoint with fallback capability.
    fn set_watchpoint(
        &mut self,
        addr: u64,
        size: usize,
        access: WatchAccess,
    ) -> Result<WatchpointId>;
    /// Remove watchpoint by ID.
    fn remove_watchpoint(&mut self, id: WatchpointId) -> Result<()>;

    /// Single step one instruction on a thread.
    fn step(&mut self, thread_id: ThreadId) -> Result<DebugEvent>;
    /// Continue execution under specified thread-stepping policy.
    fn continue_exec(&mut self, thread_id: Option<ThreadId>) -> Result<DebugEvent>;

    /// Reconstruct stack frame list for thread.
    fn backtrace(&self, thread_id: ThreadId) -> Result<Vec<StackFrame>>;
    /// Query local variable list for thread.
    fn local_variables(&self, thread_id: ThreadId) -> Result<Vec<DebugVariable>>;

    /// Read a register value by name.
    fn read_register(&self, thread_id: ThreadId, reg: &str) -> Result<u64>;
    /// Write a register value by name.
    fn write_register(&mut self, thread_id: ThreadId, reg: &str, val: u64) -> Result<()>;

    /// Enable tracing (for time-travel debugging).
    fn enable_tracing(&mut self) -> Result<()> {
        Ok(())
    }
    /// Disable tracing (for time-travel debugging).
    fn disable_tracing(&mut self) -> Result<()> {
        Ok(())
    }
    /// Reverse step one instruction.
    fn reverse_step(&mut self) -> Result<Option<DebugEvent>> {
        Ok(None)
    }
    /// Reverse continue execution.
    fn reverse_continue(&mut self) -> Result<Option<DebugEvent>> {
        Ok(None)
    }
    /// Save a checkpoint.
    fn save_checkpoint(&mut self, _name: &str) -> Result<u32> {
        Err(omnisec_core::Error::internal(
            "Tracing/checkpointing unsupported on this backend",
        ))
    }
    /// Restore a checkpoint by ID.
    fn restore_checkpoint(&mut self, _id: u32) -> Result<bool> {
        Ok(false)
    }
    /// Retrieve all saved checkpoints.
    fn get_checkpoints(&self) -> Result<Vec<Checkpoint>> {
        Ok(Vec::new())
    }
    /// Get underlying trace database size (number of steps recorded).
    fn trace_db_len(&self) -> usize {
        0
    }

    /// Single step with ML annotation.
    fn step_ml(&mut self, _thread_id: ThreadId) -> Result<(DebugEvent, MLAnnotation)> {
        Err(omnisec_core::Error::internal(
            "ML analysis unsupported on this backend",
        ))
    }
    /// Explore memory space using guided ML strategy.
    fn explore(
        &mut self,
        _strategy: Strategy,
        _max_steps: u64,
    ) -> Result<(DebugEvent, MLAnnotation)> {
        Err(omnisec_core::Error::internal(
            "ML analysis unsupported on this backend",
        ))
    }
    /// Search memory regions for anchors using the HDC scanner.
    fn find_hdc(
        &self,
        _address: u64,
        _size: usize,
        _anchor_name: Option<&str>,
        _threshold: f64,
    ) -> Result<Vec<HDCHit>> {
        Ok(Vec::new())
    }
}
