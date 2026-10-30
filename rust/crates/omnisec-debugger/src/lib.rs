//! OmniSec Debugger — GDB-like interactive machine-code debugger.
//!
//! Built on top of:
//! - `omnisec-emu-x86` for virtual memory
//! - `omnisec-disasm` / `iced-x86` for decoding
//! - `omnisec-loader` for ELF/PE loading
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │   REPL / CLI    │
//! └────────┬────────┘
//!          │ commands
//! ┌────────▼────────┐
//! │ DebuggerSession │─── breakpoints, call stack, symbols
//! └────────┬────────┘
//!          │ execute_one / run_until
//! ┌────────▼────────┐
//! │  ExecutionEngine│─── iced-x86 decode + emulate
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │  VirtualMemory  │─── sparse page-backed address space
//! └─────────────────┘
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// Debugger backend abstraction.
pub mod backend;
pub mod breakpoint;
pub mod commands;
pub mod dwarf;
pub mod emulation_backend;
pub mod engine;
pub mod format;
pub mod hdc_scanner;
pub mod ml_annotator;
pub mod repl;
pub mod session;
pub mod trace_db;
pub mod watchpoint;

pub use backend::{
    BreakpointId, DebugBackend, DebugEvent, DebugVariable, SourceLocation, StackFrame, ThreadId,
    WatchAccess, WatchpointId, WatchpointType,
};
pub use breakpoint::{Breakpoint, BreakpointManager};
pub use commands::{BreakTarget, Command, CommandError, DisassemblyFlavor, parse_command};
pub use dwarf::DwarfSymbolicator;
pub use emulation_backend::EmulationBackend;
pub use engine::{ExecutionEngine, StepResult, StopReason};
pub use session::{DebuggerSession, SessionConfig};
pub use watchpoint::{WatchType, Watchpoint, WatchpointManager};

// ML / HDC / Trace exports
pub use hdc_scanner::{HDCHit, HDCScanner};
pub use ml_annotator::{MLAnnotation, MLAnnotator, Strategy, StrategyEngine, SuggestedAction};
pub use trace_db::{Checkpoint, TraceDB, TraceEntry, TraceStats};

// Re-export register type from emulator so downstream crates don't need
// to depend on omnisec-emu-x86 directly.
pub use omnisec_emu_x86::Register;
