//! GDB-like command parser.
//!
//! Commands follow the familiar GDB syntax where possible:
//!
//! ```text
//! run / r                         start execution
//! step / stepi / si               step one instruction
//! next / nexti / ni               step over (skip calls)
//! continue / c                    resume execution
//! break / b <addr>                set software breakpoint
//! delete / d <n>                  delete breakpoint
//! info breakpoints / i b        list breakpoints
//! info registers / i r          show registers
//! disassemble / disas <addr>    disassemble at address
//! examine / x <addr>            examine memory
//! backtrace / bt                show call stack
//! quit / q                      exit debugger
//! help / h                      show help
//! ```

use crate::ml_annotator::Strategy;
use crate::watchpoint::WatchType;

/// Parsed debugger command.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Start or restart execution.
    Run,
    /// Step one instruction.
    Step,
    /// Step one instruction with full ML annotation.
    StepMl,
    /// Step over (next instruction, skip calls).
    Next,
    /// Continue execution.
    Continue,
    /// Set a breakpoint at address or by symbol name.
    Break {
        /// Target of the breakpoint (address or symbol).
        target: BreakTarget,
    },
    /// Delete breakpoint by number.
    Delete {
        /// The index of the breakpoint to delete.
        number: u32,
    },
    /// Delete breakpoint by address.
    DeleteAt {
        /// The address of the breakpoint to delete.
        address: u64,
    },
    /// List all breakpoints.
    InfoBreakpoints,
    /// Show registers.
    InfoRegisters,
    /// Disassemble at address (None = current PC).
    Disassemble {
        /// Starting address for disassembly, or None for current PC.
        address: Option<u64>,
        /// Number of instructions to disassemble.
        count: usize,
    },
    /// Examine memory.
    Examine {
        /// The starting address to examine.
        address: u64,
        /// The number of units to display.
        count: usize,
        /// The display format (hex, decimal, etc.).
        format: ExamineFormat,
        /// The size of each display unit.
        size: ExamineSize,
    },
    /// Show call stack.
    Backtrace,
    /// Set a watchpoint.
    Watch {
        /// Virtual address to watch.
        address: u64,
        /// Size of the watched region in bytes.
        size: u64,
        /// Type of watch access (Read, Write, Access).
        kind: WatchType,
    },
    /// Delete a watchpoint by id.
    DeleteWatch {
        /// The watchpoint ID.
        id: u32,
    },
    /// List watchpoints.
    InfoWatchpoints,
    /// Show help.
    Help {
        /// The optional topic to get help on.
        topic: Option<String>,
    },
    /// Set a debugger option.
    Set {
        /// The option and its value.
        option: SetOption,
    },
    /// Search memory for a byte pattern or string.
    Find {
        /// The address to start the search from.
        address: u64,
        /// The byte pattern to search for.
        pattern: Vec<u8>,
    },
    /// Search memory with HDC scanner.
    FindHdc {
        /// Starting address for scanning.
        address: u64,
        /// Number of bytes to scan.
        size: usize,
        /// Optional anchor name to look for.
        anchor_name: Option<String>,
        /// Minimum similarity threshold.
        threshold: f64,
    },
    /// Auto-exploration strategy.
    Explore {
        /// The exploration strategy to use.
        strategy: Strategy,
        /// The maximum number of steps to explore.
        max_steps: u64,
    },
    /// Save a full-state checkpoint.
    Checkpoint,
    /// Restore to a saved checkpoint.
    Restore {
        /// The ID of the checkpoint to restore.
        id: u32,
    },
    /// List checkpoints.
    InfoCheckpoints,
    /// Reverse step one instruction.
    ReverseStep,
    /// Reverse step over (reverse-next).
    ReverseNext,
    /// Reverse until return (reverse-finish).
    ReverseFinish,
    /// Continue until address is reached.
    Until {
        /// Destination address.
        address: u64,
    },
    /// Set condition on breakpoint.
    Condition {
        /// The ID of the breakpoint.
        id: u32,
        /// Optional condition expression.
        expr: Option<String>,
    },
    /// Show memory mappings.
    InfoMappings,
    /// Quit debugger.
    Quit,
    /// Empty line (repeat last command, or no-op).
    Empty,
}

/// Target for a breakpoint command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakTarget {
    /// Exact virtual address.
    Address(u64),
    /// Symbol name (e.g. "main", "JNI_OnLoad").
    Symbol(String),
}

/// `set` sub-options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetOption {
    /// `set disassembly-flavor intel|att`
    DisassemblyFlavor(DisassemblyFlavor),
}

/// Disassembly syntax flavor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisassemblyFlavor {
    /// Intel syntax (default).
    #[default]
    Intel,
    /// AT&T syntax.
    Att,
}

/// Memory display format for `x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExamineFormat {
    /// Hexadecimal (default).
    Hex,
    /// Decimal signed.
    Decimal,
    /// Unsigned decimal.
    Unsigned,
    /// Octal.
    Octal,
    /// Binary.
    Binary,
    /// ASCII string.
    String,
    /// Instruction.
    Instruction,
}

/// Memory unit size for `x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExamineSize {
    /// Byte (b).
    Byte,
    /// Halfword — 2 bytes (h).
    Halfword,
    /// Word — 4 bytes (w).
    Word,
    /// Giant — 8 bytes (g).
    Giant,
}

/// Error parsing a command.
#[derive(Debug)]
pub enum CommandError {
    /// Unknown command.
    Unknown(String),
    /// Missing required argument.
    MissingArg(&'static str),
    /// Invalid address / number.
    InvalidNumber(String),
    /// Invalid examine format string.
    InvalidExamineFormat(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(cmd) => write!(f, "unknown command: {cmd}"),
            Self::MissingArg(arg) => write!(f, "missing argument for {arg}"),
            Self::InvalidNumber(arg) => write!(f, "invalid number: {arg}"),
            Self::InvalidExamineFormat(arg) => write!(f, "invalid examine format: {arg}"),
        }
    }
}

impl std::error::Error for CommandError {}

/// Parse a user input line into a [`Command`].
///
/// # Errors
/// Returns [`CommandError`] if the input is not a valid command.
pub fn parse_command(line: &str) -> Result<Command, CommandError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(Command::Empty);
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    let cmd = parts[0].to_lowercase();

    match cmd.as_str() {
        // Short aliases first
        "r" | "run" => Ok(Command::Run),
        "si" | "stepi" | "s" | "step" => Ok(Command::Step),
        "stepml" | "step-ml" | "step_ml" | "sml" => Ok(Command::StepMl),
        "ni" | "nexti" | "n" | "next" => Ok(Command::Next),
        "c" | "continue" | "cont" => Ok(Command::Continue),

        "b" | "break" | "breakpoint" => {
            let arg = parts.get(1).ok_or(CommandError::MissingArg("break"))?;
            let target = if arg.starts_with("0x")
                || arg.starts_with("0X")
                || arg.chars().all(|c| c.is_ascii_digit())
            {
                BreakTarget::Address(parse_addr(arg)?)
            } else {
                BreakTarget::Symbol(arg.to_string())
            };
            Ok(Command::Break { target })
        }

        "d" | "del" | "delete" => {
            let arg = parts.get(1).ok_or(CommandError::MissingArg("delete"))?;
            // Could be a number or an address
            if arg.starts_with("0x") || arg.starts_with("0X") {
                let addr = parse_addr(arg)?;
                Ok(Command::DeleteAt { address: addr })
            } else {
                let num = arg
                    .parse::<u32>()
                    .map_err(|_| CommandError::InvalidNumber(arg.to_string()))?;
                Ok(Command::Delete { number: num })
            }
        }

        "rsi" | "reverse-stepi" | "reverse-step" | "rs" => Ok(Command::ReverseStep),
        "rni" | "reverse-nexti" | "reverse-next" | "rn" => Ok(Command::ReverseNext),
        "rfi" | "reverse-finish" | "rf" => Ok(Command::ReverseFinish),

        "find" => {
            let addr_str = parts.get(1).ok_or(CommandError::MissingArg("find"))?;
            let addr = parse_addr(addr_str)?;
            let pattern_str = parts
                .get(2)
                .ok_or(CommandError::MissingArg("find pattern"))?;
            let pattern = if let Some(hex_part) = pattern_str.strip_prefix("0x") {
                // Hex byte sequence: 0xdeadbeef
                decode_hex(hex_part)
                    .map_err(|()| CommandError::InvalidNumber(pattern_str.to_string()))?
            } else if pattern_str.starts_with('\'') && pattern_str.ends_with('\'') {
                // Quoted string: 'hello'
                pattern_str.as_bytes()[1..pattern_str.len() - 1].to_vec()
            } else {
                // Raw string
                pattern_str.as_bytes().to_vec()
            };
            Ok(Command::Find {
                address: addr,
                pattern,
            })
        }

        "findhdc" | "find-hdc" | "find_hdc" | "fhdc" => {
            let addr_str = parts.get(1).ok_or(CommandError::MissingArg("findhdc"))?;
            let address = parse_addr(addr_str)?;
            let size_str = parts
                .get(2)
                .ok_or(CommandError::MissingArg("findhdc size"))?;
            let size = if size_str.starts_with("0x") || size_str.starts_with("0X") {
                usize::from_str_radix(&size_str[2..], 16)
                    .map_err(|_| CommandError::InvalidNumber(size_str.to_string()))?
            } else {
                size_str
                    .parse::<usize>()
                    .map_err(|_| CommandError::InvalidNumber(size_str.to_string()))?
            };
            let mut anchor_name = None;
            let mut threshold = 0.7;
            if let Some(arg3) = parts.get(3) {
                if let Ok(val) = arg3.parse::<f64>() {
                    threshold = val;
                } else {
                    anchor_name = Some(arg3.to_string());
                    if let Some(arg4) = parts.get(4)
                        && let Ok(val) = arg4.parse::<f64>()
                    {
                        threshold = val;
                    }
                }
            }
            Ok(Command::FindHdc {
                address,
                size,
                anchor_name,
                threshold,
            })
        }

        "explore" | "exp" => {
            let strat_str = parts.get(1).map(|s| s.to_lowercase());
            let mut next_idx = 2;
            let strategy = match strat_str.as_deref() {
                Some("step") => Strategy::Step,
                Some("branch" | "explorebranch" | "explore-branch") => {
                    let target_str = parts
                        .get(2)
                        .ok_or(CommandError::MissingArg("explore branch target"))?;
                    let target = parse_addr(target_str)?;
                    next_idx = 3;
                    Strategy::ExploreBranch { target }
                }
                Some("loop" | "fastforwardloop" | "fast-forward-loop") => Strategy::FastForwardLoop,
                Some("dump" | "dumpandscan" | "dump-and-scan") => Strategy::DumpAndScan,
                Some("checkpoint") => Strategy::Checkpoint,
                Some("stop") => Strategy::Stop,
                _ => Strategy::Step,
            };
            let max_steps = if let Some(steps_str) = parts.get(next_idx) {
                steps_str.parse::<u64>().unwrap_or(1000)
            } else {
                1000
            };
            Ok(Command::Explore {
                strategy,
                max_steps,
            })
        }

        "checkpoint" | "save" => Ok(Command::Checkpoint),
        "restore" => {
            let id_str = parts.get(1).ok_or(CommandError::MissingArg("restore"))?;
            let id = id_str
                .parse::<u32>()
                .map_err(|_| CommandError::InvalidNumber(id_str.to_string()))?;
            Ok(Command::Restore { id })
        }

        "until" | "u" => {
            let addr_str = parts.get(1).ok_or(CommandError::MissingArg("until"))?;
            let addr = parse_addr(addr_str)?;
            Ok(Command::Until { address: addr })
        }

        "condition" | "cond" => {
            let id_str = parts.get(1).ok_or(CommandError::MissingArg("condition"))?;
            let id = id_str
                .parse::<u32>()
                .map_err(|_| CommandError::InvalidNumber(id_str.to_string()))?;
            let expr = parts.get(2).map(std::string::ToString::to_string);
            Ok(Command::Condition { id, expr })
        }

        "i" | "info" => {
            let sub = parts.get(1).map(|s| s.to_lowercase());
            match sub.as_deref() {
                Some("b" | "break" | "breakpoints") => Ok(Command::InfoBreakpoints),
                Some("r" | "reg" | "registers") => Ok(Command::InfoRegisters),
                Some("w" | "watch" | "watchpoints") => Ok(Command::InfoWatchpoints),
                Some("checkpoint" | "checkpoints" | "cp") => Ok(Command::InfoCheckpoints),
                Some("m" | "map" | "mappings" | "proc") => Ok(Command::InfoMappings),
                _ => Ok(Command::Help { topic: sub }),
            }
        }

        "disas" | "disasm" | "disassemble" => {
            let (addr, count) = if parts.len() > 1 {
                let addr = parse_addr(parts[1])?;
                let count = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
                (Some(addr), count)
            } else {
                (None, 10)
            };
            Ok(Command::Disassemble {
                address: addr,
                count,
            })
        }

        "x" | "examine" => {
            let arg = parts.get(1).ok_or(CommandError::MissingArg("examine"))?;
            let (fmt, size, count, addr_str) = parse_examine_spec(arg, parts.get(2))?;
            let addr = parse_addr(addr_str)?;
            Ok(Command::Examine {
                address: addr,
                count,
                format: fmt,
                size,
            })
        }

        "bt" | "backtrace" | "where" => Ok(Command::Backtrace),

        "watch" => {
            let addr_str = parts.get(1).ok_or(CommandError::MissingArg("watch"))?;
            let addr = parse_addr(addr_str)?;
            let size = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(8);
            Ok(Command::Watch {
                address: addr,
                size,
                kind: WatchType::Access,
            })
        }
        "rwatch" => {
            let addr_str = parts.get(1).ok_or(CommandError::MissingArg("rwatch"))?;
            let addr = parse_addr(addr_str)?;
            let size = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(8);
            Ok(Command::Watch {
                address: addr,
                size,
                kind: WatchType::Read,
            })
        }
        "wwatch" => {
            let addr_str = parts.get(1).ok_or(CommandError::MissingArg("wwatch"))?;
            let addr = parse_addr(addr_str)?;
            let size = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(8);
            Ok(Command::Watch {
                address: addr,
                size,
                kind: WatchType::Write,
            })
        }

        "set" => {
            let sub = parts.get(1).ok_or(CommandError::MissingArg("set"))?;
            match sub.to_lowercase().as_str() {
                "disassembly-flavor" => {
                    let flavor = parts
                        .get(2)
                        .ok_or(CommandError::MissingArg("set disassembly-flavor"))?;
                    let f = match flavor.to_lowercase().as_str() {
                        "intel" => DisassemblyFlavor::Intel,
                        "att" => DisassemblyFlavor::Att,
                        _ => return Err(CommandError::InvalidNumber(flavor.to_string())),
                    };
                    Ok(Command::Set {
                        option: SetOption::DisassemblyFlavor(f),
                    })
                }
                _ => Err(CommandError::Unknown(format!("set {sub}"))),
            }
        }

        "h" | "help" | "?" => Ok(Command::Help {
            topic: parts.get(1).map(std::string::ToString::to_string),
        }),

        "q" | "quit" | "exit" => Ok(Command::Quit),

        _ => Err(CommandError::Unknown(cmd)),
    }
}

fn parse_addr(s: &str) -> Result<u64, CommandError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|_| CommandError::InvalidNumber(s.to_string()))
    } else {
        s.parse::<u64>()
            .or_else(|_| u64::from_str_radix(s, 16))
            .map_err(|_| CommandError::InvalidNumber(s.to_string()))
    }
}

/// Parse the GDB `x/FMT` specifier.
///
/// Format: `[count][format][size]address`  e.g. `10xg0x401000`, `5i$pc`, `s0x1000`
fn parse_examine_spec<'a>(
    spec: &'a str,
    fallback_addr: Option<&&'a str>,
) -> Result<(ExamineFormat, ExamineSize, usize, &'a str), CommandError> {
    // Simple heuristic: split into leading number/format and trailing address
    let mut chars = spec.chars().peekable();

    // Parse count
    let mut count_str = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            count_str.push(c);
            chars.next();
        } else {
            break;
        }
    }
    let count = if count_str.is_empty() {
        1
    } else {
        count_str
            .parse()
            .map_err(|_| CommandError::InvalidExamineFormat(spec.to_string()))?
    };

    // Parse format
    let format = if let Some(&c) = chars.peek() {
        match c {
            'x' | 'X' => {
                chars.next();
                ExamineFormat::Hex
            }
            'd' | 'D' => {
                chars.next();
                ExamineFormat::Decimal
            }
            'u' | 'U' => {
                chars.next();
                ExamineFormat::Unsigned
            }
            'o' | 'O' => {
                chars.next();
                ExamineFormat::Octal
            }
            't' | 'T' => {
                chars.next();
                ExamineFormat::Binary
            }
            'i' | 'I' => {
                chars.next();
                ExamineFormat::Instruction
            }
            's' | 'S' => {
                chars.next();
                ExamineFormat::String
            }
            _ => ExamineFormat::Hex,
        }
    } else {
        ExamineFormat::Hex
    };

    // Parse size
    let size = if let Some(&c) = chars.peek() {
        match c {
            'b' | 'B' => {
                chars.next();
                ExamineSize::Byte
            }
            'h' | 'H' => {
                chars.next();
                ExamineSize::Halfword
            }
            'w' | 'W' => {
                chars.next();
                ExamineSize::Word
            }
            'g' | 'G' => {
                chars.next();
                ExamineSize::Giant
            }
            _ => ExamineSize::Word,
        }
    } else {
        ExamineSize::Word
    };

    // Remaining is address
    let addr_part: String = chars.collect();
    let addr = if addr_part.is_empty() {
        fallback_addr.copied().unwrap_or("0")
    } else {
        &spec[spec.len() - addr_part.len()..]
    };

    Ok((format, size, count, addr))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
