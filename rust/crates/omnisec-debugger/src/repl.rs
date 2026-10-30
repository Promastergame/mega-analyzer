//! Interactive GDB-like REPL.
//!
//! Reads lines from stdin, parses commands, and dispatches to the session.

use std::io::{self, Write};

use crate::commands::{Command, parse_command};
use crate::engine::StopReason;
use crate::format;
use crate::session::DebuggerSession;
use omnisec_emu_x86::CpuState;

/// Run the interactive debugger REPL.
///
/// Returns `Ok(())` on `quit`, or an error on I/O failure.
pub fn run(session: &mut DebuggerSession) -> io::Result<()> {
    println!("OmniSec Debugger — GDB-like interactive machine-code debugger");
    println!("Type 'help' for a list of commands.\n");

    let stdin = io::stdin();
    let mut last_cmd: Option<Command> = None;
    let _checkpoints: Vec<CpuState> = Vec::new();
    session.engine.enable_tracing();

    loop {
        let prompt = "(omnisec-dbg) ";
        print!("{prompt}");
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            // EOF
            println!();
            break;
        }

        let trimmed = line.trim();

        // Empty line repeats last command (GDB behavior)
        let cmd = if trimmed.is_empty() {
            match last_cmd.clone() {
                Some(c) => c,
                None => continue,
            }
        } else {
            match parse_command(trimmed) {
                Ok(c) => c,
                Err(e) => {
                    println!("Error: {e}");
                    continue;
                }
            }
        };

        last_cmd = Some(cmd.clone());

        match cmd {
            Command::Run => {
                let result = session.continue_run();
                print_stop(&result);
            }
            Command::Step => {
                let result = session.step();
                if let Some(ref insn) = result.instruction {
                    println!(
                        "=> {:#018x}  {:<30}  {insn}",
                        result.address,
                        hex_raw(&result.raw)
                    );
                }
                print_stop(&result);
            }
            Command::StepMl => {
                let result = session.step_ml();
                if let Some(ref insn) = result.instruction {
                    println!(
                        "=> {:#018x}  {:<30}  {insn}",
                        result.address,
                        hex_raw(&result.raw)
                    );
                }
                format::print_ml_annotation(&result.annotation);
                print_stop(&result);
            }
            Command::Next => {
                let result = session.next();
                if let Some(ref insn) = result.instruction {
                    println!(
                        "=> {:#018x}  {:<30}  {insn}",
                        result.address,
                        hex_raw(&result.raw)
                    );
                }
                print_stop(&result);
            }
            Command::Continue => {
                let result = session.continue_run();
                print_stop(&result);
            }
            Command::Break { target } => match target {
                crate::commands::BreakTarget::Address(addr) => match session.add_breakpoint(addr) {
                    Ok(id) => println!("Breakpoint {id} at {addr:#018x}"),
                    Err(e) => println!("Cannot set breakpoint: {e}"),
                },
                crate::commands::BreakTarget::Symbol(name) => match session.resolve_symbol(&name) {
                    Some(addr) => match session.add_breakpoint(addr) {
                        Ok(id) => println!("Breakpoint {id} at {addr:#018x} ({name})"),
                        Err(e) => println!("Cannot set breakpoint: {e}"),
                    },
                    None => println!("No symbol '{name}' found"),
                },
            },
            Command::Delete { number } => match session.remove_breakpoint(number) {
                Ok(()) => println!("Deleted breakpoint #{number}"),
                Err(e) => println!("{e}"),
            },
            Command::DeleteAt { address } => match session.remove_breakpoint_at(address) {
                Ok(()) => println!("Deleted breakpoint at {address:#x}"),
                Err(e) => println!("{e}"),
            },
            Command::InfoBreakpoints => {
                format::print_breakpoints(session);
            }
            Command::InfoRegisters => {
                format::print_registers(&session.engine.state);
            }
            Command::Disassemble { address, count } => {
                let addr = address
                    .unwrap_or_else(|| session.engine.state.get(omnisec_emu_x86::Register::RIP));
                format::print_disassembly(session, addr, count);
            }
            Command::Examine {
                address,
                count,
                format: fmt,
                size,
            } => {
                format::print_examine(session, address, count, fmt, size);
            }
            Command::Backtrace => {
                format::print_backtrace(session);
            }
            Command::Watch {
                address,
                size,
                kind,
            } => {
                let id = session.engine.watchpoints.add(address, size, kind);
                let kind_str = match kind {
                    crate::watchpoint::WatchType::Read => "read",
                    crate::watchpoint::WatchType::Write => "write",
                    crate::watchpoint::WatchType::Access => "access",
                };
                println!("Watchpoint {id}: {kind_str} at {address:#018x} (size={size})");
            }
            Command::DeleteWatch { id } => match session.engine.watchpoints.remove(id) {
                Some(_) => println!("Deleted watchpoint #{id}"),
                None => println!("No watchpoint #{id}"),
            },
            Command::InfoWatchpoints => {
                format::print_watchpoints(session);
            }
            Command::Help { topic } => {
                print_help(topic.as_deref());
            }
            Command::Set { option } => match option {
                crate::commands::SetOption::DisassemblyFlavor(flavor) => {
                    session.config.disassembly_flavor = flavor;
                    let name = match flavor {
                        crate::commands::DisassemblyFlavor::Intel => "intel",
                        crate::commands::DisassemblyFlavor::Att => "att",
                    };
                    println!("Disassembly flavor set to {name}.");
                }
            },
            Command::Find { address, pattern } => {
                let mut found = false;
                for region in session.engine.memory.regions() {
                    if !region.perm.read {
                        continue;
                    }
                    let start = std::cmp::max(region.base, address);
                    let end = region.base + region.size;
                    if start >= end {
                        continue;
                    }
                    let len = (end - start) as usize;
                    if let Ok(bytes) = session.engine.memory.read(start, len) {
                        let mut i = 0;
                        while i + pattern.len() <= bytes.len() {
                            if bytes[i..i + pattern.len()] == pattern[..] {
                                let match_addr = start + i as u64;
                                println!("Pattern found at: {:#018x}", match_addr);
                                found = true;
                            }
                            i += 1;
                        }
                    }
                }
                if !found {
                    println!("Pattern not found");
                }
            }
            Command::FindHdc {
                address,
                size,
                anchor_name,
                threshold,
            } => {
                let hits = session.find_hdc(address, size, anchor_name.as_deref(), threshold);
                format::print_hdc_hits(&hits);
            }
            Command::Explore {
                strategy,
                max_steps,
            } => {
                println!(
                    "Starting auto-exploration with strategy {:?} (max_steps={})...",
                    strategy, max_steps
                );
                let result = session.explore(strategy, max_steps);
                if let Some(ref insn) = result.instruction {
                    println!(
                        "=> {:#018x}  {:<30}  {insn}",
                        result.address,
                        hex_raw(&result.raw)
                    );
                }
                format::print_ml_annotation(&result.annotation);
                print_stop(&result);
            }
            Command::Checkpoint => {
                let rip = session.engine.state.get(omnisec_emu_x86::Register::RIP);
                let id =
                    session.save_checkpoint(&format!("manual_{}", session.engine.trace_db.len()));
                println!("Checkpoint #{} saved at RIP = {:#018x}", id, rip);
            }
            Command::Restore { id } => {
                if session.restore_checkpoint(id) {
                    println!("Restored checkpoint #{}", id);
                } else {
                    println!("No checkpoint #{}", id);
                }
            }
            Command::InfoCheckpoints => {
                let cps: Vec<_> = session.engine.trace_db.iter_checkpoints().collect();
                if cps.is_empty() {
                    println!("No checkpoints saved.");
                } else {
                    println!("Saved checkpoints:");
                    for cp in cps {
                        format::print_checkpoint(cp);
                    }
                }
            }
            Command::ReverseStep => match session.reverse_step() {
                Some(result) => {
                    if let Some(ref insn) = result.instruction {
                        println!(
                            "=> {:#018x}  {:<30}  {insn}",
                            result.address,
                            hex_raw(&result.raw)
                        );
                    }
                    print_stop(&result);
                }
                None => {
                    println!("No reverse-step history available.");
                }
            },
            Command::ReverseNext => {
                println!(
                    "Warning: reverse-next is not implemented. Use 'rs' to reverse-step one instruction."
                );
            }
            Command::ReverseFinish => {
                println!(
                    "Warning: reverse-finish is not implemented. Use 'rs' to reverse-step one instruction."
                );
            }
            Command::Until { address } => {
                let result = session.until(address, 1_000_000);
                if let Some(ref insn) = result.instruction {
                    println!(
                        "=> {:#018x}  {:<30}  {insn}",
                        result.address,
                        hex_raw(&result.raw)
                    );
                }
                print_stop(&result);
            }
            Command::Condition { id, expr: _expr } => {
                println!(
                    "Warning: breakpoint condition is not supported in this version. Breakpoint #{id} condition ignored."
                );
            }
            Command::InfoMappings => {
                println!("Mapped memory regions:");
                println!(
                    "  {:^18}  {:^18}  {:^8}  {:^6}  Label",
                    "Start Address", "End Address", "Size", "Perms"
                );
                println!(
                    "  {:─<18}  {:─<18}  {:─<8}  {:─<6}  {:─<20}",
                    "", "", "", "", ""
                );
                for region in session.engine.memory.regions() {
                    let end = region.base + region.size;
                    let r = if region.perm.read { "r" } else { "-" };
                    let w = if region.perm.write { "w" } else { "-" };
                    let x = if region.perm.execute { "x" } else { "-" };
                    println!(
                        "  {:#018x}  {:#018x}  {:<8}  {}{}{}    {}",
                        region.base,
                        end,
                        format!("{:#x}", region.size),
                        r,
                        w,
                        x,
                        region.label
                    );
                }
            }
            Command::Quit => {
                println!("Quitting debugger.");
                break;
            }
            Command::Empty => {}
        }
    }

    Ok(())
}

fn print_stop(result: &crate::engine::StepResult) {
    match &result.stop_reason {
        StopReason::Breakpoint { address } => {
            println!("\nBreakpoint hit at {address:#018x}.");
        }
        StopReason::TempBreakpoint { address } => {
            println!("\nTemporary breakpoint hit at {address:#018x}.");
        }
        StopReason::MaxInstructions => {
            println!("\nStopped: reached max instruction limit.");
        }
        StopReason::InvalidInstruction { address, opcode } => {
            println!("\nStopped: invalid instruction {opcode:#04x} at {address:#018x}.");
        }
        StopReason::MemoryFault { address, reason } => {
            println!("\nStopped: memory fault at {address:#018x}: {reason}");
        }
        StopReason::Completed => {
            println!("\nProgram completed normally.");
        }
        StopReason::Watchpoint { address, access } => {
            println!("\nWatchpoint triggered: {access} at {address:#018x}.");
        }
    }
}

fn hex_raw(raw: &[u8]) -> String {
    raw.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_help(topic: Option<&str>) {
    match topic {
        Some("break" | "breakpoint") => {
            println!("break <address>       -- set software breakpoint at address");
            println!("break <symbol_name>   -- set breakpoint on symbol (e.g. 'b main')");
            println!("delete <n>            -- delete breakpoint by number");
            println!("info breakpoints      -- list all breakpoints");
        }
        Some("step" | "next") => {
            println!("step / si        -- step one instruction (into calls)");
            println!("next / ni        -- step one instruction (over calls)");
            println!("continue / c     -- resume execution");
            println!("run / r          -- start/restart execution");
        }
        Some("examine" | "x") => {
            println!("x/FMT ADDRESS    -- examine memory");
            println!("  Format: [count][format][size]");
            println!(
                "  Formats: x=hex, d=decimal, u=unsigned, o=octal, t=binary, i=instruction, s=string"
            );
            println!("  Sizes:  b=byte, h=2b, w=4b, g=8b");
            println!("  Example: x/10xg 0x401000   (10 giant words in hex)");
            println!("           x/5i $pc          (5 instructions from PC)");
        }
        _ => {
            println!("OmniSec Debugger commands:");
            println!("  run / r                      start execution");
            println!("  step / stepi / si            step one instruction (into)");
            println!("  stepml / sml                 step one instruction with ML annotation");
            println!("  next / nexti / ni            step one instruction (over)");
            println!("  continue / c                 continue execution");
            println!("  break / b <addr|symbol>      set breakpoint");
            println!("  watch / rwatch / wwatch      set watchpoint (access/read/write)");
            println!("  delete / d <n>               delete breakpoint");
            println!(
                "  findhdc / fhdc <addr> <size> [anchor] [thresh] -- search memory with HDC scanner"
            );
            println!(
                "  explore / exp <strategy> [steps] -- run with ML-guided strategy (step, branch, loop, dump, checkpoint, stop)"
            );
            println!("  checkpoint / save            save CPU and ML state checkpoint");
            println!("  restore <id>                 restore to checkpoint ID");
            println!("  info checkpoints / i cp      list checkpoints");
            println!("  info breakpoints / i b       list breakpoints");
            println!("  info watchpoints             list watchpoints");
            println!("  info registers / i r         show registers");
            println!("  disassemble / disas <a>      disassemble at address");
            println!("  examine / x <addr>           examine memory");
            println!("  backtrace / bt               show call stack");
            println!("  set disassembly-flavor <f>   intel or att");
            println!("  help / h [topic]             show help");
            println!("  quit / q                     exit debugger");
        }
    }
}
