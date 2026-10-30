//! Pretty-printing helpers for the debugger CLI output.

use iced_x86::{Decoder, DecoderOptions, GasFormatter, Instruction as IcedInsn, IntelFormatter};
use omnisec_emu_x86::{CpuState, Register};

use crate::commands::{DisassemblyFlavor, ExamineFormat, ExamineSize};
use crate::hdc_scanner::HDCHit;
use crate::ml_annotator::MLAnnotation;
use crate::session::DebuggerSession;
use crate::trace_db::{Checkpoint, TraceStats};

/// Print registers in a GDB-like two-column layout.
pub fn print_registers(state: &CpuState) {
    println!("{:─<60}", "");
    println!(
        "  {:^8} {:>18} {:>18}   {:^8} {:>18} {:>18}",
        "Reg", "Hex", "Decimal", "Reg", "Hex", "Decimal"
    );
    println!("{:─<60}", "");

    let regs = [
        (Register::RAX, "rax"),
        (Register::RBX, "rbx"),
        (Register::RCX, "rcx"),
        (Register::RDX, "rdx"),
        (Register::RSI, "rsi"),
        (Register::RDI, "rdi"),
        (Register::RBP, "rbp"),
        (Register::RSP, "rsp"),
        (Register::R8, "r8"),
        (Register::R9, "r9"),
        (Register::R10, "r10"),
        (Register::R11, "r11"),
        (Register::R12, "r12"),
        (Register::R13, "r13"),
        (Register::R14, "r14"),
        (Register::R15, "r15"),
        (Register::RIP, "rip"),
    ];

    for chunk in regs.chunks(2) {
        let left = &chunk[0];
        let lval = state.get(left.0);
        let right = chunk.get(1);

        if let Some(r) = right {
            let rval = state.get(r.0);
            println!(
                "  {:>3} = {:#018x} {:>20}   {:>3} = {:#018x} {:>20}",
                left.1,
                lval,
                fmt_signed(lval),
                r.1,
                rval,
                fmt_signed(rval),
            );
        } else {
            println!("  {:>3} = {:#018x} {}", left.1, lval, fmt_signed(lval));
        }
    }

    println!(
        "  eflags = [ {} {} {} {} ]",
        if state.flags.zf { "ZF" } else { "  " },
        if state.flags.sf { "SF" } else { "  " },
        if state.flags.cf { "CF" } else { "  " },
        if state.flags.of { "OF" } else { "  " },
    );
    println!("{:─<60}", "");
}

fn fmt_signed(v: u64) -> String {
    let signed = v as i64;
    format!("{signed}")
}

/// Disassemble `count` instructions at `address` using iced-x86.
pub fn print_disassembly(session: &DebuggerSession, address: u64, count: usize) {
    let is_64bit = session.config.arch == omnisec_core::Arch::X86_64;
    let bitness = if is_64bit { 64 } else { 32 };

    let flavor_name = match session.config.disassembly_flavor {
        DisassemblyFlavor::Intel => "intel",
        DisassemblyFlavor::Att => "att",
    };
    println!("Dump of assembler code for {address:#x} (flavor: {flavor_name}):");
    println!("{:─<50}", "");

    let mut formatter: Box<dyn iced_x86::Formatter> = match session.config.disassembly_flavor {
        DisassemblyFlavor::Intel => Box::new(IntelFormatter::new()),
        DisassemblyFlavor::Att => Box::new(GasFormatter::new()),
    };
    let mut output = String::new();

    let mut insn = IcedInsn::default();
    let mut addr = address;

    for _ in 0..count {
        // Read bytes from emulator memory for disassembly
        let mem_bytes = session.engine.memory.read(addr, 15);
        let chunk = match mem_bytes {
            Ok(b) => b,
            Err(_) => {
                // Try file offset (rough approximation)
                break;
            }
        };

        let mut local_decoder = Decoder::with_ip(bitness, &chunk, addr, DecoderOptions::NONE);
        local_decoder.decode_out(&mut insn);

        if insn.is_invalid() {
            println!(
                "   {addr:#018x}:\t{:02x}\t.byte 0x{:02x}",
                chunk[0], chunk[0]
            );
            addr += 1;
            continue;
        }

        let arrow = if addr == session.engine.state.get(Register::RIP) {
            "=>"
        } else {
            "  "
        };

        output.clear();
        formatter.format(&insn, &mut output);

        let raw: Vec<u8> = chunk[..insn.len()].to_vec();
        let raw_str = raw
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");

        println!("{} {:#018x}:  {:<24} {}", arrow, addr, raw_str, output);

        addr += insn.len() as u64;
    }

    println!("{:─<50}", "");
}

/// Print memory examination.
pub fn print_examine(
    session: &DebuggerSession,
    address: u64,
    count: usize,
    fmt: ExamineFormat,
    size: ExamineSize,
) {
    let unit = match size {
        ExamineSize::Byte => 1usize,
        ExamineSize::Halfword => 2,
        ExamineSize::Word => 4,
        ExamineSize::Giant => 8,
    };

    if fmt == ExamineFormat::Instruction {
        print_disassembly(session, address, count);
        return;
    }

    if fmt == ExamineFormat::String {
        match session.engine.memory.read_string(address) {
            Ok(s) => println!("{address:#018x}: \"{s}\""),
            Err(e) => println!("cannot read string at {address:#x}: {e}"),
        }
        return;
    }

    let bytes_per_row = 16usize;
    let total_bytes = count * unit;

    for row_start in (0..total_bytes).step_by(bytes_per_row) {
        let row_addr = address + row_start as u64;
        let row_len = bytes_per_row.min(total_bytes - row_start);

        let data = match session.engine.memory.read(row_addr, row_len) {
            Ok(d) => d,
            Err(e) => {
                println!("{row_addr:#018x}: <unmapped: {e}>");
                continue;
            }
        };

        print!("{row_addr:#018x}: ");

        for chunk in data.chunks(unit) {
            let val = match unit {
                1 => chunk[0] as u64,
                2 => u16::from_le_bytes([chunk[0], chunk[1]]) as u64,
                4 => u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64,
                8 => u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]),
                _ => 0,
            };

            match fmt {
                ExamineFormat::Hex => match unit {
                    1 => print!(" {:02x}", val),
                    2 => print!(" {:04x}", val),
                    4 => print!(" {:08x}", val),
                    8 => print!(" {:016x}", val),
                    _ => {}
                },
                ExamineFormat::Decimal => print!(" {:>12}", val as i64),
                ExamineFormat::Unsigned => print!(" {:>12}", val),
                ExamineFormat::Octal => print!(" {:>12o}", val),
                ExamineFormat::Binary => print!(" {:064b}", val),
                _ => {}
            }
        }

        // ASCII dump
        print!("  |");
        for &b in &data {
            let c = if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            };
            print!("{c}");
        }
        println!("|");
    }
}

/// Print breakpoint list.
pub fn print_breakpoints(session: &DebuggerSession) {
    if session.breakpoints.is_empty() {
        println!("No breakpoints.");
        return;
    }
    println!("Num\tType\t\tDisp\tEnb\tAddress\t\tWhat");
    for bp in session.breakpoints.iter() {
        println!(
            "{}\tbreakpoint\tkeep\t{}\t{:#018x}",
            bp.id.0,
            if bp.enabled { "y" } else { "n" },
            bp.address,
        );
    }
}

/// Print watchpoint list.
pub fn print_watchpoints(session: &DebuggerSession) {
    if session.engine.watchpoints.is_empty() {
        println!("No watchpoints.");
        return;
    }
    println!("Num\tType\t\tDisp\tEnb\tAddress\t\tWhat");
    for wp in session.engine.watchpoints.iter() {
        let kind = match wp.kind {
            crate::watchpoint::WatchType::Read => "rwatch",
            crate::watchpoint::WatchType::Write => "watch",
            crate::watchpoint::WatchType::Access => "awatch",
        };
        println!(
            "{}\t{}\t\tkeep\ty\t{:#018x}\t(size={})",
            wp.id, kind, wp.address, wp.size,
        );
    }
}

/// Print call stack.
pub fn print_backtrace(session: &DebuggerSession) {
    let rip = session.engine.state.get(Register::RIP);
    let rbp = session.engine.state.get(Register::RBP);

    println!("#0  {:#018x} in ???", rip);

    // Simple frame walk using RBP chain
    let mut frame = 0;
    let mut fp = rbp;
    while frame < 64 {
        let next_fp = match session.engine.memory.read_u64(fp) {
            Ok(v) => v,
            Err(_) => break,
        };
        let ret_addr = match session.engine.memory.read_u64(fp + 8) {
            Ok(v) => v,
            Err(_) => break,
        };
        if next_fp == 0 || ret_addr == 0 {
            break;
        }
        frame += 1;
        println!("#{frame}  {ret_addr:#018x} in ???");
        if next_fp <= fp {
            break; // Prevent infinite loop on corrupted stack
        }
        fp = next_fp;
    }
}

/// Print an ML annotation in a concise box.
pub fn print_ml_annotation(ann: &MLAnnotation) {
    println!("{:─<50}", "─ ML Annotation ─");
    println!("  Risk:          {}", ann.risk_score);
    println!("  Confidence:    {}", ann.confidence);
    if !ann.reason.is_empty() {
        println!("  Reason:        {:?}", ann.reason);
    }
    println!("  Entropy:       {:.4}", ann.entropy);
    if let Some(delta) = ann.entropy_delta {
        println!("  Entropy delta: {:.4}", delta);
    }
    if let Some(api) = &ann.api_call {
        println!("  API:           {}", api);
    }
    if !ann.pattern_hits.is_empty() {
        println!("  Patterns:      {}", ann.pattern_hits.join(", "));
    }
    println!("  HDC similarity: {:.4}", ann.hdc_similarity);
    println!("  HDC anchor:    {:?}", ann.hdc_anchor);
    if !ann.next_actions.is_empty() {
        println!("  Next actions:  {:?}", ann.next_actions);
    }
    println!("{:─<50}", "");
}

/// Print a list of HDC hits.
pub fn print_hdc_hits(hits: &[HDCHit]) {
    if hits.is_empty() {
        println!("No HDC hits found.");
        return;
    }
    println!("{:─<60}", "─ HDC Hits ─");
    println!(
        "  {:>18} {:>14} {:>14} Region Entropy",
        "Address", "Anchor", "Similarity"
    );
    for h in hits {
        println!(
            "  {:#018x} {:>14} {:>14.4} {:.4}",
            h.address, h.anchor_name, h.similarity, h.region_entropy
        );
    }
    println!("{:─<60}", "");
}

/// Print trace statistics.
pub fn print_trace_stats(stats: &TraceStats) {
    println!("{:─<50}", "─ Trace Statistics ─");
    println!("  Total steps:  {}", stats.total);
    println!("  Max risk:     {}", stats.max_risk);
    println!("  Avg risk:     {:.4}", stats.avg_risk);
    println!("  Max entropy:  {:.4}", stats.max_entropy);
    println!("  Patterns:     {}", stats.total_patterns);
    println!("  Checkpoints:  {}", stats.checkpoint_count);
    println!("{:─<50}", "");
}

/// Print checkpoint info.
pub fn print_checkpoint(cp: &Checkpoint) {
    println!(
        "  #{}  name={}  RIP={:#018x}  risk={}",
        cp.id,
        cp.name,
        cp.cpu_state.get(Register::RIP),
        cp.annotation_at_save.risk_score,
    );
}
