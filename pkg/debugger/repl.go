package debugger

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"mega-analyzer/pkg/debugger/native"
)

type DebuggerEngine interface {
	Start(filePath string, entry uint64) uint64
	Stop(sessionID uint64)
	Step(sessionID uint64) (map[string]interface{}, error)
	Next(sessionID uint64) (map[string]interface{}, error)
	Continue(sessionID uint64) (map[string]interface{}, error)
	Registers(sessionID uint64) (map[string]interface{}, error)
	Disassemble(sessionID uint64, address uint64, count int) (map[string]interface{}, error)
	ReadMemory(sessionID uint64, address uint64, size uint64) (map[string]interface{}, error)
	WriteMemory(sessionID uint64, address uint64, hex string) (map[string]interface{}, error)
	SetRegister(sessionID uint64, reg string, value uint64) (map[string]interface{}, error)
	Breakpoint(sessionID uint64, target string) (map[string]interface{}, error)
	RemoveBreakpoint(sessionID uint64, id uint32) (map[string]interface{}, error)
	TraceEnable(sessionID uint64, enabled bool)
	SetFlavor(sessionID uint64, flavor string)
	ReverseStep(sessionID uint64) (map[string]interface{}, error)
	ReverseContinue(sessionID uint64) (map[string]interface{}, error)
	ScanMemory(sessionID uint64, pattern string) (map[string]interface{}, error)
}

var newDebuggerEngine = func() DebuggerEngine {
	return native.NewNative()
}

func startSession(eng DebuggerEngine, filePath string, entry uint64) (sid uint64, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	sid = eng.Start(filePath, entry)
	return sid, nil
}

// RunREPL starts an interactive debugger session for the given binary.
func RunREPL(filePath, entryStr string) error {
	var entry uint64
	if entryStr != "" {
		v, err := parseUint64(entryStr)
		if err != nil {
			return fmt.Errorf("bad entry point: %w", err)
		}
		entry = v
	}

	eng := newDebuggerEngine()
	sid, err := startSession(eng, filePath, entry)
	if err != nil {
		return fmt.Errorf("failed to start debugger session for %s: %w", filePath, err)
	}
	if sid == 0 {
		return fmt.Errorf("failed to start debugger session for %s", filePath)
	}
	defer eng.Stop(sid)

	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║     OMNISEC MACHINE-CODE DEBUGGER        ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Printf("Session %d started for %s\n", sid, filePath)
	fmt.Println("Type 'help' for commands, 'quit' to exit.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	var lastCmd string
	for {
		fmt.Print("(omnisec) ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" && lastCmd != "" {
			line = lastCmd
			fmt.Printf("(repeat) %s\n", lastCmd)
		} else if line == "" {
			continue
		}
		lastCmd = line

		parts := strings.Fields(line)
		cmd := parts[0]

		switch cmd {
		case "help", "h", "?":
			printHelp()

		case "quit", "q", "exit":
			fmt.Println("Session stopped.")
			return nil

		case "step", "s":
			res, err := eng.Step(sid)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				printStep(res)
				autoContext(eng, sid)
			}

		case "next", "n":
			res, err := eng.Next(sid)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				printStep(res)
				autoContext(eng, sid)
			}

		case "continue", "c":
			res, err := eng.Continue(sid)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				printStep(res)
				autoContext(eng, sid)
			}

		case "regs", "registers", "info", "r":
			res, err := eng.Registers(sid)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				printRegs(res)
			}

		case "disas", "disassemble", "d":
			addr := uint64(0)
			count := 10
			if len(parts) > 1 {
				v, err := parseUint64(parts[1])
				if err == nil {
					addr = v
				}
			}
			if len(parts) > 2 {
				v, err := strconv.Atoi(parts[2])
				if err == nil {
					count = v
				}
			}
			res, err := eng.Disassemble(sid, addr, count)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				printDisas(res)
			}

		case "mem", "x", "memory":
			addr := uint64(0)
			size := uint64(16)
			if len(parts) > 1 {
				v, err := parseUint64(parts[1])
				if err == nil {
					addr = v
				}
			}
			if len(parts) > 2 {
				v, err := parseUint64(parts[2])
				if err == nil {
					size = v
				}
			}
			res, err := eng.ReadMemory(sid, addr, size)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				printMem(res)
			}

		case "bp", "break", "b":
			if len(parts) < 2 {
				fmt.Println("Usage: bp <address|symbol>")
				continue
			}
			res, err := eng.Breakpoint(sid, parts[1])
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Printf("Breakpoint: %+v\n", res)
			}

		case "remove-bp", "rb":
			if len(parts) < 2 {
				fmt.Println("Usage: remove-bp <id>")
				continue
			}
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Println("bad id")
				continue
			}
			res, err := eng.RemoveBreakpoint(sid, uint32(id))
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Printf("Result: %+v\n", res)
			}

		case "patch", "p":
			if len(parts) < 3 {
				fmt.Println("Usage: patch <address> <hex>")
				continue
			}
			addr, err := parseUint64(parts[1])
			if err != nil {
				fmt.Println("bad address")
				continue
			}
			res, err := eng.WriteMemory(sid, addr, parts[2])
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Printf("Result: %+v\n", res)
			}

		case "set-reg", "sr":
			if len(parts) < 3 {
				fmt.Println("Usage: set-reg <register> <value>")
				continue
			}
			val, err := parseUint64(parts[2])
			if err != nil {
				fmt.Println("bad value")
				continue
			}
			res, err := eng.SetRegister(sid, parts[1], val)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Printf("Result: %+v\n", res)
			}

		case "reverse-step", "rs":
			res, err := eng.ReverseStep(sid)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				printStep(res)
				autoContext(eng, sid)
			}

		case "reverse-continue", "rc":
			res, err := eng.ReverseContinue(sid)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				printStep(res)
				autoContext(eng, sid)
			}

		case "trace", "t":
			enabled := true
			if len(parts) > 1 && (parts[1] == "off" || parts[1] == "0") {
				enabled = false
			}
			eng.TraceEnable(sid, enabled)
			fmt.Printf("trace %v\n", enabled)

		case "scan":
			if len(parts) < 2 {
				fmt.Println("Usage: scan <hex pattern>  (e.g. scan '48 8B ?? 24')")
				continue
			}
			pattern := strings.Join(parts[1:], " ")
			res, err := eng.ScanMemory(sid, pattern)
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				printScan(res)
			}

		case "flavor", "f":
			f := "intel"
			if len(parts) > 1 {
				f = parts[1]
			}
			eng.SetFlavor(sid, f)
			fmt.Println("ok")

		default:
			fmt.Printf("Unknown command: %s (try 'help')\n", cmd)
		}
	}
	return nil
}

func printHelp() {
	fmt.Println(`Commands:
  step, s                     Step one instruction
  next, n                     Step over calls
  continue, c                 Run until stop
  reverse-step, rs            Reverse step (needs trace)
  reverse-continue, rc         Reverse continue (needs trace)
  trace [on|off]              Toggle time-travel trace
  scan <pattern>              YARA-like memory scan (hex + ??)
  regs, r                     Show registers
  disas [addr] [count]        Disassemble
  mem [addr] [size]           Read memory
  bp <addr|symbol>            Set breakpoint
  remove-bp <id>              Remove breakpoint
  patch <addr> <hex>          Patch memory
  set-reg <reg> <value>       Change register
  flavor <intel|att>          Disassembly syntax
  help, h                     Show this help
  quit, q                     Exit debugger
  <Enter>                     Repeat last command`)
}

func unwrapResult(res map[string]interface{}) map[string]interface{} {
	if r, ok := res["result"].(map[string]interface{}); ok {
		return r
	}
	return res
}

func printStep(res map[string]interface{}) {
	r := unwrapResult(res)
	fmt.Printf("RIP=%v  insn=%v  reason=%v\n",
		r["rip"], r["instruction"], r["stop_reason"])
}

func printRegs(res map[string]interface{}) {
	result := unwrapResult(res)
	fmt.Printf("RAX=%-18v RBX=%-18v RCX=%-18v RDX=%-18v\n",
		result["rax"], result["rbx"], result["rcx"], result["rdx"])
	fmt.Printf("RSI=%-18v RDI=%-18v RBP=%-18v RSP=%-18v\n",
		result["rsi"], result["rdi"], result["rbp"], result["rsp"])
	fmt.Printf("R8 =%-18v R9 =%-18v R10=%-18v R11=%-18v\n",
		result["r8"], result["r9"], result["r10"], result["r11"])
	fmt.Printf("R12=%-18v R13=%-18v R14=%-18v R15=%-18v\n",
		result["r12"], result["r13"], result["r14"], result["r15"])
	fmt.Printf("RIP=%-18v\n", result["rip"])
	if f, ok := result["flags"].(map[string]interface{}); ok {
		fmt.Printf("Flags: ZF=%v SF=%v CF=%v OF=%v\n", f["zf"], f["sf"], f["cf"], f["of"])
	}
}

func printDisas(res map[string]interface{}) {
	result := unwrapResult(res)
	lines, _ := result["lines"].([]interface{})
	for _, line := range lines {
		if l, ok := line.(map[string]interface{}); ok {
			marker := " "
			if l["is_pc"] == true {
				marker = ">"
			}
			fmt.Printf("%s %s  %-20s  %s\n", marker, l["address"], l["raw"], l["text"])
		}
	}
}

func printMem(res map[string]interface{}) {
	result := unwrapResult(res)
	fmt.Printf("%v: %v\n", result["address"], result["hex"])
}

// autoContext prints current instruction + 2 next with a => arrow after step/next/continue.
func autoContext(eng DebuggerEngine, sid uint64) {
	regs, err := eng.Registers(sid)
	if err != nil {
		return
	}
	r := unwrapResult(regs)
	ripVal, ok := r["rip"]
	if !ok {
		return
	}
	var rip uint64
	switch v := ripVal.(type) {
	case float64:
		rip = uint64(v)
	case uint64:
		rip = v
	case int:
		rip = uint64(v)
	default:
		return
	}
	res, err := eng.Disassemble(sid, rip, 3)
	if err != nil {
		return
	}
	result := unwrapResult(res)
	lines, _ := result["lines"].([]interface{})
	for _, line := range lines {
		if l, ok := line.(map[string]interface{}); ok {
			marker := "  "
			if l["is_pc"] == true {
				marker = "=>"
			}
			fmt.Printf("%s %s  %-20s  %s\n", marker, l["address"], l["raw"], l["text"])
		}
	}
}

func printScan(res map[string]interface{}) {
	result := unwrapResult(res)
	count, _ := result["count"].(float64)
	fmt.Printf("Found %d hit(s)\n", int(count))
	hits, _ := result["hits"].([]interface{})
	for _, h := range hits {
		if m, ok := h.(map[string]interface{}); ok {
			fmt.Printf("  hit at %v\n", m["address"])
		} else {
			fmt.Printf("  %v\n", h)
		}
	}
}

func parseUint64(s string) (uint64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}
