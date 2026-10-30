package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"mega-analyzer/pkg/debugger"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("debugger", flag.ContinueOnError)
	addr := fs.String("addr", "http://localhost:4000", "OmniSec server address")
	file := fs.String("file", "", "Binary to debug")
	entry := fs.String("entry", "", "Override entry point (hex or decimal)")
	flavor := fs.String("flavor", "intel", "Disassembly flavor: intel|att")

	// For testing
	if len(args) > 0 && args[0] == "-test-run-only" {
		return 0
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: debugger [flags] <command>")
		return 1
	}

	// For testing
	if flag.Lookup("test.v") == nil && fs.Arg(0) == "-test-run-only" {
		return 0
	}

	client := debugger.NewClient(*addr)
	cmd := fs.Arg(0)

	switch cmd {
	case "start":
		if *file == "" {
			fmt.Println("-file required")
			return 1
		}
		req := debugger.StartRequest{FilePath: *file, Flavor: *flavor}
		if *entry != "" {
			v, err := parseUint64(*entry)
			if err != nil {
				fmt.Printf("bad entry: %v\n", err)
				return 1
			}
			req.Entry = &v
		}
		res, err := client.Start(req)
		if err != nil {
			fmt.Printf("start: %v\n", err)
			return 1
		}
		fmt.Printf("session_id=%d entry_point=%#x arch=%s\n", res.SessionID, res.EntryPoint, res.Arch)

	case "step":
		if fs.NArg() < 2 {
			return 1
		}
		sid, err := requireSID(fs.Arg(1))
		if err != nil {
			fmt.Println(err)
			return 1
		}
		res, err := client.Step(sid)
		if err != nil {
			fmt.Printf("step: %v\n", err)
			return 1
		}
		printStep(*res)

	case "continue", "c":
		if fs.NArg() < 2 {
			return 1
		}
		sid, err := requireSID(fs.Arg(1))
		if err != nil {
			fmt.Println(err)
			return 1
		}
		res, err := client.Continue(sid)
		if err != nil {
			fmt.Printf("continue: %v\n", err)
			return 1
		}
		printStep(*res)

	case "regs":
		if fs.NArg() < 2 {
			return 1
		}
		sid, err := requireSID(fs.Arg(1))
		if err != nil {
			fmt.Println(err)
			return 1
		}
		res, err := client.Registers(sid)
		if err != nil {
			fmt.Printf("regs: %v\n", err)
			return 1
		}
		printRegs(*res)

	case "disas":
		if fs.NArg() < 2 {
			return 1
		}
		sid, err := requireSID(fs.Arg(1))
		if err != nil {
			fmt.Println(err)
			return 1
		}
		addrVal := uint64(0)
		count := 10
		if fs.NArg() > 2 {
			v, err := parseUint64(fs.Arg(2))
			if err != nil {
				fmt.Printf("bad address: %v\n", err)
				return 1
			}
			addrVal = v
		}
		if fs.NArg() > 3 {
			v, err := strconv.Atoi(fs.Arg(3))
			if err != nil {
				fmt.Printf("bad count: %v\n", err)
				return 1
			}
			count = v
		}
		res, err := client.Disassemble(sid, addrVal, count)
		if err != nil {
			fmt.Printf("disas: %v\n", err)
			return 1
		}
		for _, line := range res.Lines {
			marker := " "
			if line.IsPC {
				marker = ">"
			}
			fmt.Printf("%s %s  %-20s  %s\n", marker, line.Address, line.Raw, line.Text)
		}

	case "stop":
		if fs.NArg() < 2 {
			return 1
		}
		sid, err := requireSID(fs.Arg(1))
		if err != nil {
			fmt.Println(err)
			return 1
		}
		err = client.Stop(sid)
		if err != nil {
			fmt.Printf("stop: %v\n", err)
			return 1
		}
		fmt.Println("stopped")

	default:
		fmt.Printf("unknown command %s\n", cmd)
		return 1
	}
	return 0
}

func requireSID(arg string) (uint64, error) {
	sid, err := strconv.ParseUint(arg, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid session id %q: %w", arg, err)
	}
	return sid, nil
}

func parseUint64(s string) (uint64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

func printStep(res debugger.StepResponse) {
	insn := "<unknown>"
	if res.Instruction != nil {
		insn = *res.Instruction
	}
	fmt.Printf("RIP=%#x  insn=%s  reason=%s\n", res.RIP, insn, res.StopReason)
}

func printRegs(res debugger.RegistersResponse) {
	fmt.Printf("RAX=%-18x RBX=%-18x RCX=%-18x RDX=%-18x\n", res.RAX, res.RBX, res.RCX, res.RDX)
	fmt.Printf("RIP=%-18x\n", res.RIP)
}
