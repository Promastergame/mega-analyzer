// sandbox-collector provisions a VM agent or recovers host reports offline.
package main

import (
	"flag"
	"fmt"
	"os"

	"mega-analyzer/pkg/internal/sandbox"
)

func run(args []string) error {
	fs := flag.NewFlagSet("sandbox-collector", flag.ContinueOnError)
	initDir := fs.String("init", "", "Create NEW host profile and guest agent TLS directory")
	endpoint := fs.String("endpoint", "", "Private numeric VM guest IP:port")
	python := fs.String("python", "", "Absolute trusted Python interpreter path on this host (Frida SDK required)")
	recoverPath := fs.String("recover", "", "Host events.jsonl to recover without VM")
	output := fs.String("output", "analysis_output", "Local host report directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*initDir == "") == (*recoverPath == "") {
		return fmt.Errorf("choose exactly one: -init NEW_DIRECTORY or -recover HOST_EVENTS_JSONL")
	}
	if *initDir != "" {
		path, err := sandbox.CreateRemoteProfile(*initDir, *endpoint, *python)
		if err != nil {
			return err
		}
		fmt.Printf("Host profile: %s\nCopy only guest/ into the clean VM. See docs/SANDBOX_VM_HOST.ru.md.\n", path)
		return nil
	}
	r, err := sandbox.RecoverRemoteJournal(*recoverPath, *output)
	if err == nil {
		fmt.Printf("Recovered host report: %s\nIncomplete: %t\n", r.JSONPath, r.RemoteCapture.Incomplete)
	}
	return err
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
