// Package antivm provides the command-line surface for the Android anti-VM
// analysis toolkit: it validates device profiles and runs sessions against an
// Android emulator (or a replayed/mock device), applying feature modules and
// verifying the result.
//
// Usage:
//
//	antivm profile validate <profile.json>
//	antivm session start   --profile <p.json> [--dry-run] [--strict] [--module m] [--report fmt]
//	antivm session verify  --profile <p.json> --replay <after.json>
//	antivm session report  --session <dir> [--format html]
//	antivm session diff    --before <b.json> --after <a.json> [--scan]
//
// It follows the repository CLI convention: stdlib flag, a Run(args) int entry
// point, and a -test-run-only smoke gate.
package antivm

import (
	"fmt"
	"os"
)

// Run is the CLI entry point. It returns a process exit code.
func Run(args []string) int {
	if len(args) > 0 && args[0] == "-test-run-only" {
		return 0
	}
	if len(args) < 1 {
		usage()
		return 2
	}

	switch args[0] {
	case "profile":
		return runProfile(args[1:])
	case "session":
		return runSession(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `antivm — Android anti-VM analysis toolkit

Commands:
  profile validate <file>                 Validate a device profile for consistency
  session start   --profile <file>        Apply modules to a device and verify
  session verify  --profile <file> --replay <state.json>
                                          Verify a captured device state offline
  session report  --session <dir> [--format json|text|html] [--out <file>]
  session diff    --before <b.json> --after <a.json>
                                          Diff two device states and scan the
                                          after-state for residual VM tells

Common flags for 'session start':
  --profile <file>    device profile JSON (required)
  --adb <path>        adb binary (default "adb"); omit with --mock/--replay
  --serial <id>       device serial, e.g. emulator-5554
  --mock              run against an in-memory mock device (no emulator)
  --replay <file>     verify against a captured DeviceState JSON
  --dry-run           print the plan without applying
  --strict            any module failure aborts the run
  --module <name>     restrict to a module (repeatable via comma list)
  --sessions <dir>    session artifact root (default "sessions")
  --report <fmt>      json|text|html (default text)
  --verbose           extra logging

Flags for 'session diff':
  --session <dir>     read before.json/after.json from a session directory
  --before <file>     before-state JSON (overrides --session)
  --after <file>      after-state JSON (overrides --session)
  --scan              scan the after-state for residual VM tells (default true)
  --fail-on-residue   exit non-zero if residual VM tells remain
  --residue-threshold exposure score (0-100) above which --fail-on-residue trips
  --format <fmt>      json|text (default text)
  --out <file>        write output to a file instead of stdout
`)
}
