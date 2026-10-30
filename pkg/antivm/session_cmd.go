package antivm

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/modules"
	"mega-analyzer/pkg/internal/antivm/planner"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/report"
	"mega-analyzer/pkg/internal/antivm/session"
)

// runSession handles `antivm session <sub>`.
func runSession(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: antivm session <start|verify|report|diff> ...")
		return 2
	}
	switch args[0] {
	case "start", "verify":
		return runSessionStart(args[0], args[1:])
	case "report":
		return runSessionReport(args[1:])
	case "diff":
		return runSessionDiff(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown session subcommand %q\n", args[0])
		return 2
	}
}

// runSessionStart runs a full apply+verify session. When sub is "verify" it
// only verifies (against a replay or mock) without claiming to have applied.
func runSessionStart(sub string, args []string) int {
	fs := flag.NewFlagSet("session "+sub, flag.ContinueOnError)
	profilePath := fs.String("profile", "", "device profile JSON (required)")
	adbPath := fs.String("adb", "adb", "adb binary path")
	serial := fs.String("serial", "", "device serial (e.g. emulator-5554)")
	mock := fs.Bool("mock", false, "run against an in-memory mock device")
	replayPath := fs.String("replay", "", "verify against a captured DeviceState JSON")
	dryRun := fs.Bool("dry-run", false, "print the plan without applying")
	strict := fs.Bool("strict", false, "any module failure aborts the run")
	moduleList := fs.String("module", "", "restrict to comma-separated module names")
	sessionsRoot := fs.String("sessions", "sessions", "session artifact root")
	reportFmt := fs.String("report", "text", "report format: json|text|html")
	verbose := fs.Bool("verbose", false, "extra logging")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *profilePath == "" {
		fmt.Fprintln(os.Stderr, "error: --profile is required")
		return 2
	}

	p, err := profile.Load(*profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load profile: %v\n", err)
		return 1
	}
	if res := profile.Validate(p); !res.OK() {
		fmt.Fprintf(os.Stderr, "profile is invalid:\n")
		for _, e := range res.Errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", e.Error())
		}
		return 1
	}

	// Choose the device adapter.
	dev, err := selectAdapter(*mock, *replayPath, *adbPath, *serial, sub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	// Build the module set.
	mods := []modules.Module{
		modules.NewIdentityModule(p),
		modules.NewEnvironmentModule(p),
		modules.NewBatteryModule(p),
	}
	opts := planner.Options{
		DryRun: *dryRun,
		Strict: *strict,
		Only:   parseModuleFilter(*moduleList),
	}

	ctx := context.Background()
	now := time.Now

	// Create the session directory unless dry-running.
	var sess *session.Session
	if !*dryRun {
		sess, err = session.NewSession(*sessionsRoot, p, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create session: %v\n", err)
			return 1
		}
		if *verbose {
			fmt.Printf("session: %s\n", sess.Dir)
		}
		// Capture 'before' state (best-effort).
		if before, rerr := dev.ReadState(ctx); rerr == nil {
			_ = sess.SaveBefore(before)
		}
	}

	pl := planner.New(p, mods)
	rep, runErr := pl.Run(ctx, dev, opts, now)

	// Persist artifacts and render the report.
	if sess != nil {
		if after, rerr := dev.ReadState(ctx); rerr == nil {
			_ = sess.SaveAfter(after)
		}
		_ = sess.SaveVerification(rep)
	}

	out, rerr := report.Render(rep, report.Format(*reportFmt))
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "render report: %v\n", rerr)
		return 1
	}
	fmt.Println(string(out))
	if sess != nil {
		ext := *reportFmt
		_ = sess.WriteReport(ext, out)
	}

	// Exit code reflects the real outcome, not merely "ran".
	if runErr != nil {
		if *verbose {
			fmt.Fprintf(os.Stderr, "run: %v\n", runErr)
		}
		return 1
	}
	switch rep.Status {
	case "failed":
		return 1
	default:
		return 0
	}
}

// selectAdapter picks the device transport based on flags. For `session verify`
// a mock or replay source is required (no real apply happens).
func selectAdapter(mock bool, replayPath, adbPath, serial, sub string) (adapter.DeviceAdapter, error) {
	switch {
	case replayPath != "":
		return adapter.LoadReplay(replayPath)
	case mock:
		return adapter.NewMockAdapter(), nil
	case sub == "verify":
		return nil, fmt.Errorf("session verify requires --replay <file> or --mock")
	default:
		return adapter.NewADBAdapter(adbPath, serial), nil
	}
}

func parseModuleFilter(list string) map[string]bool {
	list = strings.TrimSpace(list)
	if list == "" {
		return nil
	}
	only := map[string]bool{}
	for _, name := range strings.Split(list, ",") {
		if n := strings.TrimSpace(name); n != "" {
			only[n] = true
		}
	}
	return only
}
