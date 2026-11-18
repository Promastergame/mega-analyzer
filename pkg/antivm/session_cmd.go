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
	"mega-analyzer/pkg/internal/antivm/verifier"
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
	keepGoing := fs.Bool("continue-on-failure", false, "verify remaining modules after a critical failure (status stays failed)")
	moduleList := fs.String("module", "", "restrict to comma-separated module names")
	sessionsRoot := fs.String("sessions", "sessions", "session artifact root")
	reportFmt := fs.String("report", "text", "report format: json|text|html")
	verbose := fs.Bool("verbose", false, "extra logging")
	timeout := fs.Duration("timeout", 3*time.Minute, "maximum session duration, e.g. 3m")
	hold := fs.Duration("hold", 0, "keep the analysis session and sensor playback running after verification")
	resetprop := fs.String("resetprop", "", "absolute path to a resetprop executable in a root AVD")
	restartFramework := fs.Bool("restart-framework", false, "restart Android after property writes so apps see refreshed Build values (requires --resetprop)")
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
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: --timeout must be positive")
		return 2
	}
	if *hold < 0 || *hold >= *timeout || (*hold > 0 && (sub != "start" || *dryRun || *replayPath != "")) {
		fmt.Fprintln(os.Stderr, "error: --hold requires session start and must be non-negative and shorter than --timeout")
		return 2
	}
	if *restartFramework && *resetprop == "" {
		fmt.Fprintln(os.Stderr, "error: --restart-framework requires --resetprop")
		return 2
	}
	if *resetprop != "" && (*mock || *replayPath != "" || sub == "verify") {
		fmt.Fprintln(os.Stderr, "error: --resetprop requires a real AVD session start")
		return 2
	}
	switch *reportFmt {
	case "json", "text", "html":
	default:
		fmt.Fprintf(os.Stderr, "error: unknown --report %q\n", *reportFmt)
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
		modules.NewDisplayModule(p),
		modules.NewSensorsModule(p),
	}
	only := parseModuleFilter(*moduleList)
	for name := range only {
		known := false
		for _, mod := range mods {
			if mod.Name() == name {
				known = true
				break
			}
		}
		if !known {
			fmt.Fprintf(os.Stderr, "unknown module %q; supported: identity, environment, battery, display, sensors\n", name)
			return 2
		}
	}
	opts := planner.Options{
		DryRun:            *dryRun,
		Strict:            *strict,
		Only:              only,
		ContinueOnFailure: *keepGoing,
		VerifyOnly:        sub == "verify" || *replayPath != "",
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	deviceStopped := false
	defer func() {
		if deviceStopped {
			return
		}
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer stopCancel()
		if err := dev.Stop(stopCtx); err != nil {
			fmt.Fprintf(os.Stderr, "stop device session: %v\n", err)
		}
	}()
	if !*dryRun && !*mock && *replayPath == "" {
		if err := dev.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "connect device: %v\n", err)
			return 1
		}
		if err := dev.WaitForBoot(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "wait for Android: %v\n", err)
			return 1
		}
		if *resetprop != "" {
			if err := dev.(*adapter.ADBAdapter).ConfigureResetprop(ctx, *resetprop, *restartFramework); err != nil {
				fmt.Fprintf(os.Stderr, "configure property writer: %v\n", err)
				return 1
			}
		}
	}
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
		before, rerr := dev.ReadState(ctx)
		if rerr == nil {
			rerr = sess.SaveBefore(before)
		}
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "capture before: %v\n", rerr)
			return 1
		}
	}

	pl := planner.New(p, mods)
	rep, runErr := pl.Run(ctx, dev, opts, now)
	if *hold > 0 && runErr == nil {
		fmt.Fprintf(os.Stderr, "keeping the analysis session open for %s\n", *hold)
		timer := time.NewTimer(*hold)
		select {
		case <-timer.C:
		case <-ctx.Done():
			runErr = ctx.Err()
			rep.Status = "failed"
		}
		timer.Stop()
		for index := range rep.Modules {
			if rep.Modules[index].Module != "sensors" {
				continue
			}
			verified, err := modules.NewSensorsModule(p).Verify(ctx, dev)
			rep.Modules[index].Verify = verified
			if err != nil {
				rep.Modules[index].Err = err.Error()
				rep.Status = verifier.StatusFailed
				runErr = err
			} else if verified.Status != verifier.StatusPassed && verified.Status != verifier.StatusSkipped {
				rep.Warnings = append(rep.Warnings, "sensor playback verification after hold did not pass")
				if *strict {
					rep.Status = verifier.StatusFailed
					runErr = fmt.Errorf("sensor playback verification after hold failed")
				} else if rep.Status != verifier.StatusFailed {
					rep.Status = verifier.StatusPartial
				}
			}
		}
		rep.FinishedAt = now()
	}

	// Persist artifacts and render the report.
	if sess != nil {
		after, rerr := dev.ReadState(ctx)
		if rerr == nil {
			rerr = sess.SaveAfter(after)
		}
		if rerr != nil {
			rep.Warnings = append(rep.Warnings, "capture after: "+rerr.Error())
			rep.Status = "failed"
			runErr = rerr
		}
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
	stopErr := dev.Stop(stopCtx)
	stopCancel()
	deviceStopped = true
	if stopErr != nil {
		rep.Warnings = append(rep.Warnings, "restore sensor state: "+stopErr.Error())
		rep.Status = verifier.StatusFailed
		runErr = stopErr
	}
	if sess != nil {
		if err := sess.SaveVerification(rep); err != nil {
			fmt.Fprintf(os.Stderr, "save verification: %v\n", err)
			return 1
		}
	}

	out, rerr := report.Render(rep, report.Format(*reportFmt))
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "render report: %v\n", rerr)
		return 1
	}
	fmt.Println(string(out))
	if sess != nil {
		ext := *reportFmt
		if err := sess.WriteReport(ext, out); err != nil {
			fmt.Fprintf(os.Stderr, "save report: %v\n", err)
			return 1
		}
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
