package antivm

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"mega-analyzer/pkg/internal/antivm/planner"
	"mega-analyzer/pkg/internal/antivm/report"
)

// runSessionReport re-renders a saved verification.json from a session dir.
func runSessionReport(args []string) int {
	fs := flag.NewFlagSet("session report", flag.ContinueOnError)
	sessionDir := fs.String("session", "", "session directory (required)")
	format := fs.String("format", "text", "report format: json|text|html")
	out := fs.String("out", "", "write to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *sessionDir == "" {
		fmt.Fprintln(os.Stderr, "error: --session is required")
		return 2
	}

	data, err := os.ReadFile(filepath.Join(*sessionDir, "verification.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read verification.json: %v\n", err)
		return 1
	}
	var rep planner.RunReport
	if err := json.Unmarshal(data, &rep); err != nil {
		fmt.Fprintf(os.Stderr, "parse verification.json: %v\n", err)
		return 1
	}

	rendered, err := report.Render(rep, report.Format(*format))
	if err != nil {
		fmt.Fprintf(os.Stderr, "render: %v\n", err)
		return 1
	}
	if *out != "" {
		if err := os.WriteFile(*out, rendered, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			return 1
		}
		fmt.Printf("wrote %s\n", *out)
		return 0
	}
	fmt.Println(string(rendered))
	return 0
}
