package antivm

import (
	"flag"
	"fmt"
	"os"

	"mega-analyzer/pkg/internal/antivm/profile"
)

// runProfile handles `antivm profile <sub>`.
func runProfile(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: antivm profile validate <file>")
		return 2
	}
	switch args[0] {
	case "validate":
		return runProfileValidate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown profile subcommand %q\n", args[0])
		return 2
	}
}

func runProfileValidate(args []string) int {
	fs := flag.NewFlagSet("profile validate", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: antivm profile validate <file>")
		return 2
	}
	path := fs.Arg(0)

	p, err := profile.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		return 1
	}
	res := profile.Validate(p)
	if res.OK() {
		fmt.Printf("OK: %s is consistent (%s, API %d)\n", path, p.Model, p.APILevel)
		return 0
	}
	fmt.Printf("INVALID: %s\n", path)
	for _, e := range res.Errors {
		fmt.Printf("  - %s\n", e.Error())
	}
	return 1
}
