package main

import (
	"flag"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ARG NORMALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

// boolFlag mirrors the unexported interface the standard "flag" package uses
// internally (flag.boolFlag) to detect flags that don't take a value on the
// command line. Any flag.Value implementation with an IsBoolFlag() bool method
// (as produced by flag.BoolVar) satisfies this structurally.
type boolFlag interface {
	IsBoolFlag() bool
}

// valueFlagsFromFlagSet derives the set of value-taking flag names (both "-x"
// and "--x" spellings) directly from a FlagSet's registrations, so the set can
// never drift out of sync with the flags actually registered in Parse().
func valueFlagsFromFlagSet(fs *flag.FlagSet) map[string]bool {
	valueFlags := make(map[string]bool)
	if fs == nil {
		return valueFlags
	}
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(boolFlag); ok && bf.IsBoolFlag() {
			return
		}
		valueFlags["-"+f.Name] = true
		valueFlags["--"+f.Name] = true
	})
	return valueFlags
}

func normalizeArgs(args []string, fs *flag.FlagSet) []string {
	valueFlags := valueFlagsFromFlagSet(fs)

	flags := make([]string, 0, len(args))
	positional := make([]string, 0, 2)

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}

		flags = append(flags, arg)

		name := arg
		if eq := strings.IndexByte(arg, '='); eq != -1 {
			name = arg[:eq]
		} else if valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}

	return append(flags, positional...)
}
