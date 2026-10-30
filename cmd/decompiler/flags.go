package main

import (
	"flag"
	"strings"
)

// Permit options on either side of the input while retaining flag's handling
// of values, boolean flags, errors and the explicit -- separator.
func interspersedArgs(fs *flag.FlagSet, args []string) []string {
	var options, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		options = append(options, arg)
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		f := fs.Lookup(name)
		if f == nil || hasValue {
			continue
		}
		boolean, ok := f.Value.(interface{ IsBoolFlag() bool })
		if ok && boolean.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			options = append(options, args[i])
		} else {
			// Leave a missing value at the end so flag.Parse reports it;
			// appending -- here would accidentally turn it into the value.
			return options
		}
	}
	if len(positional) > 0 {
		options = append(options, "--")
		options = append(options, positional...)
	}
	return options
}
