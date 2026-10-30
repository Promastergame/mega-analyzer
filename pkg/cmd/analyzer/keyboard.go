package main

import "errors"

// errTUIUnsupported is returned by newRawTerm on platforms where the
// interactive wizard isn't implemented yet. Callers should treat it as
// a signal to drop into -no-tui mode.
var errTUIUnsupported = errors.New("interactive TUI is not supported on this platform yet — use -no-tui")
