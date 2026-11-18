package web

import _ "embed"

//go:embed index.html
var Page []byte

//go:embed text.html
var TextPage []byte

//go:embed eval.html
var EvalPage []byte

// EvalReport is the bundled `decision-ai eval` report shown at /eval.
//
//go:embed eval-report.json
var EvalReport []byte
