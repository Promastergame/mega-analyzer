// Command antivm is the CLI for the Android anti-VM analysis toolkit. It
// validates device profiles and runs apply+verify sessions against an emulator,
// a mock device, or a replayed capture. All logic lives in pkg/antivm.
package main

import (
	"os"

	"mega-analyzer/pkg/antivm"
)

func main() {
	os.Exit(antivm.Run(os.Args[1:]))
}
