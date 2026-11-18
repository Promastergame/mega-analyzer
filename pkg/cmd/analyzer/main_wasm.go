//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"syscall/js"

	"mega-analyzer/pkg/buildinfo"
	"mega-analyzer/pkg/cmd/analyzer/web"
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/pipeline"
)

var AppName, Version, BuildDate, CommitHash = "Mega Analyzer", "", "", ""

type browserCommand struct {
	Mode    string   `json:"mode"`
	Targets []string `json:"targets"`
	Output  string   `json:"output"`
	Flags   []string `json:"flags"`
	Workers int      `json:"workers"`
	Timeout *int     `json:"timeout"`
}

func init() {
	buildinfo.Configure(Version, BuildDate, CommitHash)
	Version, BuildDate, CommitHash = buildinfo.Version, buildinfo.BuildDate, buildinfo.CommitHash
}

func main() {
	var fileScanner *pipeline.FileScanWorker
	var fileScannerConfiguration string
	scanFile := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 4 || args[2].Get("byteLength").Int() > 64<<20 {
			return false
		}
		configuration, metadata, id := args[0].String(), args[1].String(), args[3].String()
		content := make([]byte, args[2].Get("byteLength").Int())
		js.CopyBytesToGo(content, args[2])
		go func() {
			var result pipeline.FileScanResult
			var err error
			defer func() {
				if recovered := recover(); recovered != nil {
					err = fmt.Errorf("file helper: %v", recovered)
				}
				message := ""
				if err != nil {
					message = err.Error()
				}
				encoded, encodeErr := json.Marshal(result)
				if encodeErr != nil {
					message = encodeErr.Error()
				}
				js.Global().Call("megaFileReply", id, string(encoded), message)
			}()
			if fileScanner == nil || fileScannerConfiguration != configuration {
				var cfg config.Config
				if err = json.Unmarshal([]byte(configuration), &cfg); err != nil {
					return
				}
				if fileScanner, err = pipeline.NewFileScanWorker(&cfg); err != nil {
					return
				}
				fileScannerConfiguration = configuration
			}
			var task pipeline.FileScanTask
			if err = json.Unmarshal([]byte(metadata), &task); err != nil {
				return
			}
			result, err = fileScanner.Scan(context.Background(), task, content)
		}()
		return true
	})
	js.Global().Set("megaScanFile", scanFile)
	run := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 1 {
			return false
		}
		var command browserCommand
		if err := json.Unmarshal([]byte(args[0].String()), &command); err != nil {
			return false
		}
		allowed := map[string]bool{"full": true, "minecraft": true, "decode": true, "build": true, "machine-code": true, "firmware": true, "version-diff": true, "js-deobf": true, "js-patch": true}
		if !allowed[command.Mode] || len(command.Targets) == 0 || (command.Mode == "version-diff" && len(command.Targets) != 2) {
			return false
		}
		if command.Workers == 0 {
			command.Workers = 2
		}
		timeout := 300
		if command.Timeout != nil {
			timeout = *command.Timeout
		}
		if command.Workers < 1 || command.Workers > 4 || timeout < 0 || timeout > 3600 {
			return false
		}
		flags, err := web.ValidateModeFlags(command.Mode, command.Flags)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return false
		}
		cli := web.BuildModeArgs(command.Mode, command.Targets, command.Output, "", "", "", flags)
		cli = append(cli, "-no-profile", "-workers", strconv.Itoa(command.Workers), "-timeout", strconv.Itoa(timeout))
		go func() {
			code := 0
			defer func() {
				if recovered := recover(); recovered != nil {
					fmt.Fprintln(os.Stderr, recovered)
					code = 1
				}
				js.Global().Call("megaDone", code)
			}()
			os.Args = append([]string{"analyzer"}, cli...)
			app := NewApp()
			if err := app.Run(cli); err != nil {
				fmt.Fprintln(os.Stderr, err)
				code = 1
			} else {
				code = app.ExitCode()
			}
		}()
		return true
	})
	js.Global().Set("megaRun", run)
	select {}
}
