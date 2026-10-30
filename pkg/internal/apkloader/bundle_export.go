package apkloader

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mega-analyzer/pkg/internal/types"
	"os"
	"path/filepath"
	"time"

	"mega-analyzer/pkg/internal/deobfuscation"
)

// IsJavaScriptBundle checks content, not a filename extension. HBC and Unity
// containers must never be sent through text rewriting.
func IsJavaScriptBundle(data []byte) bool { return classifyBundle(data) == bundleJS }

// BundleExportOptions bounds decoding and text expansion independently.
type BundleExportOptions struct {
	MaxFunctions     int
	MaxBytecodeBytes uint64
	MaxInstructions  uint64
	MaxOutputBytes   int64
}

// BundleBudget provides documented, bounded presets; neither is unlimited.
func BundleBudget(name string) (BundleExportOptions, error) {
	switch name {
	case "compact":
		return BundleExportOptions{5000, 16 << 20, 1000000, 64 << 20}, nil
	case "", "large":
		return BundleExportOptions{100000, 64 << 20, 10000000, 512 << 20}, nil
	default:
		return BundleExportOptions{}, fmt.Errorf("invalid bundle budget %q: compact|large", name)
	}
}

func ExportBundle(ctx context.Context, input, output string) (BundleFileAnalysis, error) {
	opts, _ := BundleBudget("large")
	return ExportBundleWithOptions(ctx, input, output, opts)
}

// ExportBundleWithOptions writes inspectable artifacts, not recovered source.
// Metadata is streamed, strings in disassembly are previews, full values stay
// in hermes.json. Unsupported HBC still gets coverage.json and original bytes.
func ExportBundleWithOptions(ctx context.Context, input, output string, opts BundleExportOptions) (coverage BundleFileAnalysis, err error) {
	started := time.Now()
	coverage = BundleFileAnalysis{Path: filepath.Base(input), Status: "complete"}
	if opts.MaxFunctions <= 0 || opts.MaxBytecodeBytes == 0 || opts.MaxInstructions == 0 || opts.MaxOutputBytes <= 0 {
		return coverage, fmt.Errorf("all bundle export limits must be positive")
	}
	if err = os.MkdirAll(output, 0755); err != nil {
		return
	}
	defer func() {
		coverage.ElapsedSeconds = time.Since(started).Seconds()
		if err != nil {
			coverage.Status = "failed"
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				coverage.Status = "partial"
			}
			coverage.Diagnostics = append(coverage.Diagnostics, err.Error())
		}
		data, writeErr := json.MarshalIndent(coverage, "", "  ")
		if writeErr == nil {
			writeErr = os.WriteFile(filepath.Join(output, "coverage.json"), data, 0644)
		}
		if err == nil {
			err = writeErr
		}
	}()
	data, readErr := ReadBundleFile(ctx, input)
	if readErr != nil {
		err = readErr
		return
	}
	coverage.TotalBytes, coverage.ScannedBytes = int64(len(data)), int64(len(data))
	if err = os.WriteFile(filepath.Join(output, "original.bundle"), data, 0644); err != nil {
		return
	}
	switch classifyBundle(data) {
	case bundleJS:
		coverage.Kind, coverage.Mode = "javascript", "original_and_decoded_strings"
		coverage.Diagnostics = append(coverage.Diagnostics, "original.js is unchanged input; decoded_strings.json contains heuristic decoded text fragments for inspection, not executable JavaScript or recovered source")
		if err = os.WriteFile(filepath.Join(output, "original.js"), data, 0644); err != nil {
			return
		}
		engine := deobfuscation.NewJSDeobfuscator(deobfuscation.ScanJSOptions())
		fragments := extractPrintableStrings([]byte(engine.Deobfuscate(string(data))), 4)
		if err = ctx.Err(); err != nil {
			return
		}
		file, openErr := os.Create(filepath.Join(output, "decoded_strings.json"))
		if openErr != nil {
			err = openErr
			return
		}
		writer := bufio.NewWriter(file)
		written := int64(2)
		_, err = writer.WriteString("[")
		for i, fragment := range fragments {
			if err != nil {
				break
			}
			if err = ctx.Err(); err != nil {
				break
			}
			encoded, _ := json.Marshal(fragment)
			prefix := ""
			if i > 0 {
				prefix = ","
			}
			if int64(len(encoded)+len(prefix)) > opts.MaxOutputBytes-written {
				coverage.Status = "partial"
				coverage.Diagnostics = append(coverage.Diagnostics, "Decoded strings output budget reached")
				break
			}
			_, err = writer.WriteString(prefix + string(encoded))
			written += int64(len(prefix) + len(encoded))
		}
		if err == nil {
			_, err = writer.WriteString("]")
		}
		if flushErr := writer.Flush(); err == nil {
			err = flushErr
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		return
	case bundleHermes:
		coverage.Kind, coverage.Mode, coverage.Version = "hermes_bytecode", "disassembly", HermesBytecodeVersion(data)
		coverage.Diagnostics = append(coverage.Diagnostics, "Hermes export is disassembly/metadata, not recovered JavaScript; bytecode patch/recompile is unsupported")
	default:
		coverage.Kind, coverage.Mode, coverage.Status = "unknown_binary", "none", "unsupported"
		coverage.Diagnostics = append(coverage.Diagnostics, "Not a text JS or supported Hermes bundle; original preserved, no fake JavaScript generated")
		return
	}
	index, parseErr := ParseHermesBytecode(data)
	if parseErr != nil {
		coverage.Status = "failed"
		if errors.Is(parseErr, ErrUnsupportedHermes) {
			coverage.Status = "unsupported"
		}
		coverage.Diagnostics = append(coverage.Diagnostics, parseErr.Error())
		return
	}
	coverage.Status = index.AnalysisStatus
	coverage.TotalStrings, coverage.ScannedStrings = int(index.Header.StringCount), len(index.Strings)
	coverage.Diagnostics = append(coverage.Diagnostics, index.Diagnostics...)
	if err = writeHermesMetadata(ctx, filepath.Join(output, "hermes.json"), index); err != nil {
		return
	}
	file, openErr := os.Create(filepath.Join(output, "hermes.disasm.txt"))
	if openErr != nil {
		err = openErr
		return
	}
	writer := bufio.NewWriterSize(file, 64<<10)
	c := &types.HermesExportCoverage{TotalFunctions: len(index.Functions), FunctionLimit: opts.MaxFunctions, BytecodeLimit: opts.MaxBytecodeBytes, InstructionLimit: opts.MaxInstructions, OutputLimit: opts.MaxOutputBytes}
	coverage.Export = c
	for _, fn := range index.Functions {
		c.TotalBytecodeBytes += uint64(fn.BytecodeSize)
	}
	write := func(line string) bool {
		if int64(len(line)) > opts.MaxOutputBytes-c.OutputBytes {
			c.LimitReason = "output_bytes"
			return false
		}
		n, writeErr := writer.WriteString(line)
		c.OutputBytes += int64(n)
		if writeErr != nil {
			err = writeErr
			return false
		}
		return true
	}
	write(fmt.Sprintf("Hermes bytecode v%d — DISASSEMBLY, NOT RECOVERED JAVASCRIPT\nString operands are previews (256 bytes); full strings are in hermes.json.\n", index.Header.Version))
	diagnostics := 0
exportLoop:
	for i, fn := range index.Functions {
		if err = ctx.Err(); err != nil {
			break
		}
		if i >= opts.MaxFunctions {
			c.LimitReason = "functions"
			break
		}
		if uint64(fn.BytecodeSize) > opts.MaxBytecodeBytes-c.DecodedBytecodeBytes {
			c.LimitReason = "bytecode_bytes"
			break
		}
		if c.Instructions >= opts.MaxInstructions && fn.BytecodeSize > 0 {
			c.LimitReason = "instructions"
			break
		}
		if !write(fmt.Sprintf("\nFunction %d %q params=%d registers=%d\n", fn.Index, hermesStringPreview(fn.Name), fn.ParamCount, fn.FrameSize)) {
			break
		}
		c.ScannedFunctions++
		decoded, decodeErr := index.DecodeFunction(uint32(i))
		for _, ins := range decoded {
			if c.Instructions >= opts.MaxInstructions {
				c.LimitReason = "instructions"
				break exportLoop
			}
			if c.Instructions%4096 == 0 {
				if err = ctx.Err(); err != nil {
					break exportLoop
				}
			}
			line := fmt.Sprintf("  %08x +%04x %-28s", ins.Offset, ins.FunctionOffset, ins.Name)
			for _, operand := range ins.Operands {
				line += fmt.Sprintf(" %s:%d", operand.Kind, operand.Value)
				if operand.Kind == "string_id" {
					if value, ok := index.StringByID(uint32(operand.Value)); ok {
						line += fmt.Sprintf("(%q)", hermesStringPreview(value.Value))
					}
				}
			}
			if !write(line + "\n") {
				break exportLoop
			}
			c.Instructions++
			c.DecodedBytecodeBytes += uint64(ins.Size)
		}
		if decodeErr != nil {
			c.FailedFunctions++
			coverage.Status = "partial"
			if !write(fmt.Sprintf("  INCOMPLETE: %v\n", decodeErr)) {
				break
			}
			if diagnostics < 32 {
				coverage.Diagnostics = append(coverage.Diagnostics, fmt.Sprintf("function %d: %v", i, decodeErr))
				diagnostics++
			}
		} else {
			c.DecodedFunctions++
		}
	}
	c.SkippedFunctions = c.TotalFunctions - c.ScannedFunctions
	if c.LimitReason != "" {
		coverage.Status = "partial"
		coverage.Diagnostics = append(coverage.Diagnostics, fmt.Sprintf("Disassembly limit reached: %s; decoded %d/%d functions, %d instructions, %d output bytes", c.LimitReason, c.DecodedFunctions, c.TotalFunctions, c.Instructions, c.OutputBytes))
	}
	if flushErr := writer.Flush(); err == nil {
		err = flushErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return
}

func hermesStringPreview(value string) string {
	if len(value) <= 256 {
		return value
	}
	return value[:256] + fmt.Sprintf("… [preview; %d bytes total]", len(value))
}

// Stream arrays item by item instead of allocating one huge indented JSON blob.
func writeHermesMetadata(ctx context.Context, path string, index *HermesIndex) (err error) {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := bufio.NewWriterSize(file, 64<<10)
	defer func() {
		if e := writer.Flush(); err == nil {
			err = e
		}
		if e := file.Close(); err == nil {
			err = e
		}
	}()
	encoder := json.NewEncoder(writer)
	if _, err = io.WriteString(writer, `{"header":`); err != nil {
		return
	}
	if err = encoder.Encode(index.Header); err != nil {
		return
	}
	array := func(name string, n int, item func(int) any) error {
		if _, err := fmt.Fprintf(writer, ",%q:[", name); err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			if i%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if i > 0 {
				if err := writer.WriteByte(','); err != nil {
					return err
				}
			}
			if err := encoder.Encode(item(i)); err != nil {
				return err
			}
		}
		return writer.WriteByte(']')
	}
	if err = array("strings", len(index.Strings), func(i int) any { return index.Strings[i] }); err != nil {
		return
	}
	if err = array("functions", len(index.Functions), func(i int) any { return index.Functions[i] }); err != nil {
		return
	}
	if err = array("modules", len(index.Modules), func(i int) any { return index.Modules[i] }); err != nil {
		return
	}
	_, err = io.WriteString(writer, `,"note":"Disassembly is not original JavaScript. Bytecode patch/recompile is unsupported."}`)
	return
}
