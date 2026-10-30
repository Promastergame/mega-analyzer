package apkloader

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

var (
	treeRegistersRe = regexp.MustCompile(`^\s*\.(registers|locals)\s+(\d+)`)
	treeVRegRe      = regexp.MustCompile(`\bv(\d+)\b`)
	treeLabelDefRe  = regexp.MustCompile(`^\s*(:[A-Za-z0-9_.$-]+)`) 
	treeLabelRefRe  = regexp.MustCompile(`:[A-Za-z0-9_.$-]+`)
	// Operand stripping for register detection: type descriptors and member
	// references routinely contain vN-shaped text (support/v4/app, ->v1:) that
	// is not a register operand.
	treeStringLitRe = regexp.MustCompile(`"[^"]*"`)
	treeDescRe      = regexp.MustCompile(`L[^;\s]*;`)
	treeMemberRe    = regexp.MustCompile(`->[A-Za-z0-9_$<>-]+:`)
)

// payloadBlocks are the data blocks whose bodies list label *references*.
// A ":label" line inside them is not a definition.
var payloadBlocks = map[string]bool{
	"array-data":    true,
	"packed-switch": true,
	"sparse-switch": true,
}

// operandRegisters strips type descriptors, member refs and string literals so
// only genuine register operands remain to be matched.
func operandRegisters(line string) string {
	line = treeStringLitRe.ReplaceAllString(line, `""`)
	line = treeDescRe.ReplaceAllString(line, `LX;`)
	return treeMemberRe.ReplaceAllString(line, `->m:`)
}

// ValidateSmaliTree performs a fast, deterministic preflight over all Apktool
// smali directories under sourceDir. It catches the common rebuild killers
// before spawning smali.jar, which makes errors faster and far more readable.
//
// Files are validated in parallel (a full APK tree is tens of thousands of
// smali files, so a serial scan dominates the preflight) and the resulting
// diagnostics are sorted by path/line to keep output deterministic.
func ValidateSmaliTree(sourceDir string) []Diagnostic {
	var paths []string
	_ = filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil { return nil }
		if d.IsDir() { return nil }
		if !strings.HasSuffix(strings.ToLower(path), ".smali") { return nil }
		paths = append(paths, path)
		return nil
	})
	if len(paths) == 0 {
		return nil
	}

	workers := runtime.NumCPU()
	if workers < 2 { workers = 2 }
	if workers > 8 { workers = 8 }
	if workers > len(paths) { workers = len(paths) }

	jobs := make(chan string, workers*4)
	var mu sync.Mutex
	var diags []Diagnostic
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				rel, relErr := filepath.Rel(sourceDir, path)
				if relErr != nil { rel = path }
				local := validateSmaliFile(path, filepath.ToSlash(rel))
				if len(local) == 0 { continue }
				mu.Lock()
				diags = append(diags, local...)
				mu.Unlock()
			}
		}()
	}
	for _, p := range paths { jobs <- p }
	close(jobs)
	wg.Wait()

	sort.Slice(diags, func(i, j int) bool {
		if diags[i].Path != diags[j].Path { return diags[i].Path < diags[j].Path }
		if diags[i].Line != diags[j].Line { return diags[i].Line < diags[j].Line }
		return diags[i].Code < diags[j].Code
	})
	return diags
}

func validateSmaliFile(path, rel string) []Diagnostic {
	f, err := os.Open(path)
	if err != nil { return []Diagnostic{{Code:"SMALI_READ_FAILED", Severity:DiagError, Stage:"smali_preflight", Path:rel, Message:err.Error()}} }
	defer f.Close()

	var diags []Diagnostic
	lineNo := 0
	hasClass, hasSuper := false, false
	inMethod := false
	methodStart := 0
	regs := -1
	maxV := -1
	labels := map[string]int{}
	refs := map[string]int{}
	blockStack := []struct{name string; line int}{}
	lastInvokeLine := -1000
	lastInsnLine := -1000

	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	s.Buffer(buf, 16*1024*1024)
	for s.Scan() {
		lineNo++
		raw := s.Text()
		line := strings.TrimSpace(stripSmaliComment(raw))
		if line == "" { continue }
		if strings.HasPrefix(line, ".class") { hasClass = true }
		if strings.HasPrefix(line, ".super") { hasSuper = true }
		if strings.HasPrefix(line, ".method") {
			if inMethod { diags = append(diags, Diagnostic{Code:"SMALI_NESTED_METHOD", Severity:DiagError, Stage:"smali_preflight", Path:rel, Line:lineNo, Message:".method started before previous .end method", Hint:fmt.Sprintf("close method started at line %d", methodStart)}) }
			inMethod = true; methodStart = lineNo; regs = -1; maxV = -1; labels = map[string]int{}; refs = map[string]int{}; lastInvokeLine = -1000; lastInsnLine = -1000
			continue
		}
		if strings.HasPrefix(line, ".end method") {
			if !inMethod { diags = append(diags, Diagnostic{Code:"SMALI_END_WITHOUT_METHOD", Severity:DiagError, Stage:"smali_preflight", Path:rel, Line:lineNo, Message:".end method without .method"}) } else {
				if regs >= 0 && maxV >= regs { diags = append(diags, Diagnostic{Code:"SMALI_REGISTER_OVERFLOW", Severity:DiagError, Stage:"smali_preflight", Path:rel, Line:methodStart, Message:fmt.Sprintf("v%d used but .registers/.locals declares %d", maxV, regs), Hint:fmt.Sprintf("increase register count to at least %d or reuse lower temp registers", maxV+1)}) }
				for ref, l := range refs { if _, ok := labels[ref]; !ok { diags = append(diags, Diagnostic{Code:"SMALI_MISSING_LABEL", Severity:DiagError, Stage:"smali_preflight", Path:rel, Line:l, Message:"branch references missing label " + ref}) } }
			}
			inMethod = false
			continue
		}
		if strings.HasPrefix(line, ".array-data") || strings.HasPrefix(line, ".packed-switch") || strings.HasPrefix(line, ".sparse-switch") || strings.HasPrefix(line, ".annotation") {
			blockStack = append(blockStack, struct{name string; line int}{strings.TrimPrefix(strings.Fields(line)[0], "."), lineNo})
		}
		if strings.HasPrefix(line, ".end ") && !strings.HasPrefix(line, ".end method") && len(blockStack)>0 { blockStack = blockStack[:len(blockStack)-1] }
		if inMethod {
			if m := treeRegistersRe.FindStringSubmatch(line); len(m)>0 { fmt.Sscanf(m[2], "%d", &regs) }
			for _, m := range treeVRegRe.FindAllStringSubmatch(operandRegisters(line), -1) { var n int; fmt.Sscanf(m[1], "%d", &n); if n>maxV { maxV=n } }
			inPayload := len(blockStack) > 0 && payloadBlocks[blockStack[len(blockStack)-1].name]
			if m := treeLabelDefRe.FindStringSubmatch(line); len(m)>0 && !inPayload { if prev, ok := labels[m[1]]; ok { diags = append(diags, Diagnostic{Code:"SMALI_DUPLICATE_LABEL", Severity:DiagError, Stage:"smali_preflight", Path:rel, Line:lineNo, Message:fmt.Sprintf("duplicate label %s, first seen at line %d", m[1], prev)}) }; labels[m[1]]=lineNo; continue }
			if strings.HasPrefix(line, "invoke-") || strings.HasPrefix(line, "filled-new-array") { lastInvokeLine = lineNo }
			if strings.HasPrefix(line, "move-result") && lastInsnLine != lastInvokeLine { diags = append(diags, Diagnostic{Code:"SMALI_BAD_MOVE_RESULT", Severity:DiagError, Stage:"smali_preflight", Path:rel, Line:lineNo, Message:"move-result* must immediately follow invoke-* or filled-new-array", Hint:"move or remove instructions between invoke and move-result"}) }
			if isBranchOpcode(line) { for _, ref := range treeLabelRefRe.FindAllString(treeStringLitRe.ReplaceAllString(line, `""`), -1) { refs[ref]=lineNo } }
			// Adjacency is measured in instructions, not physical lines:
			// baksmali emits blank lines and .line/.catch/.local directives
			// between the invoke and its move-result, and labels may legally
			// sit there too (labels already `continue` above).
			if !strings.HasPrefix(line, ".") { lastInsnLine = lineNo }
		}
	}
	if err := s.Err(); err != nil { diags = append(diags, Diagnostic{Code:"SMALI_SCAN_FAILED", Severity:DiagError, Stage:"smali_preflight", Path:rel, Message:err.Error()}) }
	if inMethod { diags = append(diags, Diagnostic{Code:"SMALI_MISSING_END_METHOD", Severity:DiagError, Stage:"smali_preflight", Path:rel, Line:methodStart, Message:"method has no .end method"}) }
	for _, b := range blockStack { diags = append(diags, Diagnostic{Code:"SMALI_UNCLOSED_BLOCK", Severity:DiagError, Stage:"smali_preflight", Path:rel, Line:b.line, Message:"unclosed ."+b.name+" block"}) }
	if !hasClass { diags = append(diags, Diagnostic{Code:"SMALI_MISSING_CLASS", Severity:DiagError, Stage:"smali_preflight", Path:rel, Message:"file has no .class directive"}) }
	if !hasSuper { diags = append(diags, Diagnostic{Code:"SMALI_MISSING_SUPER", Severity:DiagWarn, Stage:"smali_preflight", Path:rel, Message:"file has no .super directive"}) }
	return diags
}

func stripSmaliComment(s string) string {
	inString := false
	for i, r := range s {
		if r == '"' { inString = !inString }
		if r == '#' && !inString { return s[:i] }
	}
	return s
}

// isBranchOpcode reports whether the instruction on this line is a branch that
// takes a label operand. Only the opcode token is inspected: matching
// "-switch" anywhere in the line misfires on string constants such as
// "urn:mpeg:dash:adaptation-set-switching:2016".
func isBranchOpcode(line string) bool {
	op := line
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		op = line[:i]
	}
	return strings.HasPrefix(op, "goto") || strings.HasPrefix(op, "if-") ||
		op == "packed-switch" || op == "sparse-switch"
}
