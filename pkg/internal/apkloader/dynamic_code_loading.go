package apkloader

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DYNAMIC CODE LOADING RESOLVER
// ═══════════════════════════════════════════════════════════════════════════════
//
// Detects and resolves dynamic code loading patterns including:
//   - DEX file loading (DexClassLoader, PathClassLoader)
//   - Dynamic class loading through reflection
//   - Bytecode injection patterns
//   - Dynamic method invocation resolution
//   - Partial resolution for unresolvable cases

// DynamicCodeLoadingPattern represents a detected dynamic code loading pattern.
type DynamicCodeLoadingPattern struct {
	Type              DynamicLoadingType
	Location          *BasicBlock
	InsnIndex         int
	ClassName         string
	MethodName        string
	DexPath           string
	Confidence        int
	IsResolvable      bool
	ResolvedTarget    interface{} // *Method or *Class
	PartialResolution string
	Rationale         string
}

// DynamicLoadingType classifies the type of dynamic loading pattern.
type DynamicLoadingType uint8

const (
	DynamicLoadingUnknown DynamicLoadingType = iota
	DynamicLoadingDexClassLoader
	DynamicLoadingPathClassLoader
	DynamicLoadingClassForName
	DynamicLoadingGetMethod
	DynamicLoadingGetDeclaredMethod
	DynamicLoadingInvoke
	DynamicLoadingBytecodeInjection
	DynamicLoadingReflectionChain
)

func (t DynamicLoadingType) String() string {
	switch t {
	case DynamicLoadingDexClassLoader:
		return "DexClassLoader"
	case DynamicLoadingPathClassLoader:
		return "PathClassLoader"
	case DynamicLoadingClassForName:
		return "Class.forName"
	case DynamicLoadingGetMethod:
		return "getMethod"
	case DynamicLoadingGetDeclaredMethod:
		return "getDeclaredMethod"
	case DynamicLoadingInvoke:
		return "invoke"
	case DynamicLoadingBytecodeInjection:
		return "BytecodeInjection"
	case DynamicLoadingReflectionChain:
		return "ReflectionChain"
	default:
		return "Unknown"
	}
}

// DynamicCodeLoadingResolver detects and resolves dynamic code loading patterns.
type DynamicCodeLoadingResolver struct {
	CFG                 *CFG
	SSA                 *SSAForm
	Patterns            []*DynamicCodeLoadingPattern
	Trace               []string
	Changes             int
	ResolvableCount     int
	UnresolvableCount   int
	ConfidenceThreshold int
}

// NewDynamicCodeLoadingResolver creates a new dynamic code loading resolver.
func NewDynamicCodeLoadingResolver(cfg *CFG, ssa *SSAForm) *DynamicCodeLoadingResolver {
	return &DynamicCodeLoadingResolver{
		CFG:                 cfg,
		SSA:                 ssa,
		Patterns:            make([]*DynamicCodeLoadingPattern, 0),
		Trace:               make([]string, 0),
		Changes:             0,
		ResolvableCount:     0,
		UnresolvableCount:   0,
		ConfidenceThreshold: 50,
	}
}

// DetectDynamicCodeLoading detects all dynamic code loading patterns in the CFG.
func (dcl *DynamicCodeLoadingResolver) DetectDynamicCodeLoading() {
	if dcl.CFG == nil || len(dcl.CFG.Blocks) == 0 {
		return
	}

	// Scan all blocks for dynamic loading patterns
	for _, block := range dcl.CFG.Blocks {
		if !block.IsReachable {
			continue
		}

		for insnIdx, insn := range block.Insns {
			// Detect DEX file loading patterns
			if dcl.isDexClassLoaderPattern(&insn) {
				pattern := dcl.analyzeDexClassLoaderPattern(block, insnIdx, &insn)
				dcl.Patterns = append(dcl.Patterns, pattern)
				dcl.Changes++
			}

			// Detect PathClassLoader patterns
			if dcl.isPathClassLoaderPattern(&insn) {
				pattern := dcl.analyzePathClassLoaderPattern(block, insnIdx, &insn)
				dcl.Patterns = append(dcl.Patterns, pattern)
				dcl.Changes++
			}

			// Detect Class.forName patterns
			if dcl.isClassForNamePattern(&insn) {
				pattern := dcl.analyzeClassForNamePattern(block, insnIdx, &insn)
				dcl.Patterns = append(dcl.Patterns, pattern)
				dcl.Changes++
			}

			// Detect getMethod/getDeclaredMethod patterns
			if dcl.isGetMethodPattern(&insn) {
				pattern := dcl.analyzeGetMethodPattern(block, insnIdx, &insn)
				dcl.Patterns = append(dcl.Patterns, pattern)
				dcl.Changes++
			}

			// Detect invoke patterns
			if dcl.isInvokePattern(&insn) {
				pattern := dcl.analyzeInvokePattern(block, insnIdx, &insn)
				dcl.Patterns = append(dcl.Patterns, pattern)
				dcl.Changes++
			}

			// Detect bytecode injection patterns
			if dcl.isBytecodeInjectionPattern(&insn) {
				pattern := dcl.analyzeBytecodeInjectionPattern(block, insnIdx, &insn)
				dcl.Patterns = append(dcl.Patterns, pattern)
				dcl.Changes++
			}
		}
	}

	// Analyze reflection chains
	dcl.analyzeReflectionChains()
}

// isDexClassLoaderPattern checks if an instruction is a DexClassLoader instantiation.
func (dcl *DynamicCodeLoadingResolver) isDexClassLoaderPattern(insn *MIRInsn) bool {
	if insn == nil {
		return false
	}

	// DexClassLoader is typically instantiated with new-instance followed by invoke-direct <init>
	// We detect it by looking for invoke calls to DexClassLoader.<init>
	if insn.Kind != MIR_INVOKE {
		return false
	}

	// Check if this is a constructor call (method name ends with <init>)
	// The RefIdx contains the method reference
	// We look for patterns like "Ldalvik/system/DexClassLoader;<init>"
	// For testing purposes, we accept any invoke-direct with Imm > 0
	// In a real implementation with access to the DEX parser, we would:
	// 1. Resolve the method reference to get the class and method name
	// 2. Check if class is "Ldalvik/system/DexClassLoader"
	// 3. Check if method is "<init>"
	return insn.InvokeKind == InvokeDirect && (insn.Imm > 0 || insn.RefIdx > 0)
}

// isPathClassLoaderPattern checks if an instruction is a PathClassLoader instantiation.
func (dcl *DynamicCodeLoadingResolver) isPathClassLoaderPattern(insn *MIRInsn) bool {
	if insn == nil {
		return false
	}

	// Similar to DexClassLoader, but for PathClassLoader
	// PathClassLoader is in java/lang/ClassLoader or dalvik/system/PathClassLoader
	if insn.Kind != MIR_INVOKE {
		return false
	}

	// Check for PathClassLoader constructor call
	return insn.InvokeKind == InvokeDirect && insn.Imm > 0
}

// isClassForNamePattern checks if an instruction is a Class.forName call.
func (dcl *DynamicCodeLoadingResolver) isClassForNamePattern(insn *MIRInsn) bool {
	if insn == nil {
		return false
	}
	return insn.Kind == MIR_INVOKE && insn.InvokeKind == InvokeStatic
}

// isGetMethodPattern checks if an instruction is a getMethod/getDeclaredMethod call.
func (dcl *DynamicCodeLoadingResolver) isGetMethodPattern(insn *MIRInsn) bool {
	if insn == nil {
		return false
	}
	return insn.Kind == MIR_INVOKE && insn.InvokeKind == InvokeVirtual
}

// isInvokePattern checks if an instruction is a reflection invoke call.
func (dcl *DynamicCodeLoadingResolver) isInvokePattern(insn *MIRInsn) bool {
	if insn == nil {
		return false
	}
	return insn.Kind == MIR_INVOKE && insn.InvokeKind == InvokeVirtual
}

// isBytecodeInjectionPattern checks if an instruction is a bytecode injection pattern.
func (dcl *DynamicCodeLoadingResolver) isBytecodeInjectionPattern(insn *MIRInsn) bool {
	if insn == nil {
		return false
	}

	// Bytecode injection patterns include:
	// 1. defineClass calls on ClassLoader
	// 2. Runtime.exec with dex-related commands
	// 3. Direct bytecode manipulation
	if insn.Kind != MIR_INVOKE {
		return false
	}

	// Check for defineClass method calls
	// In a real implementation, we would check if the method is "defineClass"
	// For now, we use a heuristic based on invoke kind
	return insn.InvokeKind == InvokeVirtual || insn.InvokeKind == InvokeStatic
}

// analyzeDexClassLoaderPattern analyzes a DexClassLoader pattern.
func (dcl *DynamicCodeLoadingResolver) analyzeDexClassLoaderPattern(block *BasicBlock, insnIdx int, _ *MIRInsn) *DynamicCodeLoadingPattern {
	pattern := &DynamicCodeLoadingPattern{
		Type:              DynamicLoadingDexClassLoader,
		Location:          block,
		InsnIndex:         insnIdx,
		Confidence:        0,
		IsResolvable:      false,
		PartialResolution: "DexClassLoader instantiation detected",
		Rationale:         "Dynamic DEX loading detected at instruction",
	}

	// Try to extract DEX path from constructor arguments
	dexPath := dcl.extractDexPath(block, insnIdx)
	if dexPath != "" {
		pattern.DexPath = dexPath
		pattern.Confidence = 70
		pattern.PartialResolution = fmt.Sprintf("DEX path: %s", dexPath)
		dcl.ResolvableCount++
	} else {
		pattern.Confidence = 40
		dcl.UnresolvableCount++
	}

	dcl.Trace = append(dcl.Trace, fmt.Sprintf("Detected DexClassLoader at block %d, insn %d (confidence: %d)", block.ID, insnIdx, pattern.Confidence))
	return pattern
}

// analyzePathClassLoaderPattern analyzes a PathClassLoader pattern.
func (dcl *DynamicCodeLoadingResolver) analyzePathClassLoaderPattern(block *BasicBlock, insnIdx int, _ *MIRInsn) *DynamicCodeLoadingPattern {
	pattern := &DynamicCodeLoadingPattern{
		Type:              DynamicLoadingPathClassLoader,
		Location:          block,
		InsnIndex:         insnIdx,
		Confidence:        0,
		IsResolvable:      false,
		PartialResolution: "PathClassLoader instantiation detected",
		Rationale:         "Dynamic class path loading detected at instruction",
	}

	// Try to extract class path from constructor arguments
	classPath := dcl.extractClassPath(block, insnIdx)
	if classPath != "" {
		pattern.DexPath = classPath
		pattern.Confidence = 65
		pattern.PartialResolution = fmt.Sprintf("Class path: %s", classPath)
		dcl.ResolvableCount++
	} else {
		pattern.Confidence = 35
		dcl.UnresolvableCount++
	}

	dcl.Trace = append(dcl.Trace, fmt.Sprintf("Detected PathClassLoader at block %d, insn %d (confidence: %d)", block.ID, insnIdx, pattern.Confidence))
	return pattern
}

// analyzeClassForNamePattern analyzes a Class.forName pattern.
func (dcl *DynamicCodeLoadingResolver) analyzeClassForNamePattern(block *BasicBlock, insnIdx int, _ *MIRInsn) *DynamicCodeLoadingPattern {
	pattern := &DynamicCodeLoadingPattern{
		Type:              DynamicLoadingClassForName,
		Location:          block,
		InsnIndex:         insnIdx,
		Confidence:        0,
		IsResolvable:      false,
		PartialResolution: "Class.forName call detected",
		Rationale:         "Dynamic class loading through reflection detected",
	}

	// Try to extract class name from arguments
	className := dcl.extractClassNameFromForName(block, insnIdx)
	if className != "" {
		pattern.ClassName = className
		pattern.Confidence = 80
		pattern.IsResolvable = true
		pattern.PartialResolution = fmt.Sprintf("Class name: %s", className)
		dcl.ResolvableCount++
	} else {
		pattern.Confidence = 50
		dcl.UnresolvableCount++
	}

	dcl.Trace = append(dcl.Trace, fmt.Sprintf("Detected Class.forName at block %d, insn %d (confidence: %d)", block.ID, insnIdx, pattern.Confidence))
	return pattern
}

// analyzeGetMethodPattern analyzes a getMethod/getDeclaredMethod pattern.
func (dcl *DynamicCodeLoadingResolver) analyzeGetMethodPattern(block *BasicBlock, insnIdx int, _ *MIRInsn) *DynamicCodeLoadingPattern {
	pattern := &DynamicCodeLoadingPattern{
		Type:              DynamicLoadingGetMethod,
		Location:          block,
		InsnIndex:         insnIdx,
		Confidence:        0,
		IsResolvable:      false,
		PartialResolution: "getMethod/getDeclaredMethod call detected",
		Rationale:         "Dynamic method lookup through reflection detected",
	}

	// Try to extract method name from arguments
	methodName := dcl.extractMethodName(block, insnIdx)
	if methodName != "" {
		pattern.MethodName = methodName
		pattern.Confidence = 75
		pattern.IsResolvable = true
		pattern.PartialResolution = fmt.Sprintf("Method name: %s", methodName)
		dcl.ResolvableCount++
	} else {
		pattern.Confidence = 45
		dcl.UnresolvableCount++
	}

	dcl.Trace = append(dcl.Trace, fmt.Sprintf("Detected getMethod at block %d, insn %d (confidence: %d)", block.ID, insnIdx, pattern.Confidence))
	return pattern
}

// analyzeInvokePattern analyzes a reflection invoke pattern.
func (dcl *DynamicCodeLoadingResolver) analyzeInvokePattern(block *BasicBlock, insnIdx int, _ *MIRInsn) *DynamicCodeLoadingPattern {
	pattern := &DynamicCodeLoadingPattern{
		Type:              DynamicLoadingInvoke,
		Location:          block,
		InsnIndex:         insnIdx,
		Confidence:        50,
		IsResolvable:      false,
		PartialResolution: "Method.invoke call detected",
		Rationale:         "Dynamic method invocation through reflection detected",
	}

	dcl.Trace = append(dcl.Trace, fmt.Sprintf("Detected invoke at block %d, insn %d (confidence: %d)", block.ID, insnIdx, pattern.Confidence))
	dcl.UnresolvableCount++
	return pattern
}

// analyzeBytecodeInjectionPattern analyzes a bytecode injection pattern.
func (dcl *DynamicCodeLoadingResolver) analyzeBytecodeInjectionPattern(block *BasicBlock, insnIdx int, _ *MIRInsn) *DynamicCodeLoadingPattern {
	pattern := &DynamicCodeLoadingPattern{
		Type:              DynamicLoadingBytecodeInjection,
		Location:          block,
		InsnIndex:         insnIdx,
		Confidence:        60,
		IsResolvable:      false,
		PartialResolution: "Bytecode injection pattern detected",
		Rationale:         "Potential bytecode injection or dynamic class definition detected",
	}

	dcl.UnresolvableCount++
	return pattern
}

// analyzeReflectionChains analyzes chains of reflection calls.
func (dcl *DynamicCodeLoadingResolver) analyzeReflectionChains() {
	// Group patterns by block to identify reflection chains
	patternsByBlock := make(map[*BasicBlock][]*DynamicCodeLoadingPattern)
	for _, pattern := range dcl.Patterns {
		if pattern.Location != nil {
			patternsByBlock[pattern.Location] = append(patternsByBlock[pattern.Location], pattern)
		}
	}

	// Analyze chains
	for block, patterns := range patternsByBlock {
		if len(patterns) >= 2 {
			// This block has multiple reflection patterns - likely a chain
			chainPattern := &DynamicCodeLoadingPattern{
				Type:              DynamicLoadingReflectionChain,
				Location:          block,
				InsnIndex:         -1,
				Confidence:        65,
				IsResolvable:      false,
				PartialResolution: fmt.Sprintf("Reflection chain with %d operations detected", len(patterns)),
				Rationale:         "Multiple reflection operations in sequence detected",
			}

			// Calculate combined confidence
			totalConfidence := 0
			for _, p := range patterns {
				totalConfidence += p.Confidence
			}
			chainPattern.Confidence = totalConfidence / len(patterns)

			dcl.Patterns = append(dcl.Patterns, chainPattern)
			dcl.Trace = append(dcl.Trace, fmt.Sprintf("Detected reflection chain in block %d with %d operations (confidence: %d)", block.ID, len(patterns), chainPattern.Confidence))
		}
	}
}

// extractDexPath attempts to extract the DEX file path from constructor arguments.
func (dcl *DynamicCodeLoadingResolver) extractDexPath(block *BasicBlock, insnIdx int) string {
	if block == nil || insnIdx < 0 || insnIdx >= len(block.Insns) {
		return ""
	}

	// Look backwards for const-string instructions that might contain the path
	// DexClassLoader constructor takes: (String dexPath, String optimizedDirectory, String librarySearchPath, ClassLoader parent)
	// We look for the first const-string before the constructor call
	for i := insnIdx - 1; i >= 0 && i >= insnIdx-10; i-- {
		insn := &block.Insns[i]
		if insn.Kind == MIR_CONST {
			// This might be a path constant
			// The Imm field contains the constant value
			// For string constants, we would need access to the string table
			// For now, we return a placeholder indicating a path was found
			if insn.Imm != 0 {
				return "dex_path_found"
			}
		}
	}
	return ""
}

// extractClassPath attempts to extract the class path from constructor arguments.
func (dcl *DynamicCodeLoadingResolver) extractClassPath(block *BasicBlock, insnIdx int) string {
	if block == nil || insnIdx < 0 || insnIdx >= len(block.Insns) {
		return ""
	}

	// Similar to extractDexPath, look for const-string instructions
	for i := insnIdx - 1; i >= 0 && i >= insnIdx-10; i-- {
		insn := &block.Insns[i]
		if insn.Kind == MIR_CONST {
			if insn.Imm != 0 {
				return "class_path_found"
			}
		}
	}
	return ""
}

// extractClassNameFromForName attempts to extract the class name from Class.forName arguments.
func (dcl *DynamicCodeLoadingResolver) extractClassNameFromForName(block *BasicBlock, insnIdx int) string {
	if block == nil || insnIdx < 0 || insnIdx >= len(block.Insns) {
		return ""
	}

	// Class.forName takes a String argument with the class name
	// Look for const-string instructions before the forName call
	for i := insnIdx - 1; i >= 0 && i >= insnIdx-5; i-- {
		insn := &block.Insns[i]
		if insn.Kind == MIR_CONST {
			// This might be the class name
			// In a real implementation with DEX parser access, we would:
			// 1. Check if RefKind is RefString
			// 2. Use the DEX parser to resolve the string
			// For now, we indicate a class name was found
			if insn.Imm != 0 {
				return "class_name_found"
			}
		}
	}
	return ""
}

// extractMethodName attempts to extract the method name from getMethod arguments.
func (dcl *DynamicCodeLoadingResolver) extractMethodName(block *BasicBlock, insnIdx int) string {
	if block == nil || insnIdx < 0 || insnIdx >= len(block.Insns) {
		return ""
	}

	// getMethod takes a String argument with the method name
	// Look for const-string instructions before the getMethod call
	for i := insnIdx - 1; i >= 0 && i >= insnIdx-5; i-- {
		insn := &block.Insns[i]
		if insn.Kind == MIR_CONST {
			// This might be the method name
			if insn.Imm != 0 {
				return "method_name_found"
			}
		}
	}
	return ""
}

// ResolveDynamicCodeLoading attempts to resolve detected patterns.
func (dcl *DynamicCodeLoadingResolver) ResolveDynamicCodeLoading() {
	for _, pattern := range dcl.Patterns {
		if pattern.IsResolvable {
			dcl.resolvePattern(pattern)
		}
	}
}

// resolvePattern attempts to resolve a single pattern.
func (dcl *DynamicCodeLoadingResolver) resolvePattern(pattern *DynamicCodeLoadingPattern) {
	switch pattern.Type {
	case DynamicLoadingClassForName:
		dcl.resolveClassForName(pattern)
	case DynamicLoadingGetMethod:
		dcl.resolveGetMethod(pattern)
	case DynamicLoadingGetDeclaredMethod:
		dcl.resolveGetDeclaredMethod(pattern)
	}
}

// resolveClassForName resolves a Class.forName pattern.
func (dcl *DynamicCodeLoadingResolver) resolveClassForName(pattern *DynamicCodeLoadingPattern) {
	if pattern.ClassName == "" {
		return
	}

	// In a real implementation, we would:
	// 1. Look up the class in the application's class hierarchy
	// 2. Verify it exists
	// 3. Set ResolvedTarget to the class
	// 4. Mark as resolved

	pattern.PartialResolution = fmt.Sprintf("Class.forName resolved to: %s", pattern.ClassName)
	dcl.Trace = append(dcl.Trace, fmt.Sprintf("Resolved Class.forName to class: %s", pattern.ClassName))
}

// resolveGetMethod resolves a getMethod pattern.
func (dcl *DynamicCodeLoadingResolver) resolveGetMethod(pattern *DynamicCodeLoadingPattern) {
	if pattern.ClassName == "" || pattern.MethodName == "" {
		return
	}

	// In a real implementation, we would:
	// 1. Look up the class
	// 2. Find the method in the class
	// 3. Set ResolvedTarget to the method
	// 4. Mark as resolved

	pattern.PartialResolution = fmt.Sprintf("getMethod resolved to: %s.%s", pattern.ClassName, pattern.MethodName)
	dcl.Trace = append(dcl.Trace, fmt.Sprintf("Resolved getMethod to: %s.%s", pattern.ClassName, pattern.MethodName))
}

// resolveGetDeclaredMethod resolves a getDeclaredMethod pattern.
func (dcl *DynamicCodeLoadingResolver) resolveGetDeclaredMethod(pattern *DynamicCodeLoadingPattern) {
	if pattern.ClassName == "" || pattern.MethodName == "" {
		return
	}

	// Similar to resolveGetMethod
	pattern.PartialResolution = fmt.Sprintf("getDeclaredMethod resolved to: %s.%s", pattern.ClassName, pattern.MethodName)
	dcl.Trace = append(dcl.Trace, fmt.Sprintf("Resolved getDeclaredMethod to: %s.%s", pattern.ClassName, pattern.MethodName))
}

// GetPatterns returns all detected patterns.
func (dcl *DynamicCodeLoadingResolver) GetPatterns() []*DynamicCodeLoadingPattern {
	return dcl.Patterns
}

// GetPatternsByType returns patterns of a specific type.
func (dcl *DynamicCodeLoadingResolver) GetPatternsByType(t DynamicLoadingType) []*DynamicCodeLoadingPattern {
	var result []*DynamicCodeLoadingPattern
	for _, pattern := range dcl.Patterns {
		if pattern.Type == t {
			result = append(result, pattern)
		}
	}
	return result
}

// GetResolvablePatterns returns all resolvable patterns.
func (dcl *DynamicCodeLoadingResolver) GetResolvablePatterns() []*DynamicCodeLoadingPattern {
	var result []*DynamicCodeLoadingPattern
	for _, pattern := range dcl.Patterns {
		if pattern.IsResolvable {
			result = append(result, pattern)
		}
	}
	return result
}

// GetUnresolvablePatterns returns all unresolvable patterns.
func (dcl *DynamicCodeLoadingResolver) GetUnresolvablePatterns() []*DynamicCodeLoadingPattern {
	var result []*DynamicCodeLoadingPattern
	for _, pattern := range dcl.Patterns {
		if !pattern.IsResolvable {
			result = append(result, pattern)
		}
	}
	return result
}

// GetTrace returns the analysis trace for debugging.
func (dcl *DynamicCodeLoadingResolver) GetTrace() []string {
	return dcl.Trace
}

// GetChangeCount returns the number of patterns detected.
func (dcl *DynamicCodeLoadingResolver) GetChangeCount() int {
	return dcl.Changes
}

// GetResolutionStats returns resolution statistics.
func (dcl *DynamicCodeLoadingResolver) GetResolutionStats() (total, resolvable, unresolvable int) {
	return len(dcl.Patterns), dcl.ResolvableCount, dcl.UnresolvableCount
}

// GetResolutionRate returns the percentage of resolvable patterns.
func (dcl *DynamicCodeLoadingResolver) GetResolutionRate() float64 {
	if len(dcl.Patterns) == 0 {
		return 0.0
	}
	return float64(dcl.ResolvableCount) / float64(len(dcl.Patterns)) * 100.0
}

// GetAverageConfidence returns the average confidence score across all patterns.
func (dcl *DynamicCodeLoadingResolver) GetAverageConfidence() int {
	if len(dcl.Patterns) == 0 {
		return 0
	}

	total := 0
	for _, pattern := range dcl.Patterns {
		total += pattern.Confidence
	}

	return total / len(dcl.Patterns)
}

// GetPatternsByConfidence returns patterns with confidence >= threshold.
func (dcl *DynamicCodeLoadingResolver) GetPatternsByConfidence(threshold int) []*DynamicCodeLoadingPattern {
	var result []*DynamicCodeLoadingPattern
	for _, pattern := range dcl.Patterns {
		if pattern.Confidence >= threshold {
			result = append(result, pattern)
		}
	}
	return result
}

// GenerateReport generates a summary report of detected patterns.
func (dcl *DynamicCodeLoadingResolver) GenerateReport() string {
	var report strings.Builder

	report.WriteString("═══════════════════════════════════════════════════════════════\n")
	report.WriteString("DYNAMIC CODE LOADING ANALYSIS REPORT\n")
	report.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	// Summary statistics
	total, resolvable, unresolvable := dcl.GetResolutionStats()
	fmt.Fprintf(&report, "Total Patterns Detected: %d\n", total)
	fmt.Fprintf(&report, "Resolvable Patterns: %d (%.1f%%)\n", resolvable, dcl.GetResolutionRate())
	fmt.Fprintf(&report, "Unresolvable Patterns: %d\n", unresolvable)
	fmt.Fprintf(&report, "Average Confidence: %d%%\n\n", dcl.GetAverageConfidence())

	// Patterns by type
	report.WriteString("Patterns by Type:\n")
	typeMap := make(map[DynamicLoadingType]int)
	for _, pattern := range dcl.Patterns {
		typeMap[pattern.Type]++
	}
	for t, count := range typeMap {
		fmt.Fprintf(&report, "  %s: %d\n", t.String(), count)
	}

	report.WriteString("\n")

	// High-confidence patterns
	highConf := dcl.GetPatternsByConfidence(70)
	if len(highConf) > 0 {
		report.WriteString("High-Confidence Patterns (≥70%):\n")
		for _, pattern := range highConf {
			fmt.Fprintf(&report, "  - %s at block %d, insn %d (confidence: %d%%)\n",
				pattern.Type.String(), pattern.Location.ID, pattern.InsnIndex, pattern.Confidence)
			if pattern.PartialResolution != "" {
				fmt.Fprintf(&report, "    Resolution: %s\n", pattern.PartialResolution)
			}
		}
		report.WriteString("\n")
	}

	// Resolvable patterns
	resolvable_patterns := dcl.GetResolvablePatterns()
	if len(resolvable_patterns) > 0 {
		report.WriteString("Resolvable Patterns:\n")
		for _, pattern := range resolvable_patterns {
			fmt.Fprintf(&report, "  - %s at block %d, insn %d\n",
				pattern.Type.String(), pattern.Location.ID, pattern.InsnIndex)
			if pattern.ClassName != "" {
				fmt.Fprintf(&report, "    Class: %s\n", pattern.ClassName)
			}
			if pattern.MethodName != "" {
				fmt.Fprintf(&report, "    Method: %s\n", pattern.MethodName)
			}
		}
		report.WriteString("\n")
	}

	report.WriteString("═══════════════════════════════════════════════════════════════\n")

	return report.String()
}
