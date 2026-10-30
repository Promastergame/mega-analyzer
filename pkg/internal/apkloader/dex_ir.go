package apkloader

import (
	"context"
	"sort"
	"strings"
)

// DEXReferenceSnapshot contains only table entries referenced by one method.
// Values are copied while the parser and its mmap are alive, so downstream
// workers never retain parser-backed pointers.
type DEXReferenceSnapshot struct {
	Strings map[uint32]string
	Types   map[uint32]string
	Fields  map[uint32]Field
	Methods map[uint32]Method
}

// OwnedDEXMethod is an immutable, worker-safe method input for Hyperion.
// Code and exception metadata are deep-copied before lazy class code is
// released. InvokeArgs preserves Dalvik call operands that MIR intentionally
// normalizes away.
type OwnedDEXMethod struct {
	MethodIdx        uint32
	ClassName        string
	MethodName       string
	ReturnType       string
	Parameters       []string
	AccessFlags      uint32
	RegistersSize    uint16
	InsSize          uint16
	OutsSize         uint16
	CodeUnits        []uint16
	RawInsns         []RawInsn
	InvokeArgs       map[uint32][]uint16
	Code             *CodeItem
	References       DEXReferenceSnapshot
	CandidateScore   int
	CandidateReasons []string
}

// DEXClassIR is the owned unit handed from the synchronous lazy parser to the
// bounded production class queue.
type DEXClassIR struct {
	ClassName string
	IR        []byte
	Methods   []OwnedDEXMethod
}

// OwnedDEXOptions controls cheap method triage performed during the single DEX
// parse. MinCandidateScore defaults to 2.
type OwnedDEXOptions struct {
	EnableHyperion         bool
	MinCandidateScore      int
	MaxReachableDepth      int
	MaxReachableMethods    int
	MaxOwnedCodeUnits      int
	MaxStaticFields        int
	MaxStaticArrayElements int
	MaxStaticBytes         int
	MaxEncodedValueDepth   int
	// SkipClassIR builds only the cross-class environment (callee resolver,
	// statics, initializers) without generating per-class IR text or
	// retaining class units. Used by the streaming path so peak memory stays
	// flat for huge DEX files instead of growing with the class count.
	SkipClassIR bool
}

// OwnedDEXBundle is finalized before deobfuscation workers start, making
// cross-class callees available without a second physical DEX parse.
type OwnedDEXBundle struct {
	Classes              []DEXClassIR
	Resolver             *OwnedMethodResolver
	Statics              *OwnedStaticResolver
	ClassInitializers    *OwnedClassInitResolver
	StaticReconstruction StaticReconstructionResult
}

// WalkDEXClassIRFile uses the production DEX parser (including mmap for large
// files) and emits bounded in-memory class streams.
func WalkDEXClassIRFile(ctx context.Context, path string, visit func(className, ir string) error) error {
	return WalkDEXClassIRFileBytes(ctx, path, func(className string, ir []byte) error {
		return visit(className, string(ir))
	})
}

// WalkDEXClassIRFileBytes uses the production DEX parser and streams class IR as raw byte slices.
func WalkDEXClassIRFileBytes(ctx context.Context, path string, visit func(className string, ir []byte) error) error {
	return WalkDEXClassIRFileBytesProgress(ctx, path, visit, nil)
}

// WalkDEXClassIRFileBytesProgress is the observable variant used by the
// streaming pipeline. progress receives generated/total class counts; the
// initial 0/total callback makes long DEX decoding visible before the first
// class is emitted.
func WalkDEXClassIRFileBytesProgress(
	ctx context.Context,
	path string,
	visit func(className string, ir []byte) error,
	progress func(done, total int),
) error {
	return WalkDEXClassOwnedFileProgress(ctx, path, OwnedDEXOptions{}, func(class DEXClassIR) error {
		return visit(class.ClassName, class.IR)
	}, progress)
}

// WalkDEXClassOwnedFileProgress parses a physical DEX exactly once and emits an
// owned class unit. Hyperion inputs are copied before lazy CodeItems are
// released; disabling Hyperion preserves the original textual-only cost.
func WalkDEXClassOwnedFileProgress(
	ctx context.Context,
	path string,
	options OwnedDEXOptions,
	visit func(class DEXClassIR) error,
	progress func(done, total int),
) error {
	parser, err := ParseDEXLazyFileContext(ctx, path)
	if err != nil {
		return err
	}
	defer parser.Close()
	return parser.WalkClassOwnedProgress(ctx, options, visit, progress)
}

// CollectDEXOwnedBundleFile parses a DEX once, finalizes bounded app-defined
// callee ownership, and only then returns worker-safe class units.
func CollectDEXOwnedBundleFile(ctx context.Context, path string, options OwnedDEXOptions, progress func(done, total int)) (*OwnedDEXBundle, error) {
	parser, err := ParseDEXLazyFileContext(ctx, path)
	if err != nil {
		return nil, err
	}
	defer parser.Close()
	return parser.CollectOwnedBundle(ctx, options, progress)
}

// WalkDEXClassIRBytes parses DEX bytes and emits one normalized, in-memory
// instruction stream per class. It never creates .smali files. The textual IR
// keeps the existing detector grammar while DEX remains the source of truth.
func WalkDEXClassIRBytes(ctx context.Context, data []byte, visit func(className, ir string) error) error {
	parser, err := ParseDEXBytesContext(ctx, data)
	if err != nil {
		return err
	}
	defer parser.Close()
	return parser.WalkClassIR(ctx, visit)
}

// CollectDEXOwnedBundleBytes parses one recovered DEX payload exactly once and
// finalizes its parser-detached bundle from the same in-memory parser.
func CollectDEXOwnedBundleBytes(ctx context.Context, data []byte, options OwnedDEXOptions, progress func(done, total int)) (*OwnedDEXBundle, error) {
	parser, err := ParseDEXBytesContext(ctx, data)
	if err != nil {
		return nil, err
	}
	defer parser.Close()
	return parser.CollectOwnedBundle(ctx, options, progress)
}

// WalkClassIR walks already parsed DEX classes without materialising a tree on
// disk. Streams are produced one class at a time to keep peak memory bounded.
func (p *DEXParser) WalkClassIR(ctx context.Context, visit func(className, ir string) error) error {
	return p.WalkClassIRBytes(ctx, func(className string, ir []byte) error {
		return visit(className, string(ir))
	})
}

// WalkClassIRBytes streams class IR directly as byte slices without intermediate string allocations.
func (p *DEXParser) WalkClassIRBytes(ctx context.Context, visit func(className string, ir []byte) error) error {
	return p.WalkClassIRBytesProgress(ctx, visit, nil)
}

// WalkClassIRBytesProgress streams class IR and reports bounded progress.
func (p *DEXParser) WalkClassIRBytesProgress(
	ctx context.Context,
	visit func(className string, ir []byte) error,
	progress func(done, total int),
) error {
	return p.WalkClassOwnedProgress(ctx, OwnedDEXOptions{}, func(class DEXClassIR) error {
		return visit(class.ClassName, class.IR)
	}, progress)
}

// WalkClassOwnedProgress is the parser-lifetime boundary for production DEX
// analysis. Everything in DEXClassIR owns its memory before releaseClassCode.
func (p *DEXParser) WalkClassOwnedProgress(
	ctx context.Context,
	options OwnedDEXOptions,
	visit func(class DEXClassIR) error,
	progress func(done, total int),
) error {
	if p == nil || visit == nil {
		return nil
	}
	if options.MinCandidateScore <= 0 {
		options.MinCandidateScore = 4
	}
	classes := p.GetClasses()
	total := 0
	for _, class := range classes {
		if class != nil && class.ClassName != "" {
			total++
		}
	}
	if progress != nil {
		progress(0, total)
	}
	done := 0
	for _, class := range classes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if class == nil || class.ClassName == "" {
			continue
		}
		unit := DEXClassIR{
			ClassName: cloneStr(class.ClassName),
			IR:        generateSmaliClassBytes(class, p),
		}
		if options.EnableHyperion {
			unit.Methods = p.liftOwnedCandidateMethods(class, options.MinCandidateScore)
			for i := range unit.Methods {
				detachOwnedDEXMethod(&unit.Methods[i])
			}
		}
		err := visit(unit)
		p.releaseClassCode(class)
		if err != nil {
			return err
		}
		done++
		if progress != nil {
			progress(done, total)
		}
	}
	return nil
}

// CollectOwnedBundle adds a deobfuscation-only phase barrier while the same
// parser remains alive. Textual IR and all selected method snapshots own their
// memory before parser-backed code is released.
// normalizeOwnedDEXOptions fills zero budgets with production defaults.
// Shared by CollectOwnedBundle and the streaming path so both agree on the
// candidate threshold and reachability budgets.
func normalizeOwnedDEXOptions(options OwnedDEXOptions) OwnedDEXOptions {
	if options.MinCandidateScore <= 0 {
		options.MinCandidateScore = 4
	}
	if options.MaxReachableDepth <= 0 {
		options.MaxReachableDepth = 3
	}
	if options.MaxReachableMethods <= 0 {
		options.MaxReachableMethods = 256
	}
	if options.MaxOwnedCodeUnits <= 0 {
		options.MaxOwnedCodeUnits = 1 << 20
	}
	if options.MaxStaticFields <= 0 {
		options.MaxStaticFields = 4096
	}
	if options.MaxStaticArrayElements <= 0 {
		options.MaxStaticArrayElements = 65536
	}
	if options.MaxStaticBytes <= 0 {
		options.MaxStaticBytes = 1 << 20
	}
	if options.MaxEncodedValueDepth <= 0 {
		options.MaxEncodedValueDepth = 8
	}
	return options
}

// OwnedEnvironment is the parser-detached, budget-bounded cross-class context
// (callee resolver, statics, initializers) shared by every class unit of one
// DEX. Unlike OwnedDEXBundle it carries no per-class IR text, so holding it
// while streaming classes keeps peak memory flat.
type OwnedEnvironment struct {
	Resolver             *OwnedMethodResolver
	Statics              *OwnedStaticResolver
	ClassInitializers    *OwnedClassInitResolver
	StaticReconstruction StaticReconstructionResult
}

// StreamOwnedBundleFile parses a DEX once and emits one owned class unit at a
// time. The cross-class environment is built first with bounded budgets; class
// IR text is generated per class and handed to emit, so a 6k-class DEX no
// longer materializes 100-200 MiB of IR strings before workers start.
func StreamOwnedBundleFile(ctx context.Context, path string, options OwnedDEXOptions, emit func(class DEXClassIR, env *OwnedEnvironment) error, progress func(done, total int)) error {
	parser, err := ParseDEXLazyFileContext(ctx, path)
	if err != nil {
		return err
	}
	defer parser.Close()
	return parser.StreamOwnedBundle(ctx, options, emit, progress)
}

// StreamOwnedBundleBytes is the in-memory counterpart for recovered DEX
// payloads (already size-capped by the caller).
func StreamOwnedBundleBytes(ctx context.Context, data []byte, options OwnedDEXOptions, emit func(class DEXClassIR, env *OwnedEnvironment) error, progress func(done, total int)) error {
	parser, err := ParseDEXBytesContext(ctx, data)
	if err != nil {
		return err
	}
	defer parser.Close()
	return parser.StreamOwnedBundle(ctx, options, emit, progress)
}

// StreamOwnedBundle builds the cross-class environment once, then streams
// class units one at a time. Parser-side method code is released after every
// class, so peak memory is bounded by the reachability budgets plus the
// in-flight classes in the consumer queue — not by the DEX class count.
func (p *DEXParser) StreamOwnedBundle(ctx context.Context, options OwnedDEXOptions, emit func(class DEXClassIR, env *OwnedEnvironment) error, progress func(done, total int)) error {
	if p == nil || emit == nil {
		return nil
	}
	options = normalizeOwnedDEXOptions(options)
	classes := p.GetClasses()
	total := 0
	for _, class := range classes {
		if class != nil && class.ClassName != "" {
			total++
		}
	}
	if progress != nil {
		progress(0, total)
	}
	envBundle, err := p.collectOwnedEnvironment(ctx, classes, options)
	if err != nil {
		return err
	}
	env := &OwnedEnvironment{
		Resolver:             envBundle.Resolver,
		Statics:              envBundle.Statics,
		ClassInitializers:    envBundle.ClassInitializers,
		StaticReconstruction: envBundle.StaticReconstruction,
	}
	done := 0
	for _, class := range classes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if class == nil || class.ClassName == "" {
			continue
		}
		// generateSmaliClassBytes returns a fresh buffer per call, so
		// ownership transfers to the consumer with no extra copy.
		unit := DEXClassIR{
			ClassName: cloneStr(class.ClassName),
			IR:        generateSmaliClassBytes(class, p),
		}
		if options.EnableHyperion {
			unit.Methods = p.liftOwnedCandidateMethods(class, options.MinCandidateScore)
			for i := range unit.Methods {
				detachOwnedDEXMethod(&unit.Methods[i])
			}
		}
		if err := emit(unit, env); err != nil {
			p.releaseClassCode(class)
			return err
		}
		p.releaseClassCode(class)
		done++
		if progress != nil {
			progress(done, total)
		}
	}
	return nil
}

// collectOwnedEnvironment runs the ownership, reachability and static phases
// without generating per-class IR text or retaining class units. Everything
// returned owns its memory and stays valid after the parser is closed.
func (p *DEXParser) collectOwnedEnvironment(ctx context.Context, classes []*ClassDef, options OwnedDEXOptions) (*OwnedDEXBundle, error) {
	env := &OwnedDEXBundle{}
	encoded := make(map[string]*EncodedMethod)
	for _, class := range classes {
		if class == nil {
			continue
		}
		for _, method := range append(append([]*EncodedMethod(nil), class.DirectMethods...), class.VirtualMethods...) {
			if method != nil {
				encoded[method.Descriptor()] = method
			}
		}
	}
	var roots []OwnedDEXMethod
	for _, class := range classes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if class == nil || class.ClassName == "" {
			continue
		}
		// No IR text here: candidate methods feed the cross-class roots and
		// are dropped right away; the streaming caller re-lifts per-class
		// methods on demand during emission.
		if options.EnableHyperion {
			roots = append(roots, p.liftOwnedCandidateMethods(class, options.MinCandidateScore)...)
		}
		p.releaseClassCode(class)
	}
	owned := append([]OwnedDEXMethod(nil), roots...)
	seen := make(map[string]struct{}, len(owned))
	for _, method := range owned {
		seen[method.Descriptor()] = struct{}{}
	}
	type pendingMethod struct {
		descriptor string
		depth      int
	}
	var pending []pendingMethod
	for _, root := range roots {
		for _, raw := range root.RawInsns {
			if raw.Op == 0x71 || raw.Op == 0x77 {
				if ref, ok := root.References.Methods[raw.RefIdx]; ok {
					pending = append(pending, pendingMethod{descriptor: ref.Descriptor(), depth: 1})
				}
			}
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].descriptor < pending[j].descriptor })
	codeUnits := 0
	for _, method := range owned {
		codeUnits += len(method.CodeUnits)
	}
	for len(pending) > 0 && len(owned) < options.MaxReachableMethods && codeUnits < options.MaxOwnedCodeUnits {
		item := pending[0]
		pending = pending[1:]
		if item.depth > options.MaxReachableDepth {
			continue
		}
		if _, ok := seen[item.descriptor]; ok {
			continue
		}
		method := encoded[item.descriptor]
		if method == nil || method.AccessFlags&accessFlagStatic == 0 {
			continue
		}
		code := method.EnsureCode()
		if code == nil || len(code.Insns) == 0 || codeUnits+len(code.Insns) > options.MaxOwnedCodeUnits {
			continue
		}
		raw := DecodeMethodIR(code.Insns, nil)
		callee := p.ownDEXMethod(method, code, raw, 0, nil)
		seen[item.descriptor] = struct{}{}
		owned = append(owned, callee)
		codeUnits += len(code.Insns)
		for _, insn := range callee.RawInsns {
			if insn.Op == 0x71 || insn.Op == 0x77 {
				if ref, ok := callee.References.Methods[insn.RefIdx]; ok {
					pending = append(pending, pendingMethod{descriptor: ref.Descriptor(), depth: item.depth + 1})
				}
			}
		}
		sort.Slice(pending, func(i, j int) bool { return pending[i].descriptor < pending[j].descriptor })
	}
	// Static field references activate their defining classes. Own every required
	// low-score <clinit>()V, its in-DEX superclass, and any exact invoke-static
	// helpers while the original parser is still alive.
	classIndex := make(map[string]*ClassDef, len(classes))
	for _, class := range classes {
		if class != nil && class.ClassName != "" {
			classIndex[class.ClassName] = class
		}
	}
	requiredClasses := make(map[string]struct{})
	classDependencies := make(map[string][]string)
	methodScan := 0
	for methodScan < len(owned) && len(owned) < options.MaxReachableMethods && codeUnits < options.MaxOwnedCodeUnits {
		method := owned[methodScan]
		methodScan++
		for _, raw := range method.RawInsns {
			if raw.Op >= 0x60 && raw.Op <= 0x6d {
				if field, ok := method.References.Fields[raw.RefIdx]; ok {
					if _, appDefined := classIndex[field.ClassName]; appDefined {
						requiredClasses[field.ClassName] = struct{}{}
					}
				}
			}
		}
	}
	processedClasses := make(map[string]struct{})
	for {
		classQueue := make([]string, 0, len(requiredClasses))
		for className := range requiredClasses {
			if _, done := processedClasses[className]; !done {
				classQueue = append(classQueue, className)
			}
		}
		sort.Strings(classQueue)
		if len(classQueue) == 0 {
			break
		}
		for _, className := range classQueue {
			processedClasses[className] = struct{}{}
			class := classIndex[className]
			if class == nil {
				continue
			}
			if class.SuperClass != "" {
				if _, appDefined := classIndex[class.SuperClass]; appDefined {
					requiredClasses[class.SuperClass] = struct{}{}
					classDependencies[className] = append(classDependencies[className], class.SuperClass)
				}
			}
			clinitDescriptor := MethodDescriptor(className, "<clinit>", nil, "V")
			initializer := encoded[clinitDescriptor]
			if initializer == nil {
				continue
			}
			if _, alreadyOwned := seen[clinitDescriptor]; alreadyOwned {
				continue
			}
			if len(owned) >= options.MaxReachableMethods {
				break
			}
			code := initializer.EnsureCode()
			if code == nil || len(code.Insns) == 0 || codeUnits+len(code.Insns) > options.MaxOwnedCodeUnits {
				continue
			}
			clinit := p.ownDEXMethod(initializer, code, DecodeMethodIR(code.Insns, nil), 0, []string{"required-class-initializer"})
			seen[clinitDescriptor] = struct{}{}
			owned = append(owned, clinit)
			codeUnits += len(code.Insns)
			for _, raw := range clinit.RawInsns {
				if raw.Op >= 0x60 && raw.Op <= 0x6d {
					if field, ok := clinit.References.Fields[raw.RefIdx]; ok {
						if _, appDefined := classIndex[field.ClassName]; appDefined && field.ClassName != className {
							requiredClasses[field.ClassName] = struct{}{}
							classDependencies[className] = append(classDependencies[className], field.ClassName)
						}
					}
				}
				if raw.Op == 0x71 || raw.Op == 0x77 {
					ref, ok := clinit.References.Methods[raw.RefIdx]
					if !ok {
						continue
					}
					descriptor := ref.Descriptor()
					if _, alreadyOwned := seen[descriptor]; alreadyOwned {
						continue
					}
					callee := encoded[descriptor]
					if callee == nil || callee.AccessFlags&accessFlagStatic == 0 || len(owned) >= options.MaxReachableMethods {
						continue
					}
					calleeCode := callee.EnsureCode()
					if calleeCode == nil || len(calleeCode.Insns) == 0 || codeUnits+len(calleeCode.Insns) > options.MaxOwnedCodeUnits {
						continue
					}
					ownedCallee := p.ownDEXMethod(callee, calleeCode, DecodeMethodIR(calleeCode.Insns, nil), 0, []string{"class-initializer-helper"})
					seen[descriptor] = struct{}{}
					owned = append(owned, ownedCallee)
					codeUnits += len(calleeCode.Insns)
				}
			}
		}
		for methodScan < len(owned) {
			method := owned[methodScan]
			methodScan++
			for _, raw := range method.RawInsns {
				if raw.Op >= 0x60 && raw.Op <= 0x6d {
					if field, ok := method.References.Fields[raw.RefIdx]; ok {
						if _, appDefined := classIndex[field.ClassName]; appDefined {
							requiredClasses[field.ClassName] = struct{}{}
						}
					}
				}
			}
		}
	}
	env.Resolver = NewOwnedMethodResolver(owned)
	classInits := make([]OwnedClassInit, 0, len(requiredClasses))
	for className := range requiredClasses {
		class := classIndex[className]
		if class == nil {
			continue
		}
		initializer := ""
		if _, ok := seen[MethodDescriptor(className, "<clinit>", nil, "V")]; ok {
			initializer = MethodDescriptor(className, "<clinit>", nil, "V")
		}
		classInits = append(classInits, OwnedClassInit{ClassName: className, SuperClass: class.SuperClass, Initializer: initializer, Dependencies: sortedUniqueStrings(classDependencies[className])})
	}
	env.ClassInitializers = NewOwnedClassInitResolver(classInits)
	staticValues := make(map[string]OwnedStaticValue)
	staticFields := 0
	for _, class := range classes {
		if class == nil || len(class.StaticFields) == 0 {
			continue
		}
		if staticFields+len(class.StaticFields) > options.MaxStaticFields {
			break
		}
		values, err := p.decodeStaticValues(class, options.MaxEncodedValueDepth, options.MaxStaticArrayElements, options.MaxStaticBytes)
		if err != nil {
			p.warnf("class %s static values: %v", class.ClassName, err)
			continue
		}
		for descriptor, value := range values {
			staticValues[descriptor] = value
		}
		staticFields += len(class.StaticFields)
	}
	env.StaticReconstruction = ReconstructStaticFieldsWithClasses(ctx, env.Resolver, env.ClassInitializers, NewOwnedStaticResolver(staticValues), DefaultDalvikEmulatorConfig())
	env.Statics = env.StaticReconstruction.Resolver
	for _, class := range classes {
		p.releaseClassCode(class)
	}
	detachOwnedEnvironment(&OwnedEnvironment{
		Resolver: env.Resolver,
		Statics:  env.Statics,
	})
	return env, nil
}

// CollectOwnedBundle adds a deobfuscation-only phase barrier while the same
// parser remains alive. Textual IR and all selected method snapshots own their
// memory before parser-backed code is released.
//
// NOTE: prefer StreamOwnedBundleFile/StreamOwnedBundleBytes for production
// scans — this collector retains every class IR at once and peak memory grows
// with the DEX class count. It stays for small recovered payloads and tests.
func (p *DEXParser) CollectOwnedBundle(ctx context.Context, options OwnedDEXOptions, progress func(done, total int)) (*OwnedDEXBundle, error) {
	if p == nil {
		return &OwnedDEXBundle{}, nil
	}
	options = normalizeOwnedDEXOptions(options)
	classes := p.GetClasses()
	env, err := p.collectOwnedEnvironment(ctx, classes, options)
	if err != nil {
		return nil, err
	}
	bundle := &OwnedDEXBundle{
		Classes:              make([]DEXClassIR, 0, len(classes)),
		Resolver:             env.Resolver,
		Statics:              env.Statics,
		ClassInitializers:    env.ClassInitializers,
		StaticReconstruction: env.StaticReconstruction,
	}
	for done, class := range classes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if class == nil || class.ClassName == "" {
			continue
		}
		unit := DEXClassIR{ClassName: class.ClassName, IR: generateSmaliClassBytes(class, p)}
		if options.EnableHyperion {
			unit.Methods = p.liftOwnedCandidateMethods(class, options.MinCandidateScore)
		}
		bundle.Classes = append(bundle.Classes, unit)
		p.releaseClassCode(class)
		if progress != nil {
			progress(done+1, len(classes))
		}
	}
	detachOwnedDEXBundle(bundle)
	return bundle, nil
}

func cloneStr(s string) string {
	if len(s) == 0 {
		return ""
	}
	return strings.Clone(s)
}

func detachOwnedDEXMethod(m *OwnedDEXMethod) {
	if m == nil {
		return
	}
	m.ClassName = cloneStr(m.ClassName)
	m.MethodName = cloneStr(m.MethodName)
	m.ReturnType = cloneStr(m.ReturnType)
	for i := range m.Parameters {
		m.Parameters[i] = cloneStr(m.Parameters[i])
	}
	for i := range m.CandidateReasons {
		m.CandidateReasons[i] = cloneStr(m.CandidateReasons[i])
	}
	for k, v := range m.References.Strings {
		m.References.Strings[k] = cloneStr(v)
	}
	for k, v := range m.References.Types {
		m.References.Types[k] = cloneStr(v)
	}
	for k, f := range m.References.Fields {
		f.ClassName = cloneStr(f.ClassName)
		f.FieldName = cloneStr(f.FieldName)
		f.TypeName = cloneStr(f.TypeName)
		m.References.Fields[k] = f
	}
	for k, meth := range m.References.Methods {
		meth.ClassName = cloneStr(meth.ClassName)
		meth.MethodName = cloneStr(meth.MethodName)
		meth.ReturnType = cloneStr(meth.ReturnType)
		for pIdx := range meth.Parameters {
			meth.Parameters[pIdx] = cloneStr(meth.Parameters[pIdx])
		}
		m.References.Methods[k] = meth
	}
}

func detachOwnedStaticValue(val *OwnedStaticValue) {
	if val == nil {
		return
	}
	val.TypeName = cloneStr(val.TypeName)
	val.String = cloneStr(val.String)
	for i := range val.Elements {
		detachOwnedStaticValue(&val.Elements[i])
	}
	for i := range val.Operations {
		val.Operations[i] = cloneStr(val.Operations[i])
	}
}

func detachOwnedDEXBundle(bundle *OwnedDEXBundle) {
	if bundle == nil {
		return
	}
	for i := range bundle.Classes {
		c := &bundle.Classes[i]
		c.ClassName = cloneStr(c.ClassName)
		for j := range c.Methods {
			detachOwnedDEXMethod(&c.Methods[j])
		}
	}
	env := &OwnedEnvironment{Resolver: bundle.Resolver, Statics: bundle.Statics}
	detachOwnedEnvironment(env)
	bundle.Resolver, bundle.Statics = env.Resolver, env.Statics
}

// detachOwnedEnvironment clones every string reachable from the resolvers so
// the environment stays valid after the parser (and its mmap) is closed.
// Idempotent: re-detaching only copies small strings again.
func detachOwnedEnvironment(env *OwnedEnvironment) {
	if env == nil {
		return
	}
	if env.Resolver != nil {
		methods := make([]OwnedDEXMethod, 0, env.Resolver.Len())
		for _, desc := range env.Resolver.Descriptors() {
			if m, ok := env.Resolver.Resolve(desc); ok {
				detachOwnedDEXMethod(&m)
				methods = append(methods, m)
			}
		}
		env.Resolver = NewOwnedMethodResolver(methods)
	}
	if env.Statics != nil {
		detachedStatics := make(map[string]OwnedStaticValue)
		for _, desc := range env.Statics.Descriptors() {
			if val, ok := env.Statics.Resolve(desc); ok {
				detachOwnedStaticValue(&val)
				detachedStatics[cloneStr(desc)] = val
			}
		}
		env.Statics = NewOwnedStaticResolver(detachedStatics)
	}
}

func (p *DEXParser) liftOwnedCandidateMethods(class *ClassDef, minScore int) []OwnedDEXMethod {
	methods := make([]OwnedDEXMethod, 0, len(class.DirectMethods)+len(class.VirtualMethods))
	all := make([]*EncodedMethod, 0, len(class.DirectMethods)+len(class.VirtualMethods))
	all = append(all, class.DirectMethods...)
	all = append(all, class.VirtualMethods...)
	for _, method := range all {
		if method == nil {
			continue
		}
		code := method.EnsureCode()
		if code == nil || len(code.Insns) == 0 {
			continue
		}
		raw := DecodeMethodIR(code.Insns, nil)
		score, reasons := scoreHyperionCandidate(raw)
		if score < minScore {
			continue
		}
		methods = append(methods, p.ownDEXMethod(method, code, raw, score, reasons))
	}
	return methods
}

func scoreMIR(ms []MIRInsn) (int, []string) {
	var constants, stringsCount, branches, invokes, arrays, arithmetic int
	for i := range ms {
		m := &ms[i]
		if m.Kind == MIR_CONST {
			constants++
			if m.ConstKind == ConstString || m.RefKind == RefString {
				stringsCount++
			}
		}
		if m.Kind == MIR_IF || m.Kind == MIR_GOTO || m.Kind == MIR_SWITCH {
			branches++
		}
		if m.Kind == MIR_INVOKE {
			invokes++
		}
		if m.Kind == MIR_ARRAY_GET || m.Kind == MIR_ARRAY_PUT || m.Kind == MIR_NEW_ARRAY || m.Kind == MIR_FILL_ARRAY || m.Kind == MIR_ARRAY_LENGTH {
			arrays++
		}
		if m.Kind == MIR_ADD || m.Kind == MIR_SUB || m.Kind == MIR_RSUB || m.Kind == MIR_MUL || m.Kind == MIR_DIV || m.Kind == MIR_REM ||
			m.Kind == MIR_AND || m.Kind == MIR_OR || m.Kind == MIR_XOR || m.Kind == MIR_SHL || m.Kind == MIR_SHR || m.Kind == MIR_USHR {
			arithmetic++
		}
	}
	score := 0
	reasons := make([]string, 0, 4)
	if stringsCount > 0 && invokes > 0 {
		score += 3
		reasons = append(reasons, "const-string+invoke")
	}
	if arrays > 0 && arithmetic > 0 {
		score += 3
		reasons = append(reasons, "array+arithmetic")
	}
	if branches > 0 && constants >= 2 {
		score += 2
		reasons = append(reasons, "constant-branch")
	}
	if branches >= 3 || arithmetic >= 4 {
		score++
		reasons = append(reasons, "control/data complexity")
	}
	return score, reasons
}

func scoreHyperionCandidate(raw []RawInsn) (int, []string) {
	mir := LowerToMIR(raw)
	return scoreMIR(mir)
}

func (p *DEXParser) ownDEXMethod(method *EncodedMethod, code *CodeItem, raw []RawInsn, score int, reasons []string) OwnedDEXMethod {
	ownedCode := cloneCodeItemMetadata(code)
	owned := OwnedDEXMethod{
		MethodIdx:        method.MethodIdx,
		ClassName:        method.ClassName,
		MethodName:       method.Name,
		ReturnType:       method.ReturnType,
		Parameters:       append([]string(nil), method.Parameters...),
		AccessFlags:      method.AccessFlags,
		RegistersSize:    code.RegistersSize,
		InsSize:          code.InsSize,
		OutsSize:         code.OutsSize,
		CodeUnits:        append([]uint16(nil), code.Insns...),
		RawInsns:         append([]RawInsn(nil), raw...),
		InvokeArgs:       make(map[uint32][]uint16),
		Code:             ownedCode,
		CandidateScore:   score,
		CandidateReasons: append([]string(nil), reasons...),
		References: DEXReferenceSnapshot{
			Strings: make(map[uint32]string),
			Types:   make(map[uint32]string),
			Fields:  make(map[uint32]Field),
			Methods: make(map[uint32]Method),
		},
	}
	for i := range owned.RawInsns {
		insn := &owned.RawInsns[i]
		if insn.IsInvoke() {
			owned.InvokeArgs[insn.Offset] = append([]uint16(nil), DecodeInvokeRegs(insn, code.Insns)...)
		}
		switch insn.RefKind {
		case RefString:
			owned.References.Strings[insn.RefIdx] = p.getString(insn.RefIdx)
		case RefType:
			owned.References.Types[insn.RefIdx] = p.getType(insn.RefIdx)
		case RefField:
			if insn.RefIdx < uint32(len(p.fields)) && p.fields[insn.RefIdx] != nil {
				owned.References.Fields[insn.RefIdx] = *p.fields[insn.RefIdx]
			}
		case RefMethod:
			if insn.RefIdx < uint32(len(p.methods)) && p.methods[insn.RefIdx] != nil {
				m := *p.methods[insn.RefIdx]
				m.Parameters = append([]string(nil), m.Parameters...)
				owned.References.Methods[insn.RefIdx] = m
			}
		}
	}
	return owned
}

func cloneCodeItemMetadata(code *CodeItem) *CodeItem {
	if code == nil {
		return nil
	}
	out := &CodeItem{
		RegistersSize: code.RegistersSize,
		InsSize:       code.InsSize,
		OutsSize:      code.OutsSize,
		TriesSize:     code.TriesSize,
		DebugInfoOff:  code.DebugInfoOff,
		InsnsSize:     code.InsnsSize,
		Tries:         make([]*TryItem, 0, len(code.Tries)),
		Handlers:      make([]*CatchHandler, 0, len(code.Handlers)),
	}
	handlerCopies := make(map[*CatchHandler]*CatchHandler, len(code.Handlers))
	cloneHandler := func(h *CatchHandler) *CatchHandler {
		if h == nil {
			return nil
		}
		if cloned, ok := handlerCopies[h]; ok {
			return cloned
		}
		cloned := *h
		handlerCopies[h] = &cloned
		return &cloned
	}
	for _, h := range code.Handlers {
		out.Handlers = append(out.Handlers, cloneHandler(h))
	}
	for _, tr := range code.Tries {
		if tr == nil {
			continue
		}
		cloned := *tr
		cloned.CatchHandlers = make([]*CatchHandler, 0, len(tr.CatchHandlers))
		for _, h := range tr.CatchHandlers {
			cloned.CatchHandlers = append(cloned.CatchHandlers, cloneHandler(h))
		}
		out.Tries = append(out.Tries, &cloned)
	}
	return out
}

func (p *DEXParser) releaseClassCode(class *ClassDef) {
	if p == nil || !p.lazyCode || class == nil {
		return
	}
	for _, method := range class.DirectMethods {
		method.Code = nil
	}
	for _, method := range class.VirtualMethods {
		method.Code = nil
	}
}
