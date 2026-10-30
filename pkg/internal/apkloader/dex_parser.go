package apkloader

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// ═══════════════════════════════════════════════════════════════
// КОНСТАНТЫ
// ═══════════════════════════════════════════════════════════════

const (
	dexMagic0 = 'd'
	dexMagic1 = 'e'
	dexMagic2 = 'x'
	dexMagic3 = '\n'

	dexHeaderSize   = 0x70
	dexEndianTag    = 0x12345678
	dexNoIndex      = uint32(0xFFFFFFFF)
	maxStringLen    = 1_000_000
	maxSectionItems = 200_000 // защита от OOM при повреждённых файлах

	// Максимальная разумная ёмкость одного make([]T, n) относительно файла.
	// Используется как sanity-check: count * minItemSize <= len(data).
	minStringItemSize = 1 // хотя бы 1 байт на строку (терминатор)
	minTypeItemSize   = 4 // 4 байта на string_idx
	minProtoItemSize  = 12
	minFieldItemSize  = 8
	minMethodItemSize = 8
	minClassItemSize  = 32
)

// ═══════════════════════════════════════════════════════════════
// МЕТРИКИ
// ═══════════════════════════════════════════════════════════════

// ParseMetrics содержит статистику парсинга.
type ParseMetrics struct {
	ParseDuration    time.Duration
	StringsCount     int
	TypesCount       int
	ProtosCount      int
	FieldsCount      int
	MethodsCount     int
	ClassesCount     int
	WarningsCount    int
	TotalCodeBytes   int64
	InstructionCount int64
}

// ═══════════════════════════════════════════════════════════════
// СТРУКТУРЫ
// ═══════════════════════════════════════════════════════════════

// DEXParser — высокопроизводительный, потокобезопасный парсер DEX.
// После завершения Parse безопасен для конкурентного чтения.
type DEXParser struct {
	data       []byte // неизменяем после создания
	mmapReader *MmapDEXReader
	// mapped=true, когда data указывает в mmap-регион, управляемый
	// mmapReader. Строки, возвращаемые наружу (p.strings и имена классов),
	// обязаны копироваться: после Close() регион размаплен, и zero-copy
	// строки превратились бы в use-after-free.
	mapped bool

	// Header
	version       string
	fileSize      uint32
	headerSize    uint32
	endianTag     uint32
	stringIDsSize uint32
	stringIDsOff  uint32
	typeIDsSize   uint32
	typeIDsOff    uint32
	protoIDsSize  uint32
	protoIDsOff   uint32
	fieldIDsSize  uint32
	fieldIDsOff   uint32
	methodIDsSize uint32
	methodIDsOff  uint32
	classDefsSize uint32
	classDefsOff  uint32

	// Parsed sections
	strings       []string
	types         []string
	protos        []*Proto
	fields        []*Field
	methods       []*Method
	classes       []*ClassDef
	methodHandles []DEXMethodHandle
	callSites     [][]DEXValue

	// Lazy search indexes
	classIndex      map[string]*ClassDef
	methodIndex     map[string][]*Method
	classIndexOnce  sync.Once
	methodIndexOnce sync.Once
	dexHash         string
	dexHashOnce     sync.Once

	// Warnings — только под warningsMu
	warningsMu sync.Mutex
	warnings   []string

	// Lazy loading (v11.0)
	lazyCode bool // если true, байткод методов не парсится сразу

	// Метрики парсинга
	Metrics ParseMetrics
}

// Proto описывает прототип метода.
type Proto struct {
	ShortyIdx     uint32
	ReturnTypeIdx uint32
	ParametersOff uint32
	Shorty        string
	ReturnType    string
	Parameters    []string
}

// Field описывает поле.
type Field struct {
	ClassIdx  uint16
	TypeIdx   uint16
	NameIdx   uint32
	ClassName string
	TypeName  string
	FieldName string
}

// Method описывает метод.
type Method struct {
	ClassIdx   uint16
	ProtoIdx   uint16
	NameIdx    uint32
	ClassName  string
	MethodName string
	ReturnType string
	Parameters []string
}

// ClassDef описывает класс.
type ClassDef struct {
	ClassIdx        uint32
	AccessFlags     uint32
	SuperclassIdx   uint32
	InterfacesOff   uint32
	SourceFileIdx   uint32
	AnnotationsOff  uint32
	ClassDataOff    uint32
	StaticValuesOff uint32

	ClassName      string
	SuperClass     string
	SourceFile     string
	Interfaces     []string
	StaticFields   []*EncodedField
	InstanceFields []*EncodedField
	DirectMethods  []*EncodedMethod
	VirtualMethods []*EncodedMethod
	Annotations    []DEXAnnotation
}

// EncodedField — поле с флагами доступа.
type EncodedField struct {
	FieldIdx     uint32
	AccessFlags  uint32
	Name         string
	TypeName     string
	ClassName    string
	InitialValue *DEXValue
	Annotations  []DEXAnnotation
}

// EncodedMethod — метод с байткодом.
type EncodedMethod struct {
	MethodIdx            uint32
	AccessFlags          uint32
	CodeOff              uint32
	Name                 string
	ClassName            string
	ReturnType           string
	Parameters           []string
	Code                 *CodeItem
	Annotations          []DEXAnnotation
	ParameterAnnotations [][]DEXAnnotation

	// Lazy loading support (v11.0)
	parser   *DEXParser // back-reference for on-demand code loading
	codeOnce sync.Once  // ensures code is parsed exactly once
}

// CodeItem — байткод метода.
type CodeItem struct {
	RegistersSize  uint16
	InsSize        uint16
	OutsSize       uint16
	TriesSize      uint16
	DebugInfoOff   uint32
	InsnsSize      uint32
	Insns          []uint16
	Tries          []*TryItem
	Handlers       []*CatchHandler
	PayloadOffsets map[uint32]bool
}

// TryItem — блок try.
type TryItem struct {
	StartAddr     uint32
	InsnCount     uint16
	HandlerOff    uint16
	CatchHandlers []*CatchHandler
}

// CatchHandler — обработчик исключения.
type CatchHandler struct {
	TypeIdx      int32
	TypeName     string
	HandlerAddr  uint32
	CatchAllAddr uint32
	HasCatchAll  bool
}

// sectionRange — диапазон для проверки перекрытий.
type sectionRange struct {
	name  string
	start uint64
	end   uint64
}

// ═══════════════════════════════════════════════════════════════
// ПУЛЫ БУФЕРОВ
// ═══════════════════════════════════════════════════════════════

var builderPool = sync.Pool{
	New: func() interface{} {
		b := new(strings.Builder)
		b.Grow(256)
		return b
	},
}

func getBuilder() *strings.Builder {
	return builderPool.Get().(*strings.Builder)
}

// putBuilder сбрасывает буфер перед возвратом в пул.
// Сброс делается здесь — не в getBuilder — чтобы данные не висели
// в памяти пока объект находится в пуле.
func putBuilder(b *strings.Builder) {
	if b.Cap() > 65536 {
		return // не возвращаем огромные буферы
	}
	b.Reset() // ← сброс перед помещением в пул
	builderPool.Put(b)
}

// ═══════════════════════════════════════════════════════════════
// ТОЧКИ ВХОДА
// ═══════════════════════════════════════════════════════════════

// ParseDEX читает DEX-файл по пути.
func ParseDEX(filePath string) (*DEXParser, error) {
	return ParseDEXContext(context.Background(), filePath)
}

// ParseDEXContext — ParseDEX с поддержкой отмены.
func ParseDEXContext(ctx context.Context, filePath string) (*DEXParser, error) {
	return parseDEXFileContext(ctx, filePath, false)
}

// ParseDEXLazyFileContext opens a DEX using mmap when possible and indexes
// method code offsets without materializing every CodeItem.
func ParseDEXLazyFileContext(ctx context.Context, filePath string) (*DEXParser, error) {
	return parseDEXFileContext(ctx, filePath, true)
}

func parseDEXFileContext(ctx context.Context, filePath string, lazy bool) (*DEXParser, error) {
	const mmapParseThreshold = 1 << 20
	if info, statErr := os.Stat(filePath); statErr == nil && info.Size() >= mmapParseThreshold {
		reader, mapErr := NewMmapDEXReader(filePath)
		if mapErr == nil {
			parser, parseErr := parseDEXInternal(ctx, reader.Data(), lazy, true)
			if parseErr != nil {
				_ = reader.Close()
				return nil, parseErr
			}
			parser.mmapReader = reader
			return parser, nil
		}
	}

	// mmap can be unavailable on restricted or unusual filesystems. Preserve a
	// heap fallback so parsing still works everywhere.
	data, readErr := os.ReadFile(filePath)
	if readErr != nil {
		return nil, fmt.Errorf("read dex %q: %w", filePath, readErr)
	}
	return parseDEXInternal(ctx, data, lazy, false)
}

// Close releases a file mapping owned by a path-based parser. Parsers created
// from byte slices do not own external resources and Close is a no-op.
func (p *DEXParser) Close() error {
	if p == nil || p.mmapReader == nil {
		return nil
	}
	err := p.mmapReader.Close()
	p.mmapReader = nil
	return err
}

// ParseDEXBytes парсит DEX из байтового среза.
func ParseDEXBytes(data []byte) (*DEXParser, error) {
	return ParseDEXBytesContext(context.Background(), data)
}

// ParseDEXBytesContext — ParseDEXBytes с поддержкой отмены.
func ParseDEXBytesContext(ctx context.Context, data []byte) (*DEXParser, error) {
	return parseDEXInternal(ctx, data, false, false)
}

// ParseDEXLazy — парсит DEX в режиме Index-Only (v11.0).
// Байт-код методов НЕ загружается сразу — только при обращении через EnsureCode().
// Экономит сотни МБ RAM на больших APK, где анализируется лишь 5% кода.
func ParseDEXLazy(ctx context.Context, data []byte) (*DEXParser, error) {
	return parseDEXInternal(ctx, data, true, false)
}

func parseDEXInternal(ctx context.Context, data []byte, lazy, mapped bool) (*DEXParser, error) {
	start := time.Now()

	if len(data) < dexHeaderSize {
		return nil, errDexTooSmall
	}
	if data[0] != dexMagic0 || data[1] != dexMagic1 ||
		data[2] != dexMagic2 || data[3] != dexMagic3 {
		return nil, errDexBadMagic
	}

	p := &DEXParser{
		data:     data,
		mapped:   mapped,
		warnings: make([]string, 0, 8),
		lazyCode: lazy,
	}
	p.version = strings.TrimRight(string(data[4:7]), "\x00")

	if err := p.parseHeader(); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	if err := p.validateHeader(); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.parseSections(ctx); err != nil {
		return nil, err
	}

	p.Metrics.ParseDuration = time.Since(start)
	p.Metrics.StringsCount = len(p.strings)
	p.Metrics.TypesCount = len(p.types)
	p.Metrics.ProtosCount = len(p.protos)
	p.Metrics.FieldsCount = len(p.fields)
	p.Metrics.MethodsCount = len(p.methods)
	p.Metrics.ClassesCount = len(p.classes)

	p.warningsMu.Lock()
	p.Metrics.WarningsCount = len(p.warnings)
	p.warningsMu.Unlock()

	return p, nil
}

// ═══════════════════════════════════════════════════════════════
// ПАРАЛЛЕЛЬНЫЙ ПАРСИНГ СЕКЦИЙ
// ═══════════════════════════════════════════════════════════════

// parseSections запускает секции по волнам зависимостей.
//
// Граф зависимостей:
//
//	strings ──┐
//	          ├──▶ protos ──┐
//	types ────┤             ├──▶ classes ──▶ class_data
//	          ├──▶ fields ──┤
//	          └──▶ methods ─┘  (methods зависит от protos)
//
// Волна 1: strings + types (параллельно, независимы)
// Волна 2: protos + fields  (параллельно, зависят от strings+types)
// Волна 3: methods          (зависит от protos)
// Волна 4: classes          (зависит от types+strings)
// Волна 5: class_data       (зависит от classes+fields+methods)
func (p *DEXParser) parseSections(ctx context.Context) error {
	// Wave 1: strings → types (sequential: types reads p.strings)
	if err := p.parseStrings(ctx); err != nil {
		return fmt.Errorf("strings: %w", err)
	}
	if err := p.parseTypes(ctx); err != nil {
		return fmt.Errorf("types: %w", err)
	}

	// Wave 2: protos + fields parallel (both depend only on strings+types)
	if err := p.runParallel(ctx,
		func() error { return p.parseProtos(ctx) },
		func() error { return p.parseFields(ctx) },
	); err != nil {
		return err
	}

	// Wave 3: methods (needs protos)
	if err := p.parseMethods(ctx); err != nil {
		return fmt.Errorf("methods: %w", err)
	}
	if err := p.parseExtendedTables(); err != nil {
		return fmt.Errorf("extended tables: %w", err)
	}

	// Wave 4: classes (needs strings+types)
	if err := p.parseClasses(ctx); err != nil {
		return fmt.Errorf("classes: %w", err)
	}

	// Wave 5: class data — parallel worker pool (each class is independent)
	if err := p.parseAllClassData(ctx); err != nil {
		return fmt.Errorf("class_data: %w", err)
	}
	for _, c := range p.classes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.parseClassMetadata(c); err != nil {
			return fmt.Errorf("metadata %s: %w", c.ClassName, err)
		}
	}

	return nil
}

// runParallel запускает фунции параллельно через WaitGroup.
// Возвращает первую возникшую ошибку; ждёт завершения всех горутин.
func (p *DEXParser) runParallel(ctx context.Context, fns ...func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)

	for _, fn := range fns {
		fn := fn
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return firstErr
}

// ═══════════════════════════════════════════════════════════════
// ЗАГОЛОВОК И ВАЛИДАЦИЯ
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) parseHeader() error {
	d := p.data

	p.fileSize = leU32(d, 32)
	p.headerSize = leU32(d, 36)
	p.endianTag = leU32(d, 40)

	p.stringIDsSize = leU32(d, 56)
	p.stringIDsOff = leU32(d, 60)
	p.typeIDsSize = leU32(d, 64)
	p.typeIDsOff = leU32(d, 68)
	p.protoIDsSize = leU32(d, 72)
	p.protoIDsOff = leU32(d, 76)
	p.fieldIDsSize = leU32(d, 80)
	p.fieldIDsOff = leU32(d, 84)
	p.methodIDsSize = leU32(d, 88)
	p.methodIDsOff = leU32(d, 92)
	p.classDefsSize = leU32(d, 96)
	p.classDefsOff = leU32(d, 100)

	return nil
}

// sectionDef описывает секцию для валидации.
type sectionDef struct {
	name     string
	off      uint32
	count    uint32
	itemSize uint32
	minItem  uint32 // минимальный размер элемента для OOM-guard
}

func (p *DEXParser) allSections() []sectionDef {
	return []sectionDef{
		{"string_ids", p.stringIDsOff, p.stringIDsSize, 4, minStringItemSize},
		{"type_ids", p.typeIDsOff, p.typeIDsSize, 4, minTypeItemSize},
		{"proto_ids", p.protoIDsOff, p.protoIDsSize, 12, minProtoItemSize},
		{"field_ids", p.fieldIDsOff, p.fieldIDsSize, 8, minFieldItemSize},
		{"method_ids", p.methodIDsOff, p.methodIDsSize, 8, minMethodItemSize},
		{"class_defs", p.classDefsOff, p.classDefsSize, 32, minClassItemSize},
	}
}

func (p *DEXParser) validateHeader() error {
	if p.headerSize != dexHeaderSize {
		return fmt.Errorf("bad header_size: 0x%x (want 0x%x)", p.headerSize, dexHeaderSize)
	}
	if p.endianTag != dexEndianTag {
		return fmt.Errorf("bad endian_tag: 0x%08x (want 0x%08x)", p.endianTag, dexEndianTag)
	}
	if p.fileSize == 0 {
		return fmt.Errorf("file_size is zero")
	}
	if int(p.fileSize) > len(p.data) {
		return fmt.Errorf("file_size=%d > data_len=%d", p.fileSize, len(p.data))
	}

	sections := p.allSections()
	dataLen := uint64(len(p.data))

	for _, s := range sections {
		if s.count == 0 {
			continue
		}
		// Hard cap — защита от OOM при count=0xFFFF_FFFF
		if s.count > maxSectionItems {
			return fmt.Errorf("%s: count=%d exceeds max=%d: %w",
				s.name, s.count, maxSectionItems, errCountTooLarge)
		}
		// OOM guard: count * minItemSize не должно превышать размер файла
		if uint64(s.count)*uint64(s.minItem) > dataLen {
			return fmt.Errorf("%s: count=%d impossible for file_size=%d: %w",
				s.name, s.count, dataLen, errCountTooLarge)
		}
		// Bounds: секция укладывается в файл
		totalBytes := uint64(s.count) * uint64(s.itemSize)
		end := uint64(s.off) + totalBytes
		if end > dataLen {
			return fmt.Errorf("%s: out of bounds [%d..%d) > %d: %w",
				s.name, s.off, end, dataLen, errSectionOOB)
		}
	}

	// Проверяем перекрытие секций
	ranges := make([]sectionRange, 0, len(sections))
	for _, s := range sections {
		if s.count == 0 {
			continue
		}
		total := uint64(s.count) * uint64(s.itemSize)
		ranges = append(ranges, sectionRange{
			name:  s.name,
			start: uint64(s.off),
			end:   uint64(s.off) + total,
		})
	}
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})
	for i := 1; i < len(ranges); i++ {
		prev, curr := ranges[i-1], ranges[i]
		if prev.end > curr.start {
			return fmt.Errorf("sections overlap: %s [%d..%d) ∩ %s [%d..%d): %w",
				prev.name, prev.start, prev.end,
				curr.name, curr.start, curr.end,
				errSectionOverlap)
		}
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════
// ПАРСИНГ СТРОК — MUTF-8
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) parseStrings(ctx context.Context) error {
	count := p.stringIDsSize
	off := p.stringIDsOff
	p.strings = make([]string, count)

	// For small string counts, use sequential parsing
	if count < 1000 {
		return p.parseStringsSequential(ctx, off, count)
	}

	// For large counts, use worker pool
	return p.parseStringsParallel(ctx, off, count)
}

// parseStringsSequential — последовательный парсинг строк.
func (p *DEXParser) parseStringsSequential(ctx context.Context, off, count uint32) error {
	for i := uint32(0); i < count; i++ {
		// Проверяем контекст каждые 1000 итераций
		if i%1000 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}

		pos := off + i*4
		if !p.boundsOK(pos, 4) {
			p.warnf("string_id[%d]: offset out of bounds", i)
			continue
		}
		strDataOff := leU32(p.data, pos)
		str, err := p.readMUTF8(strDataOff)
		if err != nil {
			p.warnf("string[%d]@0x%x: %v", i, strDataOff, err)
			continue
		}
		p.strings[i] = str
	}
	return nil
}

// parseStringsParallel — параллельный парсинг строк.
//
// Строки разбиваются на непрерывные блоки по числу воркеров (range-partition),
// без канала на каждую строку. Это убирает overhead канала (для APK с 100k+
// строк это были сотни тысяч send/recv) и даёт лучшую cache-locality: каждый
// воркер идёт по своему диапазону string_ids подряд. Запись в p.strings[i]
// не требует мьютекса — каждый воркер пишет в непересекающийся диапазон.
func (p *DEXParser) parseStringsParallel(ctx context.Context, off, count uint32) error {
	workers := runtime.NumCPU()
	if workers > 16 {
		workers = 16 // cap at 16 to avoid excessive goroutines
	}
	if workers < 1 {
		workers = 1
	}

	chunk := (count + uint32(workers) - 1) / uint32(workers) // ceil division

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		start := uint32(w) * chunk
		if start >= count {
			break
		}
		end := start + chunk
		if end > count {
			end = count
		}
		wg.Add(1)
		go func(start, end uint32) {
			defer wg.Done()
			for i := start; i < end; i++ {
				// Проверяем контекст каждые 4096 строк, чтобы отмена
				// работала, но без накладных расходов на каждой итерации.
				if i&0xFFF == 0 && ctx.Err() != nil {
					return
				}
				pos := off + i*4
				if !p.boundsOK(pos, 4) {
					p.warnf("string_id[%d]: offset out of bounds", i)
					continue
				}
				strDataOff := leU32(p.data, pos)
				str, err := p.readMUTF8(strDataOff)
				if err != nil {
					p.warnf("string[%d]@0x%x: %v", i, strDataOff, err)
					continue
				}
				p.strings[i] = str
			}
		}(start, end)
	}
	wg.Wait()
	return ctx.Err()
}

// readMUTF8 декодирует Modified UTF-8 строку.
//
// Оптимизации:
//  1. Fast-path для чистых ASCII строк — прямое копирование из среза без Builder.
//  2. Пакетная проверка границ вместо побайтовой p.boundsOK в цикле.
//  3. Builder берётся из пула только если нужен (не-ASCII путь).
//  4. Убрано дублирование boundsOK вызовов.
func (p *DEXParser) readMUTF8(offset uint32) (string, error) {
	if !p.boundsOK(offset, 1) {
		return "", errOutOfBounds
	}

	utf16Size, bytesRead := p.readULEB128At(offset)
	if bytesRead == 0 {
		return "", errBadULEB128
	}
	if utf16Size > maxStringLen {
		return "", fmt.Errorf("string too long: %d utf16 units", utf16Size)
	}

	cursor := offset + uint32(bytesRead)

	if utf16Size == 0 {
		if p.boundsOK(cursor, 1) && p.data[cursor] != 0x00 {
			p.warnf("MUTF-8 empty string missing terminator at 0x%x", cursor)
		}
		return "", nil
	}

	// Пакетная проверка: убеждаемся что хотя бы utf16Size байт доступно
	// (реальная строка может быть длиннее из-за многобайтовых символов,
	// но это минимум для UTF-16 единиц).
	if !p.boundsOK(cursor, utf16Size) {
		// Не возвращаем ошибку — пытаемся прочитать сколько есть
		p.warnf("MUTF-8 string at 0x%x: data may be truncated", offset)
	}

	// ── Fast-path: чисто ASCII ────────────────────────────────
	// Сканируем байты вперёд: если все < 0x80 и нет 0x00 — это ASCII.
	// Избегаем Builder и аллокаций RuneWriter.
	available := uint32(len(p.data)) - cursor
	scanLen := utf16Size
	if scanLen > available {
		scanLen = available
	}

	if isASCII(p.data[cursor : cursor+scanLen]) {
		// Use scanLen (clamped to available) — on a truncated DEX utf16Size can
		// exceed the buffer, and the slice below would panic. The truncation was
		// already flagged at the boundsOK check above; here we return the bytes
		// that actually exist rather than crashing the whole parse.
		raw := p.data[cursor : cursor+scanLen]
		// Проверяем терминатор только один раз
		termPos := cursor + scanLen
		if termPos < uint32(len(p.data)) && p.data[termPos] != 0x00 {
			p.warnf("MUTF-8 missing null terminator at 0x%x (got 0x%02x)",
				termPos, p.data[termPos])
		}
		// v11.0 Zero-Copy String Pool — only for heap-owned data. When data
		// lives in an mmap region, Close() unmaps it while strings returned
		// to callers (findings, class names) may still be referenced, so we
		// must copy; a string pointing into the heap buffer keeps that
		// buffer alive for the GC and is safe to retain.
		if p.mapped {
			return string(raw), nil
		}
		return unsafe.String(&raw[0], len(raw)), nil
	}

	// ── Slow-path: multi-byte ─────────────────────────────────
	return p.readMUTF8Slow(cursor, utf16Size, offset)
}

// isASCII checks all bytes < 0x80 and no null — word-at-a-time for speed.
// Optimized: processes 8 bytes at a time using uint64 chunks.
func isASCII(b []byte) bool {
	const hiMask = 0x8080808080808080
	const zeroMask = 0x0101010101010101 // detect zero bytes via (x - 0x01) & ^x & 0x80
	i := 0
	// Process 8 bytes at a time. binary.LittleEndian.Uint64 compiles to the
	// same unaligned load on amd64/arm64 but stays safe on strict-alignment
	// architectures (mips, old ARM32).
	for ; i+8 <= len(b); i += 8 {
		w := binary.LittleEndian.Uint64(b[i : i+8])
		if w&hiMask != 0 {
			return false
		}
		// zero-byte detection: (w - 0x0101...) & ^w & 0x8080...
		if (w-zeroMask)&^w&hiMask != 0 {
			return false
		}
	}
	// Process remaining bytes
	for ; i < len(b); i++ {
		if b[i] >= 0x80 || b[i] == 0x00 {
			return false
		}
	}
	return true
}

// readMUTF8Slow — полный декодер MUTF-8 для не-ASCII строк.
func (p *DEXParser) readMUTF8Slow(cursor, utf16Size uint32, _ uint32) (string, error) {
	buf := getBuilder()
	defer putBuilder(buf)
	buf.Grow(int(utf16Size))

	utf16Units := uint32(0)

	for utf16Units < utf16Size {
		if cursor >= uint32(len(p.data)) {
			p.warnf("MUTF-8 truncated at 0x%x (%d/%d units)", cursor, utf16Units, utf16Size)
			break
		}

		b1 := p.data[cursor]
		cursor++

		if b1 == 0x00 {
			p.warnf("MUTF-8 premature null at 0x%x (%d/%d units)", cursor-1, utf16Units, utf16Size)
			break
		}

		switch {
		case b1 < 0x80:
			buf.WriteByte(b1)
			utf16Units++

		case b1&0xE0 == 0xC0:
			if cursor >= uint32(len(p.data)) {
				buf.WriteRune(0xFFFD)
				break
			}
			b2 := p.data[cursor]
			cursor++
			if b2&0xC0 != 0x80 {
				buf.WriteRune(0xFFFD)
				utf16Units++
				continue
			}
			if b1 == 0xC0 && b2 == 0x80 {
				buf.WriteByte(0x00)
			} else {
				buf.WriteRune(rune(uint32(b1&0x1F)<<6 | uint32(b2&0x3F)))
			}
			utf16Units++

		case b1&0xF0 == 0xE0:
			if cursor+1 >= uint32(len(p.data)) {
				buf.WriteRune(0xFFFD)
				break
			}
			b2 := p.data[cursor]
			b3 := p.data[cursor+1]
			cursor += 2
			if b2&0xC0 != 0x80 || b3&0xC0 != 0x80 {
				buf.WriteRune(0xFFFD)
				utf16Units++
				continue
			}
			ch := rune(uint32(b1&0x0F)<<12 | uint32(b2&0x3F)<<6 | uint32(b3&0x3F))

			// CESU-8: суррогатная пара → Unicode codepoint
			if ch >= 0xD800 && ch <= 0xDBFF && cursor+2 < uint32(len(p.data)) &&
				p.data[cursor]&0xF0 == 0xE0 {
				b4 := p.data[cursor]
				b5 := p.data[cursor+1]
				b6 := p.data[cursor+2]
				if b5&0xC0 == 0x80 && b6&0xC0 == 0x80 {
					low := rune(uint32(b4&0x0F)<<12 | uint32(b5&0x3F)<<6 | uint32(b6&0x3F))
					if low >= 0xDC00 && low <= 0xDFFF {
						cp := 0x10000 + (ch-0xD800)*0x400 + (low - 0xDC00)
						buf.WriteRune(cp)
						cursor += 3
						utf16Units += 2
						continue
					}
				}
			}
			if ch >= 0xD800 && ch <= 0xDFFF {
				buf.WriteRune(0xFFFD)
			} else {
				buf.WriteRune(ch)
			}
			utf16Units++

		default:
			buf.WriteRune(0xFFFD)
			utf16Units++
		}
	}

	if p.boundsOK(cursor, 1) && p.data[cursor] != 0x00 {
		p.warnf("MUTF-8 missing null terminator at 0x%x (got 0x%02x)",
			cursor, p.data[cursor])
	}

	return buf.String(), nil
}

// ═══════════════════════════════════════════════════════════════
// ПАРСИНГ ТИПОВ
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) parseTypes(ctx context.Context) error {
	count := p.typeIDsSize
	p.types = make([]string, count)

	for i := uint32(0); i < count; i++ {
		if i%1000 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		pos := p.typeIDsOff + i*4
		if !p.boundsOK(pos, 4) {
			return fmt.Errorf("type_id[%d]: %w", i, errOutOfBounds)
		}
		p.types[i] = p.getString(leU32(p.data, pos))
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// ПАРСИНГ ПРОТОТИПОВ
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) parseProtos(ctx context.Context) error {
	count := p.protoIDsSize
	p.protos = make([]*Proto, count)

	for i := uint32(0); i < count; i++ {
		if i%1000 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		pos := p.protoIDsOff + i*12
		if !p.boundsOK(pos, 12) {
			return fmt.Errorf("proto_id[%d]: %w", i, errOutOfBounds)
		}
		proto := &Proto{
			ShortyIdx:     leU32(p.data, pos),
			ReturnTypeIdx: leU32(p.data, pos+4),
			ParametersOff: leU32(p.data, pos+8),
		}
		proto.Shorty = p.getString(proto.ShortyIdx)
		proto.ReturnType = p.getType(proto.ReturnTypeIdx)

		if proto.ParametersOff != 0 {
			params, err := p.readTypeList(proto.ParametersOff)
			if err != nil {
				p.warnf("proto[%d] params: %v", i, err)
			} else {
				proto.Parameters = params
			}
		}
		p.protos[i] = proto
	}
	return nil
}

func (p *DEXParser) readTypeList(offset uint32) ([]string, error) {
	if !p.boundsOK(offset, 4) {
		return nil, errOutOfBounds
	}
	size := leU32(p.data, offset)
	if size == 0 {
		return nil, nil
	}
	// OOM guard
	if uint64(size)*2 > uint64(len(p.data)) {
		return nil, fmt.Errorf("type_list size=%d impossible for file size=%d", size, len(p.data))
	}
	if !p.boundsOK64(uint64(offset)+4, uint64(size)*2) {
		return nil, fmt.Errorf("type_list size=%d: %w", size, errOutOfBounds)
	}

	result := make([]string, size) // с capacity = size
	pos := offset + 4
	for i := uint32(0); i < size; i++ {
		result[i] = p.getType(uint32(leU16(p.data, pos)))
		pos += 2
	}
	return result, nil
}

// ═══════════════════════════════════════════════════════════════
// ПАРСИНГ ПОЛЕЙ
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) parseFields(ctx context.Context) error {
	count := p.fieldIDsSize
	p.fields = make([]*Field, count)

	for i := uint32(0); i < count; i++ {
		if i%1000 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		pos := p.fieldIDsOff + i*8
		if !p.boundsOK(pos, 8) {
			return fmt.Errorf("field_id[%d]: %w", i, errOutOfBounds)
		}
		f := &Field{
			ClassIdx: leU16(p.data, pos),
			TypeIdx:  leU16(p.data, pos+2),
			NameIdx:  leU32(p.data, pos+4),
		}
		f.ClassName = p.getType(uint32(f.ClassIdx))
		f.TypeName = p.getType(uint32(f.TypeIdx))
		f.FieldName = p.getString(f.NameIdx)
		p.fields[i] = f
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// ПАРСИНГ МЕТОДОВ
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) parseMethods(ctx context.Context) error {
	count := p.methodIDsSize
	p.methods = make([]*Method, count)

	for i := uint32(0); i < count; i++ {
		if i%1000 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		pos := p.methodIDsOff + i*8
		if !p.boundsOK(pos, 8) {
			return fmt.Errorf("method_id[%d]: %w", i, errOutOfBounds)
		}
		m := &Method{
			ClassIdx: leU16(p.data, pos),
			ProtoIdx: leU16(p.data, pos+2),
			NameIdx:  leU32(p.data, pos+4),
		}
		m.ClassName = p.getType(uint32(m.ClassIdx))
		m.MethodName = p.getString(m.NameIdx)

		if protoIdx := uint32(m.ProtoIdx); protoIdx < uint32(len(p.protos)) {
			if proto := p.protos[protoIdx]; proto != nil {
				m.ReturnType = proto.ReturnType
				m.Parameters = proto.Parameters
			}
		}
		p.methods[i] = m
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// ПАРСИНГ КЛАССОВ
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) parseClasses(ctx context.Context) error {
	count := p.classDefsSize
	p.classes = make([]*ClassDef, count)

	for i := uint32(0); i < count; i++ {
		if i%100 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		pos := p.classDefsOff + i*32
		if !p.boundsOK(pos, 32) {
			return fmt.Errorf("class_def[%d]: %w", i, errOutOfBounds)
		}
		cd := &ClassDef{
			ClassIdx:        leU32(p.data, pos),
			AccessFlags:     leU32(p.data, pos+4),
			SuperclassIdx:   leU32(p.data, pos+8),
			InterfacesOff:   leU32(p.data, pos+12),
			SourceFileIdx:   leU32(p.data, pos+16),
			AnnotationsOff:  leU32(p.data, pos+20),
			ClassDataOff:    leU32(p.data, pos+24),
			StaticValuesOff: leU32(p.data, pos+28),
		}
		cd.ClassName = p.getType(cd.ClassIdx)
		if cd.SuperclassIdx != dexNoIndex {
			cd.SuperClass = p.getType(cd.SuperclassIdx)
		}
		if cd.SourceFileIdx != dexNoIndex {
			cd.SourceFile = p.getString(cd.SourceFileIdx)
		}
		if cd.InterfacesOff != 0 {
			ifaces, err := p.readTypeList(cd.InterfacesOff)
			if err != nil {
				p.warnf("class[%d] interfaces: %v", i, err)
			} else {
				cd.Interfaces = ifaces
			}
		}
		p.classes[i] = cd
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// ПАРСИНГ CLASS DATA
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) parseAllClassData(ctx context.Context) error {
	// Collect classes that need parsing
	type work struct {
		idx   int
		class *ClassDef
	}
	jobs := make([]work, 0, len(p.classes))
	for i, class := range p.classes {
		if class != nil && class.ClassDataOff != 0 && p.boundsOK(class.ClassDataOff, 4) {
			jobs = append(jobs, work{i, class})
		} else if class != nil && class.ClassDataOff != 0 {
			p.warnf("class[%d] class_data_off=0x%x: %v", i, class.ClassDataOff, errOutOfBounds)
		}
	}

	if len(jobs) == 0 {
		return nil
	}

	// Use runtime.NumCPU() for optimal worker count
	workers := runtime.NumCPU()
	if workers > len(jobs) {
		workers = len(jobs)
	}

	// Atomic cursor work-stealing: no per-job channel buffer. Each worker
	// grabs the next index with one atomic add and processes it. This keeps
	// workers busy regardless of how uneven per-class parse cost is, and
	// allocates nothing beyond the goroutines themselves.
	var next int64 = -1
	total := int64(len(jobs))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := atomic.AddInt64(&next, 1)
				if i >= total {
					return
				}
				if i&0x3F == 0 && ctx.Err() != nil {
					return
				}
				j := jobs[i]
				if err := p.parseClassData(j.class); err != nil {
					p.warnf("class[%d] %s: %v", j.idx, j.class.ClassName, err)
				}
			}
		}()
	}
	wg.Wait()
	// Publish code statistics after the workers finish. Summing their parsed
	// methods avoids both lost updates and a shared lock on every code item.
	p.Metrics.InstructionCount = 0
	for _, j := range jobs {
		for _, methods := range [...][]*EncodedMethod{j.class.DirectMethods, j.class.VirtualMethods} {
			for _, method := range methods {
				if method.Code != nil {
					p.Metrics.InstructionCount += int64(method.Code.InsnsSize)
				}
			}
		}
	}
	p.Metrics.TotalCodeBytes = p.Metrics.InstructionCount * 2
	return ctx.Err()
}

func (p *DEXParser) parseClassData(class *ClassDef) error {
	cursor := class.ClassDataOff

	// Вспомогательная функция — читает ULEB128 и двигает курсор.
	readULEB := func(name string) (uint32, error) {
		v, n := p.readULEB128At(cursor)
		if n == 0 {
			return 0, fmt.Errorf("%s: %w", name, errBadULEB128)
		}
		cursor += uint32(n)
		return v, nil
	}

	staticCount, err := readULEB("static_fields_size")
	if err != nil {
		return err
	}
	instanceCount, err := readULEB("instance_fields_size")
	if err != nil {
		return err
	}
	directCount, err := readULEB("direct_methods_size")
	if err != nil {
		return err
	}
	virtualCount, err := readULEB("virtual_methods_size")
	if err != nil {
		return err
	}

	// OOM guard для всех счётчиков
	dataLen := uint64(len(p.data))
	for _, pair := range [...]struct {
		name  string
		count uint32
	}{
		{"static_fields", staticCount},
		{"instance_fields", instanceCount},
		{"direct_methods", directCount},
		{"virtual_methods", virtualCount},
	} {
		if uint64(pair.count) > dataLen {
			return fmt.Errorf("%s count=%d impossible: %w",
				pair.name, pair.count, errCountTooLarge)
		}
	}

	class.StaticFields = make([]*EncodedField, 0, staticCount)
	fieldIdx := uint32(0)
	for i := uint32(0); i < staticCount; i++ {
		ef, next, err := p.readEncodedField(cursor, fieldIdx)
		if err != nil {
			return fmt.Errorf("static_field[%d]: %w", i, err)
		}
		ef.ClassName = class.ClassName
		class.StaticFields = append(class.StaticFields, ef)
		fieldIdx = ef.FieldIdx
		cursor = next
	}

	class.InstanceFields = make([]*EncodedField, 0, instanceCount)
	fieldIdx = 0
	for i := uint32(0); i < instanceCount; i++ {
		ef, next, err := p.readEncodedField(cursor, fieldIdx)
		if err != nil {
			return fmt.Errorf("instance_field[%d]: %w", i, err)
		}
		ef.ClassName = class.ClassName
		class.InstanceFields = append(class.InstanceFields, ef)
		fieldIdx = ef.FieldIdx
		cursor = next
	}

	class.DirectMethods = make([]*EncodedMethod, 0, directCount)
	methodIdx := uint32(0)
	for i := uint32(0); i < directCount; i++ {
		em, next, err := p.readEncodedMethod(cursor, methodIdx)
		if err != nil {
			return fmt.Errorf("direct_method[%d]: %w", i, err)
		}
		em.ClassName = class.ClassName
		class.DirectMethods = append(class.DirectMethods, em)
		methodIdx = em.MethodIdx
		cursor = next
	}

	class.VirtualMethods = make([]*EncodedMethod, 0, virtualCount)
	methodIdx = 0
	for i := uint32(0); i < virtualCount; i++ {
		em, next, err := p.readEncodedMethod(cursor, methodIdx)
		if err != nil {
			return fmt.Errorf("virtual_method[%d]: %w", i, err)
		}
		em.ClassName = class.ClassName
		class.VirtualMethods = append(class.VirtualMethods, em)
		methodIdx = em.MethodIdx
		cursor = next
	}

	return nil
}

func (p *DEXParser) readEncodedField(cursor, prevIdx uint32) (*EncodedField, uint32, error) {
	diff, n := p.readULEB128At(cursor)
	if n == 0 {
		return nil, cursor, errBadULEB128
	}
	cursor += uint32(n)

	flags, n := p.readULEB128At(cursor)
	if n == 0 {
		return nil, cursor, errBadULEB128
	}
	cursor += uint32(n)

	fieldIdx := prevIdx + diff
	if fieldIdx >= uint32(len(p.fields)) {
		return nil, cursor, fmt.Errorf("field_idx=%d >= fields_len=%d", fieldIdx, len(p.fields))
	}

	ef := &EncodedField{FieldIdx: fieldIdx, AccessFlags: flags}
	if f := p.fields[fieldIdx]; f != nil {
		ef.Name = f.FieldName
		ef.TypeName = f.TypeName
	}
	return ef, cursor, nil
}

func (p *DEXParser) readEncodedMethod(cursor, prevIdx uint32) (*EncodedMethod, uint32, error) {
	diff, n := p.readULEB128At(cursor)
	if n == 0 {
		return nil, cursor, errBadULEB128
	}
	cursor += uint32(n)

	flags, n := p.readULEB128At(cursor)
	if n == 0 {
		return nil, cursor, errBadULEB128
	}
	cursor += uint32(n)

	codeOff, n := p.readULEB128At(cursor)
	if n == 0 {
		return nil, cursor, errBadULEB128
	}
	cursor += uint32(n)

	methodIdx := prevIdx + diff
	if methodIdx >= uint32(len(p.methods)) {
		return nil, cursor, fmt.Errorf("method_idx=%d >= methods_len=%d", methodIdx, len(p.methods))
	}

	em := &EncodedMethod{MethodIdx: methodIdx, AccessFlags: flags, CodeOff: codeOff}
	if m := p.methods[methodIdx]; m != nil {
		em.Name = m.MethodName
		em.ReturnType = m.ReturnType
		em.Parameters = m.Parameters
	}

	if codeOff != 0 {
		if !p.boundsOK(codeOff, 16) {
			p.warnf("method[%d] code_off=0x%x: %v", methodIdx, codeOff, errOutOfBounds)
		} else if p.lazyCode {
			// v11.0 Lazy Loading: store back-reference, parse on demand
			em.parser = p
		} else {
			code, err := p.parseCodeItem(codeOff)
			if err != nil {
				p.warnf("method[%d] code: %v", methodIdx, err)
			} else {
				em.Code = code
			}
		}
	}
	return em, cursor, nil
}

// ═══════════════════════════════════════════════════════════════
// LAZY CODE LOADING (v11.0)
// ═══════════════════════════════════════════════════════════════

// EnsureCode lazily parses the bytecode for this method on first access.
// Thread-safe: uses sync.Once internally.
// Returns the CodeItem (may be nil if method has no code or parsing fails).
func (em *EncodedMethod) EnsureCode() *CodeItem {
	if em.CodeOff == 0 || em.parser == nil {
		return em.Code
	}
	// Lazy readers must all pass through Once before inspecting Code; the
	// first caller may still be assigning it while another caller arrives.
	em.codeOnce.Do(func() {
		if em.Code != nil {
			return
		}
		code, err := em.parser.parseCodeItem(em.CodeOff)
		if err != nil {
			em.parser.warnf("lazy method[%d] code: %v", em.MethodIdx, err)
			return
		}
		em.Code = code
	})
	return em.Code
}

// GetMethodCode returns the code for a method, triggering lazy loading if needed.
func (p *DEXParser) GetMethodCode(em *EncodedMethod) *CodeItem {
	if em == nil {
		return nil
	}
	return em.EnsureCode()
}

// IsLazyMode returns true if the parser was created with lazy code loading.
func (p *DEXParser) IsLazyMode() bool {
	return p.lazyCode
}

// ═══════════════════════════════════════════════════════════════
// CODE ITEM
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) parseCodeItem(offset uint32) (*CodeItem, error) {
	if !p.boundsOK(offset, 16) {
		return nil, errOutOfBounds
	}

	code := &CodeItem{
		RegistersSize: leU16(p.data, offset),
		InsSize:       leU16(p.data, offset+2),
		OutsSize:      leU16(p.data, offset+4),
		TriesSize:     leU16(p.data, offset+6),
		DebugInfoOff:  leU32(p.data, offset+8),
		InsnsSize:     leU32(p.data, offset+12),
	}

	insnsStart := offset + 16
	insnsBytes := uint64(code.InsnsSize) * 2

	// OOM guard
	if insnsBytes > uint64(len(p.data)) {
		return code, fmt.Errorf("insns_size=%d impossible for file_size=%d: %w",
			code.InsnsSize, len(p.data), errCountTooLarge)
	}
	if !p.boundsOK64(uint64(insnsStart), insnsBytes) {
		return code, fmt.Errorf("insns out of bounds: off=0x%x size=%d: %w",
			insnsStart, code.InsnsSize, errOutOfBounds)
	}

	// Zero-copy: reinterpret p.data slice as []uint16 directly
	raw := p.data[insnsStart : insnsStart+uint32(insnsBytes)]
	code.Insns = unsafe.Slice((*uint16)(unsafe.Pointer(&raw[0])), code.InsnsSize)

	// Lazy init: only allocate PayloadOffsets if needed
	code.PayloadOffsets = make(map[uint32]bool)
	p.scanPayloads(code)

	if code.TriesSize > 0 {
		triesOff := insnsStart + uint32(insnsBytes)
		if code.InsnsSize%2 != 0 {
			triesOff += 2 // выравнивание до 4 байт
		}
		p.parseTryCatch(code, triesOff)
	}

	return code, nil
}

func (p *DEXParser) scanPayloads(code *CodeItem) {
	insns := code.Insns
	n := uint32(len(insns))

	// Lazy init: only allocate if we find payload instructions
	hasPayloads := false

	for pos := uint32(0); pos < n; {
		opcode := uint8(insns[pos])
		switch opcode {
		case 0x26, 0x2B, 0x2C: // fill-array-data, packed-switch, sparse-switch
			if !hasPayloads {
				code.PayloadOffsets = make(map[uint32]bool)
				hasPayloads = true
			}
			if pos+2 < n {
				off32 := int32(uint32(insns[pos+1]) | uint32(insns[pos+2])<<16)
				if target := uint32(int32(pos) + off32); target < n {
					code.PayloadOffsets[target] = true
				}
			}
		}
		size := opcodeTable[opcode].Size
		if size == 0 {
			size = 1
		}
		pos += size
	}
}

func (p *DEXParser) parseTryCatch(code *CodeItem, triesOffset uint32) {
	triesBytes := uint32(code.TriesSize) * 8
	if !p.boundsOK(triesOffset, triesBytes) {
		return
	}

	code.Tries = make([]*TryItem, code.TriesSize)
	for i := uint16(0); i < code.TriesSize; i++ {
		pos := triesOffset + uint32(i)*8
		code.Tries[i] = &TryItem{
			StartAddr:  leU32(p.data, pos),
			InsnCount:  leU16(p.data, pos+4),
			HandlerOff: leU16(p.data, pos+6),
		}
	}

	handlersStart := triesOffset + triesBytes
	if !p.boundsOK(handlersStart, 1) {
		return
	}

	listSize, n := p.readULEB128At(handlersStart)
	if n == 0 {
		return
	}
	// OOM guard
	if uint64(listSize) > uint64(len(p.data)) {
		p.warnf("parseTryCatch: handlers list size=%d too large", listSize)
		return
	}

	type handlerEntry struct {
		relOff   uint32
		handlers []*CatchHandler
	}
	entries := make([]handlerEntry, 0, listSize) // предварительная аллокация
	cursor := handlersStart + uint32(n)

	for i := uint32(0); i < listSize; i++ {
		if !p.boundsOK(cursor, 1) {
			break
		}
		relOff := cursor - handlersStart

		size, n := p.readSLEB128At(cursor)
		if n == 0 {
			break
		}
		cursor += uint32(n)

		hasCatchAll := size <= 0
		count := size
		if count < 0 {
			count = -count
		}

		// Предварительная аллокация с capacity
		handlers := make([]*CatchHandler, 0, int(count)+1)

		for j := int32(0); j < count; j++ {
			typeIdx, n := p.readULEB128At(cursor)
			if n == 0 {
				break
			}
			cursor += uint32(n)

			addr, n := p.readULEB128At(cursor)
			if n == 0 {
				break
			}
			cursor += uint32(n)

			handlers = append(handlers, &CatchHandler{
				TypeIdx:     int32(typeIdx),
				TypeName:    p.getType(typeIdx),
				HandlerAddr: addr,
			})
		}

		if hasCatchAll {
			addr, n := p.readULEB128At(cursor)
			if n == 0 {
				break
			}
			cursor += uint32(n)
			handlers = append(handlers, &CatchHandler{
				TypeIdx:      -1,
				TypeName:     "Ljava/lang/Throwable;",
				HandlerAddr:  addr,
				CatchAllAddr: addr,
				HasCatchAll:  true,
			})
		}
		entries = append(entries, handlerEntry{relOff, handlers})
	}

	// Собираем плоский список и привязываем к tries
	total := 0
	for _, e := range entries {
		total += len(e.handlers)
	}
	code.Handlers = make([]*CatchHandler, 0, total)
	for _, e := range entries {
		code.Handlers = append(code.Handlers, e.handlers...)
	}

	for _, try := range code.Tries {
		target := uint32(try.HandlerOff)
		for _, e := range entries {
			if e.relOff == target {
				try.CatchHandlers = e.handlers
				break
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// БИНАРНЫЕ УТИЛИТЫ
// ═══════════════════════════════════════════════════════════════

// leU16/leU32 — тонкие обёртки над encoding/binary.LittleEndian,
// оптимизируются компилятором до одной инструкции на amd64/arm64.

func leU16(data []byte, off uint32) uint16 {
	return binary.LittleEndian.Uint16(data[off:])
}

func leU32(data []byte, off uint32) uint32 {
	return binary.LittleEndian.Uint32(data[off:])
}

func (p *DEXParser) boundsOK(offset, size uint32) bool {
	return uint64(offset)+uint64(size) <= uint64(len(p.data))
}

func (p *DEXParser) boundsOK64(offset, size uint64) bool {
	return offset+size <= uint64(len(p.data))
}

func (p *DEXParser) getString(idx uint32) string {
	if idx < uint32(len(p.strings)) {
		return p.strings[idx]
	}
	return ""
}

func (p *DEXParser) getType(idx uint32) string {
	if idx < uint32(len(p.types)) {
		return p.types[idx]
	}
	return ""
}

// readULEB128At читает unsigned LEB128, максимум 5 байт.
func (p *DEXParser) readULEB128At(offset uint32) (uint32, int) {
	data := p.data
	dataLen := uint32(len(data))
	var result uint32
	for i := uint32(0); i < 5; i++ {
		if offset+i >= dataLen {
			return 0, 0
		}
		b := data[offset+i]
		result |= uint32(b&0x7F) << (i * 7)
		if b&0x80 == 0 {
			return result, int(i + 1)
		}
	}
	return 0, 0 // переполнение
}

// readSLEB128At читает signed LEB128, максимум 5 байт.
func (p *DEXParser) readSLEB128At(offset uint32) (int32, int) {
	data := p.data
	dataLen := uint32(len(data))
	var result int32
	var shift uint
	for i := uint32(0); i < 5; i++ {
		if offset+i >= dataLen {
			return 0, 0
		}
		b := data[offset+i]
		result |= int32(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			if shift < 32 && b&0x40 != 0 {
				result |= -(1 << shift)
			}
			return result, int(i + 1)
		}
	}
	return 0, 0
}

// warnf добавляет предупреждение (потокобезопасно).
// Оптимизация: используем atomic pointer swap вместо mutex lock на каждое предупреждение.
func (p *DEXParser) warnf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	p.warningsMu.Lock()
	p.warnings = append(p.warnings, msg)
	p.warningsMu.Unlock()
}

// ═══════════════════════════════════════════════════════════════
// ИНДЕКСЫ БЫСТРОГО ПОИСКА
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) buildClassIndex() {
	p.classIndexOnce.Do(func() {
		p.classIndex = make(map[string]*ClassDef, len(p.classes))
		for _, c := range p.classes {
			if c != nil && c.ClassName != "" {
				p.classIndex[c.ClassName] = c
			}
		}
	})
}

func (p *DEXParser) buildMethodIndex() {
	p.methodIndexOnce.Do(func() {
		p.methodIndex = make(map[string][]*Method, 64)
		for _, m := range p.methods {
			if m != nil && m.MethodName != "" {
				p.methodIndex[m.ClassName] = append(p.methodIndex[m.ClassName], m)
			}
		}
	})
}

// ═══════════════════════════════════════════════════════════════
// ПУБЛИЧНЫЙ API
// ═══════════════════════════════════════════════════════════════

func (p *DEXParser) GetAllStrings() []string {
	result := make([]string, 0, len(p.strings))
	for _, s := range p.strings {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func (p *DEXParser) GetClasses() []*ClassDef {
	result := make([]*ClassDef, 0, len(p.classes))
	for _, c := range p.classes {
		if c != nil && c.ClassName != "" {
			result = append(result, c)
		}
	}
	return result
}

func (p *DEXParser) GetMethods() []*Method {
	result := make([]*Method, 0, len(p.methods))
	for _, m := range p.methods {
		if m != nil && m.MethodName != "" {
			result = append(result, m)
		}
	}
	return result
}

func (p *DEXParser) GetFields() []*Field {
	result := make([]*Field, 0, len(p.fields))
	for _, f := range p.fields {
		if f != nil && f.FieldName != "" {
			result = append(result, f)
		}
	}
	return result
}

func (p *DEXParser) GetProtos() []*Proto {
	result := make([]*Proto, 0, len(p.protos))
	for _, pr := range p.protos {
		if pr != nil {
			result = append(result, pr)
		}
	}
	return result
}

func (p *DEXParser) GetVersion() string  { return p.version }
func (p *DEXParser) GetStringCount() int { return len(p.strings) }
func (p *DEXParser) GetClassCount() int  { return len(p.classes) }
func (p *DEXParser) GetMethodCount() int { return len(p.methods) }
func (p *DEXParser) GetFieldCount() int  { return len(p.fields) }

func (p *DEXParser) GetWarnings() []string {
	p.warningsMu.Lock()
	defer p.warningsMu.Unlock()
	out := make([]string, len(p.warnings))
	copy(out, p.warnings)
	return out
}

func (p *DEXParser) GetWarningCount() int {
	p.warningsMu.Lock()
	defer p.warningsMu.Unlock()
	return len(p.warnings)
}

func (p *DEXParser) GetMetrics() ParseMetrics {
	m := p.Metrics
	m.WarningsCount = p.GetWarningCount()
	return m
}

// FindClassByName — O(1) после первого вызова.
func (p *DEXParser) FindClassByName(name string) *ClassDef {
	p.buildClassIndex()
	return p.classIndex[name]
}

// FindMethodsByClass — O(1) после первого вызова.
func (p *DEXParser) FindMethodsByClass(className string) []*Method {
	p.buildMethodIndex()
	return p.methodIndex[className]
}

func (p *DEXParser) FindStringBySubstring(sub string) []string {
	result := make([]string, 0, 8)
	for _, s := range p.strings {
		if strings.Contains(s, sub) {
			result = append(result, s)
		}
	}
	return result
}

func (p *DEXParser) FindClassesBySuperClass(superClass string) []*ClassDef {
	result := make([]*ClassDef, 0, 8)
	for _, c := range p.classes {
		if c != nil && c.SuperClass == superClass {
			result = append(result, c)
		}
	}
	return result
}

func (p *DEXParser) FindClassesImplementing(iface string) []*ClassDef {
	result := make([]*ClassDef, 0, 4)
	for _, c := range p.classes {
		if c == nil {
			continue
		}
		for _, ci := range c.Interfaces {
			if ci == iface {
				result = append(result, c)
				break
			}
		}
	}
	return result
}

func (p *DEXParser) HasClass(name string) bool {
	return p.FindClassByName(name) != nil
}

// FindMethodsBySignature finds methods matching name pattern and optional return type.
// namePattern is a substring match; returnType="" matches any.
func (p *DEXParser) FindMethodsBySignature(namePattern, returnType string) []*EncodedMethod {
	result := make([]*EncodedMethod, 0, 8)
	for _, cls := range p.classes {
		if cls == nil {
			continue
		}
		for _, m := range cls.DirectMethods {
			if strings.Contains(m.Name, namePattern) && (returnType == "" || m.ReturnType == returnType) {
				result = append(result, m)
			}
		}
		for _, m := range cls.VirtualMethods {
			if strings.Contains(m.Name, namePattern) && (returnType == "" || m.ReturnType == returnType) {
				result = append(result, m)
			}
		}
	}
	return result
}

// FindStringsByPattern finds all strings matching a regex pattern.
func (p *DEXParser) FindStringsByPattern(pattern string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, 8)
	for _, s := range p.strings {
		if re.MatchString(s) {
			result = append(result, s)
		}
	}
	return result, nil
}

// FindFieldsByType finds all fields of a given type descriptor.
func (p *DEXParser) FindFieldsByType(typeName string) []*EncodedField {
	result := make([]*EncodedField, 0, 8)
	for _, cls := range p.classes {
		if cls == nil {
			continue
		}
		for _, f := range cls.StaticFields {
			if f.TypeName == typeName {
				result = append(result, f)
			}
		}
		for _, f := range cls.InstanceFields {
			if f.TypeName == typeName {
				result = append(result, f)
			}
		}
	}
	return result
}

// FindClassesByPackage finds all classes in a given package prefix (e.g. "Lcom/example/").
func (p *DEXParser) FindClassesByPackage(pkg string) []*ClassDef {
	result := make([]*ClassDef, 0, 16)
	for _, c := range p.classes {
		if c != nil && strings.HasPrefix(c.ClassName, pkg) {
			result = append(result, c)
		}
	}
	return result
}

// FindPaymentClasses returns classes likely related to in-app purchases / billing.
func (p *DEXParser) FindPaymentClasses() []*ClassDef {
	keywords := []string{"billing", "purchase", "payment", "iap", "inapp", "subscription", "premium", "BillingClient", "SkuDetails", "Purchase"}
	result := make([]*ClassDef, 0, 8)
	seen := make(map[string]bool)
	for _, c := range p.classes {
		if c == nil || seen[c.ClassName] {
			continue
		}
		name := strings.ToLower(c.ClassName)
		for _, kw := range keywords {
			if strings.Contains(name, strings.ToLower(kw)) {
				result = append(result, c)
				seen[c.ClassName] = true
				break
			}
		}
	}
	return result
}

// FindRegistrationClasses returns classes likely related to user registration / activation.
func (p *DEXParser) FindRegistrationClasses() []*ClassDef {
	keywords := []string{"register", "activation", "license", "serial", "auth", "login", "signup", "account", "trial"}
	result := make([]*ClassDef, 0, 8)
	seen := make(map[string]bool)
	for _, c := range p.classes {
		if c == nil || seen[c.ClassName] {
			continue
		}
		name := strings.ToLower(c.ClassName)
		for _, kw := range keywords {
			if strings.Contains(name, strings.ToLower(kw)) {
				result = append(result, c)
				seen[c.ClassName] = true
				break
			}
		}
	}
	return result
}

// FindServerURLStrings returns all strings that look like server URLs or endpoints.
func (p *DEXParser) FindServerURLStrings() []string {
	result := make([]string, 0, 8)
	for _, s := range p.strings {
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
			strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://") {
			result = append(result, s)
		}
	}
	return result
}

// FindAntiTamperMethods returns methods likely performing integrity / anti-tamper checks.
func (p *DEXParser) FindAntiTamperMethods() []*EncodedMethod {
	keywords := []string{"checkIntegrity", "verifySignature", "isRooted", "detectRoot",
		"isEmulator", "checkEmulator", "isDebugger", "detectDebug", "tamper",
		"checkCert", "verifyCert", "getSignature", "checkSignature"}
	result := make([]*EncodedMethod, 0, 8)
	for _, cls := range p.classes {
		if cls == nil {
			continue
		}
		for _, m := range append(cls.DirectMethods, cls.VirtualMethods...) {
			for _, kw := range keywords {
				if strings.EqualFold(m.Name, kw) || strings.Contains(strings.ToLower(m.Name), strings.ToLower(kw)) {
					result = append(result, m)
					break
				}
			}
		}
	}
	return result
}

// FindMethodsWithStringRef finds all methods whose bytecode references a string containing sub.
func (p *DEXParser) FindMethodsWithStringRef(sub string) []*EncodedMethod {
	// Build index of matching string indices
	matchIdx := make(map[uint32]bool)
	for i, s := range p.strings {
		if strings.Contains(s, sub) {
			matchIdx[uint32(i)] = true
		}
	}
	if len(matchIdx) == 0 {
		return nil
	}

	result := make([]*EncodedMethod, 0, 4)
	for _, cls := range p.classes {
		if cls == nil {
			continue
		}
		for _, m := range append(cls.DirectMethods, cls.VirtualMethods...) {
			code := m.EnsureCode()
			if code == nil {
				continue
			}
			insns := code.Insns
			for i := 0; i+1 < len(insns); i++ {
				op := uint8(insns[i])
				// const-string (0x1a) and const-string/jumbo (0x1b)
				if op == 0x1a && i+1 < len(insns) {
					if matchIdx[uint32(insns[i+1])] {
						result = append(result, m)
						break
					}
				} else if op == 0x1b && i+2 < len(insns) {
					idx := uint32(insns[i+1]) | uint32(insns[i+2])<<16
					if matchIdx[idx] {
						result = append(result, m)
						break
					}
				}
			}
		}
	}
	return result
}

func (p *DEXParser) Stats() string {
	m := p.GetMetrics()
	return fmt.Sprintf(
		"DEX v%s | strings=%d types=%d protos=%d fields=%d methods=%d classes=%d | "+
			"code=%d bytes insns=%d | warnings=%d | parsed in %v",
		p.version,
		m.StringsCount, m.TypesCount, m.ProtosCount,
		m.FieldsCount, m.MethodsCount, m.ClassesCount,
		m.TotalCodeBytes, m.InstructionCount,
		m.WarningsCount,
		m.ParseDuration.Round(time.Millisecond),
	)
}

// GetDEXHashHex returns cached SHA-256 hex string of the DEX payload.
func (p *DEXParser) GetDEXHashHex() string {
	p.dexHashOnce.Do(func() {
		if len(p.data) > 0 {
			hash := sha256.Sum256(p.data)
			p.dexHash = hex.EncodeToString(hash[:])
		}
	})
	return p.dexHash
}
