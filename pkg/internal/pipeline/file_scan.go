package pipeline

import (
	"context"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/matcher"
	"mega-analyzer/pkg/internal/parser"
	"mega-analyzer/pkg/internal/types"
)

// FileScanTask contains only independent file work. Cross-file detectors,
// deobfuscation environments, call graphs and data flow stay in the coordinator.
type FileScanTask struct {
	Job      FileJob `json:"job"`
	AppCode  bool    `json:"app_code"`
	Library  bool    `json:"library"`
	Patterns bool    `json:"patterns"`
}

type FileScanResult struct {
	Patterns  []types.Match                 `json:"patterns"`
	Piracy    []types.Match                 `json:"piracy"`
	PatternNs int64                         `json:"pattern_ns"`
	PiracyNs  int64                         `json:"piracy_ns"`
	Detectors map[string]FileDetectorResult `json:"detectors"`
}

type FileDetectorResult struct {
	Matches    []types.Match `json:"matches"`
	DurationNs int64         `json:"duration_ns"`
}

// Audited detectors append file-local matches only. Aggregators, custom
// detectors and detectors that enrich other analysis fields stay local.
func independentFileDetector(d FileDetector) bool {
	switch d.(type) {
	case *AdsDetector, *AnalyticsDetector, *PaymentDetector, *ResourceDetector,
		*ObfuscationDetector, *CryptoDetector, *EndpointDetector,
		*LibraryCallDetector, *SemanticMethodDetector, *VulnSecretDetector,
		*VulnNetworkDetector, *VulnDlopenObfuscationDetector,
		*VulnResourceIntegrityDetector, *VulnStagingEndpointDetector,
		*VulnModMenuInjectionDetector, *VulnCryptoDetector,
		*VulnWebViewDetector, *VulnZipSlipDetector, *VulnPendingIntentDetector,
		*VulnAndroidSurfaceDetector, *VulnDynamicLoadDetector, *VulnInsecureStorageDetector:
		return true
	}
	return false
}

type fileScanFuture func(context.Context) (FileScanResult, error)
type fileScanExecutor interface {
	Start(context.Context, FileScanTask, []byte) fileScanFuture
	Yield()
}

// FileScanWorker owns its immutable matcher and bounded piracy cache. It does
// not receive the APK, run global analysis or generate a partial report.
type FileScanWorker struct {
	matcher   *matcher.Matcher
	piracy    *PiracyDetectorAdapter
	detectors []FileDetector
}

func NewFileScanWorker(cfg *config.Config) (*FileScanWorker, error) {
	m, err := matcher.NewMatcher(cfg)
	if err != nil {
		return nil, err
	}
	w := &FileScanWorker{matcher: m, piracy: NewPiracyDetectorAdapter(loadPiracyDetector())}
	w.detectors = []FileDetector{
		NewAdsDetector(), NewAnalyticsDetector(), NewPaymentDetector(),
		NewResourceDetector(), NewObfuscationDetector(), NewCryptoDetector(),
		NewEndpointDetector(), NewLibraryCallDetector(), NewSemanticMethodDetector(),
		NewVulnSecretDetector(), NewVulnNetworkDetector(), NewVulnDlopenObfuscationDetector(),
		NewVulnResourceIntegrityDetector(), NewVulnStagingEndpointDetector(), NewVulnModMenuInjectionDetector(),
		NewVulnCryptoDetector(), NewVulnWebViewDetector(), NewVulnZipSlipDetector(),
		NewVulnPendingIntentDetector(), NewVulnAndroidSurfaceDetector(),
		NewVulnDynamicLoadDetector(), NewVulnInsecureStorageDetector(),
	}
	return w, nil
}

func (w *FileScanWorker) Scan(ctx context.Context, task FileScanTask, content []byte) (FileScanResult, error) {
	var result FileScanResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	buffer := newFileBuffer(content)
	defer buffer.release()
	if task.Patterns {
		started := time.Now()
		result.Patterns = w.matcher.MatchContentWithFilterLower(buffer.String(), buffer.LowerString(), task.Job.RelPath, task.AppCode)
		result.PatternNs = time.Since(started).Nanoseconds()
	}
	analysis := types.NewFileAnalysis(task.Job.RelPath, task.Job.Type, task.Job.Size)
	analysis.IsAppCode = task.AppCode
	analysis.IsLibrary = task.Library
	dctx := &FileDetectContext{
		Ctx: ctx, Path: task.Job.RelPath, Content: content, ContentLower: buffer.Lower(),
		LineOffsets: buffer.LineOffsets(), IsAppCode: task.AppCode, FileType: task.Job.Type, Job: task.Job,
	}
	if task.Job.Type == types.FileTypeSmali && !strings.Contains(task.Job.RelPath, "smali_compact/") {
		sp := parser.NewSmaliParser(buffer.String())
		if class, err := sp.Parse(); err == nil {
			class.IsAppCode = task.AppCode
			lines := sp.Lines()
			for i := range class.Methods {
				m := &class.Methods[i]
				if m.LineStart > 0 && m.LineEnd >= m.LineStart && m.LineEnd <= len(lines) {
					m.Body = lines[m.LineStart-1 : m.LineEnd]
				}
			}
			dctx.Class = class
		}
	}
	result.Detectors = make(map[string]FileDetectorResult, len(w.detectors))
	for _, d := range w.detectors {
		if selective, ok := d.(FileTypeAwareDetector); ok && !selective.SupportsFile(task.Job.Type, task.Job.RelPath) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		analysis.Matches = nil
		started := time.Now()
		d.Detect(dctx, analysis)
		result.Detectors[d.Name()] = FileDetectorResult{Matches: analysis.Matches, DurationNs: time.Since(started).Nanoseconds()}
	}
	analysis.Matches = nil
	started := time.Now()
	w.piracy.Detect(&FileDetectContext{
		Ctx: ctx, Path: task.Job.RelPath, Content: content, ContentLower: buffer.Lower(),
		LineOffsets: buffer.LineOffsets(), IsAppCode: task.AppCode, FileType: task.Job.Type, Job: task.Job,
	}, analysis)
	result.Piracy = analysis.Matches
	result.PiracyNs = time.Since(started).Nanoseconds()
	return result, ctx.Err()
}
