package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"decisionai/engine"
	"decisionai/patcheffect"
	"decisionai/semai"
	"decisionai/smalirole"
	"decisionai/textai"
	"decisionai/web"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

func read(path string) ([]byte, error) {
	var rd io.Reader = os.Stdin
	if path != "-" {
		f, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		rd = f
	}
	b, e := io.ReadAll(io.LimitReader(rd, 8*1024*1024+1))
	if len(b) > 8*1024*1024 {
		return nil, fmt.Errorf("input exceeds 8 MiB")
	}
	return b, e
}
func emit(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
func load(path, target string) (*engine.Model, error) {
	if path == "" {
		return nil, nil
	}
	b, e := read(path)
	if e != nil {
		return nil, e
	}
	var m engine.Model
	if e = engine.Decode(b, &m); e != nil {
		return nil, e
	}
	if e = m.Validate(); e != nil {
		return nil, e
	}
	if m.Target != target {
		return nil, fmt.Errorf("wrong model target")
	}
	return &m, nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "decision-ai:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("commands: solve, ask, ask-batch, analyze, batch, test, train, import-analyzer, text-analyze, text-batch, text-train, text-eval, role, patch-effect, eval, serve, version")
	}
	cmd := args[0]
	if cmd == "eval" {
		return runEval(args[1:])
	}
	if cmd == "version" {
		fmt.Println(engine.Version)
		return nil
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	input := fs.String("input", "-", "JSON file or - for stdin")
	output := fs.String("output", "", "model output file (train)")
	fm := fs.String("finding-model", "", "trained finding model JSON")
	tm := fs.String("text-model", "", "trained text model JSON (synthetic demos are labelled)")
	rolePath := fs.String("role-model", "", "Smali literal-role model (default: models/smalirole-model.json if present)")
	encPath := fs.String("encoder", "", "Transformer encoder weights (default: models/encoder-tiny.dte if present)")
	nliPath := fs.String("nli", "", "NLI cross-encoder weights (default: models/nli-tiny.dte if present)")
	pm := fs.String("patch-model", "", "trained patch model JSON")
	threshold := fs.Float64("threshold", -1, "override both thresholds (0..1)")
	question := fs.String("q", "", "question (solve)")
	ctxText := fs.String("context", "", "optional context/facts (solve)")
	filesDir := fs.String("dir", "", "folder with text files to choose from (solve)")
	appDir := fs.String("app", "", "apktool output dir of the app (CLI only): follows fields and callees across classes")
	addr := fs.String("addr", "127.0.0.1:7475", "loopback address (serve)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	thresholdSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "threshold" {
			thresholdSet = true
		}
	})
	if thresholdSet && (math.IsNaN(*threshold) || math.IsInf(*threshold, 0) || *threshold < 0 || *threshold > 1) {
		return fmt.Errorf("threshold must be in [0,1]")
	}
	finding, e := load(*fm, "finding")
	if e != nil {
		return e
	}
	patch, e := load(*pm, "patch")
	if e != nil {
		return e
	}
	textModel, e := loadText(*tm)
	if e != nil {
		return e
	}
	semEnc, e := loadSemantic(*encPath, *nliPath)
	if e != nil {
		return e
	}
	semanticEncoder = semEnc
	if p := findModel(*rolePath, "smalirole-model.json"); p != "" {
		if roleModel, e = smalirole.LoadModel(p); e != nil {
			return fmt.Errorf("role model %s: %v", p, e)
		}
	}
	var app *smalirole.App
	if *appDir != "" {
		if app, e = smalirole.LoadApp(*appDir, false); e != nil {
			return fmt.Errorf("app %s: %v", *appDir, e)
		}
		fmt.Fprintf(os.Stderr, "decision-ai: app index: %d files, %d methods\n", app.Files, len(app.Methods))
	}
	appCtx := func(code string) *smalirole.Ctx { return app.Ctx() }
	// role → patch synergy: every planned patch is explained by the literal-role model.
	engine.PatchAdvisor = patcheffect.Advisor(roleModel, appCtx)
	analyzeText := func(r textai.Request) (textai.Report, error) {
		if thresholdSet {
			r.Threshold = threshold
		}
		rep, err := textai.Analyze(r, textModel)
		if err == nil {
			if fa := semai.SolveFacts(r.State, r.Question); fa != nil && fa.Answer != "unknown" {
				rep.Facts = &textai.FactsAnswer{Answer: fa.Answer, Who: fa.Who, Confidence: fa.Confidence, Reasoning: fa.Reasoning, Solver: fa.Solver}
				if len(fa.Steps) > 0 {
					rep.Facts.Steps = fa.Steps
				}
				if fa.Total != nil {
					rep.Facts.Total = fa.Total
				}
			}
			rep = routeToSemantic(r, rep)
		}
		return rep, err
	}
	analyze := func(r engine.Request) (engine.Report, error) {
		if *threshold >= 0 {
			r.Threshold = &engine.Thresholds{Finding: *threshold, Patch: *threshold}
		}
		return engine.Analyze(r, finding, patch)
	}
	if cmd == "serve" {
		return serve(*addr, analyze, analyzeText)
	}
	b, e := read(*input)
	if e != nil {
		return e
	}
	switch cmd {
	case "solve":
		req := semai.SolveRequest{Question: *question, Context: *ctxText}
		if *question == "" {
			b, e := read(*input)
			if e != nil {
				return e
			}
			if e = json.Unmarshal(b, &req); e != nil {
				return e
			}
		}
		if *filesDir != "" {
			docs, e := readDocs(*filesDir)
			if e != nil {
				return e
			}
			req.Files = append(req.Files, docs...)
		}
		rep, e := semai.Solve(req, semanticEncoder)
		if e != nil {
			return e
		}
		return emit(rep)
	case "ask":
		var r semai.Request
		if e = engine.Decode(b, &r); e != nil {
			return e
		}
		if thresholdSet {
			r.Threshold = threshold
		}
		rep, e := semai.Analyze(r, semEnc)
		if e != nil {
			return e
		}
		return emit(rep)
	case "role":
		var r smalirole.Request
		if e = engine.Decode(b, &r); e != nil {
			return e
		}
		if thresholdSet {
			r.Threshold = threshold
		}
		if r.Class == "" {
			r.Class = app.Locate(r.Code)
		}
		rep, e := smalirole.AnalyzeCtx(r, roleModel, app.Ctx())
		if e != nil {
			return e
		}
		return emit(rep)
	case "patch-effect":
		var r patcheffect.Request
		if e = engine.Decode(b, &r); e != nil {
			return e
		}
		if r.Class == "" {
			r.Class = app.Locate(r.Code)
		}
		rep, e := patcheffect.AnalyzeCtx(r, roleModel, app.Ctx())
		if e != nil {
			return e
		}
		return emit(rep)
	case "ask-batch":
		var rs []semai.Request
		if e = engine.Decode(b, &rs); e != nil {
			return e
		}
		if len(rs) > 1000 {
			return fmt.Errorf("batch limit: 1000")
		}
		reps := []semai.Report{}
		for _, r := range rs {
			if thresholdSet {
				r.Threshold = threshold
			}
			rep, e := semai.Analyze(r, semEnc)
			if e != nil {
				return e
			}
			reps = append(reps, rep)
		}
		return emit(reps)
	case "text-analyze":
		var r textai.Request
		if e = engine.Decode(b, &r); e != nil {
			return e
		}
		rep, e := analyzeText(r)
		if e != nil {
			return e
		}
		return emit(rep)
	case "text-batch":
		var rs []textai.Request
		if e = engine.Decode(b, &rs); e != nil {
			return e
		}
		if len(rs) > 1000 {
			return fmt.Errorf("batch limit: 1000")
		}
		reps := []textai.Report{}
		for _, r := range rs {
			rep, e := analyzeText(r)
			if e != nil {
				return e
			}
			reps = append(reps, rep)
		}
		return emit(reps)
	case "text-train":
		var d textai.Dataset
		if e = engine.Decode(b, &d); e != nil {
			return e
		}
		if *output == "" {
			return fmt.Errorf("text-train requires -output")
		}
		m, e := textai.Train(d)
		if e != nil {
			return e
		}
		encoded, e := json.MarshalIndent(m, "", "  ")
		if e != nil {
			return e
		}
		if e = os.WriteFile(*output, encoded, 0600); e != nil {
			return e
		}
		return emit(m.Metrics)
	case "text-eval":
		var d textai.Dataset
		if e = engine.Decode(b, &d); e != nil {
			return e
		}
		if textModel == nil {
			return fmt.Errorf("text-eval requires -text-model")
		}
		thresholdValue := 0.85
		if thresholdSet {
			thresholdValue = *threshold
		}
		rep, e := textai.Evaluate(d, textModel, thresholdValue)
		if e != nil {
			return e
		}
		return emit(rep)
	case "analyze":
		var r engine.Request
		if e = engine.Decode(b, &r); e != nil {
			return e
		}
		report, e := analyze(r)
		if e != nil {
			return e
		}
		return emit(report)
	case "batch":
		var rs []engine.Request
		if e = engine.Decode(b, &rs); e != nil {
			return e
		}
		if len(rs) > 1000 {
			return fmt.Errorf("batch limit: 1000")
		}
		reports := []engine.Report{}
		for _, r := range rs {
			rep, e := analyze(r)
			if e != nil {
				return e
			}
			reports = append(reports, rep)
		}
		return emit(reports)
	case "test":
		var suite engine.TestSuite
		if e = engine.Decode(b, &suite); e != nil {
			return e
		}
		results, e := engine.RunSuite(suite, finding, patch)
		if e != nil {
			return e
		}
		if e = emit(results); e != nil {
			return e
		}
		if results.Failed > 0 {
			return fmt.Errorf("%d scenario(s) failed", results.Failed)
		}
		return nil
	case "train":
		var d engine.Dataset
		if e = engine.Decode(b, &d); e != nil {
			return e
		}
		m, e := engine.Train(d)
		if e != nil {
			return e
		}
		if *output == "" {
			return fmt.Errorf("train requires -output")
		}
		encoded, e := json.MarshalIndent(m, "", "  ")
		if e != nil {
			return e
		}
		if e = os.WriteFile(*output, encoded, 0600); e != nil {
			return e
		}
		return emit(m.Metrics)
	case "import-analyzer":
		rs, e := engine.ImportAnalyzer(b)
		if e != nil {
			return e
		}
		return emit(rs)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}
func serve(addr string, analyze func(engine.Request) (engine.Report, error), analyzeText func(textai.Request) (textai.Report, error)) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("only numeric loopback addresses allowed")
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return err
	}
	token := hex.EncodeToString(raw)
	guarded := makeHandler(addr, token, analyze, analyzeText)
	srv := http.Server{Addr: addr, Handler: guarded, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	fmt.Fprintln(os.Stderr, "DecisionAI:", "http://"+addr, "(offline, Ctrl+C to stop)")
	return srv.ListenAndServe()
}

// semanticEncoder is the (optional) Transformer used by /api/ask; nil means symbolic layer only.
var semanticEncoder *semai.Encoder

// semanticPromoteFloor is the minimum confidence a cross-engine answer needs
// before it may replace unknown. The NLI head is documented as weak on
// numbers and rare phrasings, so a lukewarm 0.59 must stay unknown instead of
// becoming a wrong no/yes.
const semanticPromoteFloor = 0.65

// routeToSemantic asks the meaning engine when the lexical patch model
// abstains. It only ever replaces unknown (never a yes/no), records
// provenance in Semantic/AbstentionReasons, and keeps gate blocking intact.
// textai.Analyze itself stays pure: training, bundling and text-eval never
// route, so their metrics keep measuring the lexical model only.
func routeToSemantic(r textai.Request, rep textai.Report) textai.Report {
	if rep.Answer != "unknown" {
		return rep
	}
	promote := func(answer string, srep any) {
		rep.Semantic = srep
		rep.Answer = answer
		rep.AbstentionReasons = []string{"routed_to_semantic"}
		rep.Warnings = append(rep.Warnings, "Ответ дан смысловым движком (semai), а не лексической моделью патчей: проверяй reasoning и confidence, а не только ответ.")
		if rep.Gate.Status == "blocked" {
			rep.Decision = "blocked"
		} else {
			rep.Decision = "review"
		}
	}
	// 1. Deterministic solvers (facts/riddles/arithmetic): cheap and exact.
	if srep, serr := semai.Solve(semai.SolveRequest{Question: r.Question, Context: r.State}, semanticEncoder); serr == nil {
		if (srep.Answer == "yes" || srep.Answer == "no") && srep.Confidence >= semanticPromoteFloor &&
			(srep.Mode == "facts" || (srep.Semantic != nil && srep.Semantic.Verdict == "answer")) {
			promote(srep.Answer, srep)
			return rep
		}
	}
	// 2. Criteria yes/no when the request carries true/false_when.
	if r.TrueWhen != "" && r.FalseWhen != "" {
		if srep, serr := semai.Analyze(semai.Request{Question: r.Question, State: r.State, TrueWhen: r.TrueWhen, FalseWhen: r.FalseWhen, Threshold: r.Threshold}, semanticEncoder); serr == nil {
			if srep.Verdict == "answer" && (srep.Answer == "yes" || srep.Answer == "no") && srep.Confidence >= semanticPromoteFloor {
				promote(srep.Answer, srep)
				return rep
			}
		}
	}
	return rep
}

var roleModel *smalirole.Model

// readDocs loads text files (≤256 KiB, up to 500) under dir for `solve -dir`.
func readDocs(dir string) ([]semai.Doc, error) {
	var docs []semai.Doc
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if n := d.Name(); n != "." && strings.HasPrefix(n, ".") || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if len(docs) >= 500 {
			return filepath.SkipAll
		}
		st, e := d.Info()
		if e != nil || st.Size() > 256*1024 {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil || !utf8.Valid(b) {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		docs = append(docs, semai.Doc{Name: filepath.ToSlash(rel), Content: string(b)})
		return nil
	})
	return docs, err
}

func findModel(explicit, name string) string {
	if explicit != "" {
		return explicit
	}
	cands := []string{filepath.Join("models", name)}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		cands = append(cands, filepath.Join(d, "models", name), filepath.Join(d, "..", "models", name))
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func loadSemantic(encPath, nliPath string) (*semai.Encoder, error) {
	p := findModel(encPath, "encoder-tiny.dte")
	if p == "" {
		return nil, nil
	}
	enc, err := semai.LoadEncoder(p)
	if err != nil {
		return nil, fmt.Errorf("encoder %s: %v", p, err)
	}
	if q := findModel(nliPath, "nli-tiny.dte"); q != "" {
		ce, err := semai.LoadCrossEncoder(q, enc)
		if err != nil {
			return nil, fmt.Errorf("nli %s: %v", q, err)
		}
		enc.AttachCross(ce)
	}
	return enc, nil
}

func makeHandler(addr, token string, analyze func(engine.Request) (engine.Report, error), textHandlers ...func(textai.Request) (textai.Report, error)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(strings.ReplaceAll(string(web.Page), "__SESSION_TOKEN__", token)))
	})
	mux.HandleFunc("/text", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		_, _ = w.Write([]byte(strings.ReplaceAll(string(web.TextPage), "__SESSION_TOKEN__", token)))
	})
	mux.HandleFunc("/eval", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		_, _ = w.Write(web.EvalPage)
	})
	mux.HandleFunc("/api/eval-report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if b, err := os.ReadFile("models/eval-report.json"); err == nil { // fresh `decision-ai eval -out models/eval-report.json`
			_, _ = w.Write(b)
			return
		}
		_, _ = w.Write(web.EvalReport)
	})
	mux.HandleFunc("/api/solve", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("X-DecisionAI-Token") != token {
			http.Error(w, "invalid local session token", 403)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "application/json required", 415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32*1024*1024)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			w.WriteHeader(413)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "слишком большой запрос (больше 32 МБ)"})
			return
		}
		var req semai.SolveRequest
		var rep semai.SolveReport
		if e = engine.Decode(b, &req); e == nil {
			rep, e = semai.Solve(req, semanticEncoder)
		}
		if e != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(rep)
	})
	mux.HandleFunc("/api/ask", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("X-DecisionAI-Token") != token {
			http.Error(w, "invalid local session token", 403)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "application/json required", 415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "request too large", 413)
			return
		}
		var req semai.Request
		var rep semai.Report
		if e = engine.Decode(b, &req); e == nil {
			rep, e = semai.Analyze(req, semanticEncoder)
		}
		if e != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(rep)
	})
	mux.HandleFunc("/api/role", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("X-DecisionAI-Token") != token {
			http.Error(w, "invalid local session token", 403)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "application/json required", 415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "request too large", 413)
			return
		}
		var req smalirole.Request
		var rep smalirole.Report
		if e = engine.Decode(b, &req); e == nil {
			rep, e = smalirole.Analyze(req, roleModel, nil)
		}
		if e != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(rep)
	})
	mux.HandleFunc("/api/patch-effect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("X-DecisionAI-Token") != token {
			http.Error(w, "invalid local session token", 403)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "application/json required", 415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "request too large", 413)
			return
		}
		var req patcheffect.Request
		var rep patcheffect.Report
		if e = engine.Decode(b, &req); e == nil {
			rep, e = patcheffect.Analyze(req, roleModel, nil)
		}
		if e != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(rep)
	})
	mux.HandleFunc("/api/text", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("X-DecisionAI-Token") != token {
			http.Error(w, "invalid local session token", 403)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "application/json required", 415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "request too large", 413)
			return
		}
		var req textai.Request
		var rep textai.Report
		if e = engine.Decode(b, &req); e == nil {
			if len(textHandlers) > 0 {
				rep, e = textHandlers[0](req)
			} else {
				rep, e = textai.Analyze(req, nil)
			}
		}
		if e != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(rep)
	})
	mux.HandleFunc("/api/analyze", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("X-DecisionAI-Token") != token {
			http.Error(w, "invalid local session token", 403)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "application/json required", 415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "request too large", 413)
			return
		}
		var req engine.Request
		if e = engine.Decode(b, &req); e != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			return
		}
		rep, e := analyze(req)
		if e != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(rep)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != addr {
			http.Error(w, "invalid Host", 403)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func loadText(path string) (*textai.Model, error) {
	if path == "" {
		return nil, nil
	}
	b, e := read(path)
	if e != nil {
		return nil, e
	}
	var m textai.Model
	if e = engine.Decode(b, &m); e != nil {
		return nil, e
	}
	if e = m.Validate(); e != nil {
		return nil, e
	}
	return &m, nil
}
