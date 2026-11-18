// Command dai is the DecisionAI System One CLI and HTTP server.
//
//	dai decide    -input request.json
//	dai serve     -addr 127.0.0.1:7480
//	dai eval      -input labelled.jsonl [-calib calib.json]
//	dai calibrate -input labelled.jsonl -output calib.json
//	dai bench     -input request.json -n 50
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"decisionai/experts"
	"decisionai/smalirole"
	"decisionai/textai"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"decisionai/games"
	"decisionai/s1"
	"decisionai/semai"
	"decisionai/vision"
)

//go:embed playground.html
var playground string

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dai:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: dai decide|serve|see|game|play|mcp-tools|eval|data-check|distill-export|skills-eval|skills-calibrate|skills-learn|calibrate|bench|version [flags]")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	input := fs.String("input", "-", "input file (- for stdin)")
	imagePath := fs.String("image", "", "see: image file (PNG/JPEG/GIF)")
	light := fs.Bool("light", false, "game/vision profile: one worker, no neural text weights; text fallback is lexical")
	output := fs.String("output", "", "output file")
	addr := fs.String("addr", "127.0.0.1:7480", "listen address")
	allowRemote := fs.Bool("allow-remote", false, "allow non-loopback listen address (token required)")
	encPath := fs.String("encoder", "", "encoder weights (default models/encoder-tiny.dte)")
	nliPath := fs.String("nli", "", "NLI weights (default models/nli-tiny.dte)")
	distilled := fs.String("distilled", "", "distilled System One encoder (default models/s1-distilled.dte), used by -backend s1")
	calibPath := fs.String("calib", "", "calibration JSON (default models/s1-calibration.json if present)")
	workers := fs.Int("workers", 0, "parallel workers (default: CPU count)")
	backendName := fs.String("backend", "s1", "s1 (default: v1.7 distilled encoder, base bi-encoder for skills; falls back to embed) | embed (v1.6) | nli | lexical")
	n := fs.Int("n", 30, "bench iterations")
	useExperts := fs.Bool("experts", true, "use specialised experts (checks/server rules, smalirole, textai) before the general model")
	useLex := fs.Bool("lex", true, "fuse lexical evidence (concept lexicon + description overlap) into general-model answers")
	lexScale := fs.String("lex-scale", "", "per-type lexical weight multipliers, e.g. noul=0.5,choice=1 (default: backend preset)")
	rolePath := fs.String("role-model", "", "smalirole model (default models/smalirole-model.json)")
	textPath := fs.String("text-model", "", "patch-confirmation text model (default models/demo-text-model.json)")
	skillsRoots := fs.String("skills", "", "comma-separated skill roots to index (enables task=skill_routing without criteria)")
	skillsGloss := fs.String("skills-gloss", "", "optional JSON {skill name: Russian gloss} merged into skill descriptions")
	skillsExamples := fs.String("skills-examples", "", "few-shot routing memory, JSONL {state, skill}; skills-learn and POST /v1/skills/feedback append to it")
	collectFeedback := fs.String("collect-feedback", filepath.Join(".tmp", "collect-feedback.jsonl"), "RLHF votes for the /collect page, JSONL {img_sha256, width, height, box, vote, src}")
	learnState := fs.String("state", "", "skills-learn: the request text")
	learnSkill := fs.String("skill", "", "skills-learn: the correct skill")
	escModel := fs.String("escalate", "", "System Two cascade: re-ask uncertain answers from a remote decision model, e.g. typesafe/jev-1.13 or respan/span-01-lite:free (key: OPENROUTER_API_KEY or DAI_ESCALATE_KEY)")
	escOn := fs.String("escalate-on", "review,human", "routes to escalate (comma list; all = every answer)")
	escLog := fs.String("escalate-log", "", "append System Two answers here as labelled training data (JSONL) and reuse them as an offline cache")
	escURL := fs.String("escalate-url", s1.DefaultEscalationURL, "decisions API endpoint for -escalate")
	minNoul := fs.Float64("min-noul", 0, "fail eval when noul agreement is below this (0 disables)")
	minChoice := fs.Float64("min-choice", 0, "fail eval when choice agreement is below this (0 disables)")
	minScore := fs.Float64("min-score", 0, "fail eval when score agreement is below this (0 disables)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if cmd == "version" {
		fmt.Println("dai", s1.Version)
		return nil
	}
	var visual vision.Describer = vision.Local{}
	if *light || cmd == "see" || cmd == "game" || cmd == "play" || cmd == "mcp-tools" {
		runtime.GOMAXPROCS(1)
		debug.SetMemoryLimit(64 << 20) // soft Go memory target, not an OS RAM guarantee
	}
	if cmd == "see" || cmd == "game" || cmd == "play" || cmd == "mcp-tools" {
		return runInteraction(cmd, *input, *output, *imagePath, visual)
	}
	if *light {
		if *escModel != "" || *skillsRoots != "" || *encPath != "" || *distilled != "" || *nliPath != "" {
			return fmt.Errorf("-light excludes neural weights, escalation and skill models")
		}
		*backendName, *useExperts = "lexical", false
	}
	// These commands compile data but never run inference or need model weights.
	if cmd == "data-check" || cmd == "distill-export" {
		*backendName, *useExperts = "lexical", false
	}
	distilledPath = *distilled
	collectFeedbackPath = *collectFeedback
	eng, err := buildEngine(*backendName, *encPath, *nliPath, *calibPath, *workers)
	if err != nil {
		return err
	}
	eng.NoLex = !*useLex
	eng.Vision = visual
	if *light {
		eng.Experts = []s1.Expert{experts.Game{}}
	}
	if *lexScale != "" {
		eng.LexScale = map[string]float64{}
		for _, kv := range strings.Split(*lexScale, ",") {
			k, v, _ := strings.Cut(kv, "=")
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				return fmt.Errorf("-lex-scale %q: %v", kv, err)
			}
			eng.LexScale[strings.TrimSpace(k)] = f
		}
	}
	if *escModel != "" {
		key := os.Getenv("DAI_ESCALATE_KEY")
		if key == "" {
			key = os.Getenv("OPENROUTER_API_KEY")
		}
		local := isLoopbackURL(*escURL) // v1.14: local System Two (scripts/distill/llm_teacher.py serve) needs no key
		if key == "" && !local {
			return fmt.Errorf("-escalate needs OPENROUTER_API_KEY or DAI_ESCALATE_KEY")
		}
		if local {
			key = "" // never send a cloud key to a local server
		}
		eng.Escalate = s1.NewEscalator(*escModel, key)
		eng.Escalate.URL = *escURL
		if local {
			eng.Escalate.Timeout = 15 * time.Minute // a CPU LLM answers in seconds per question
		}
		if eng.Escalate.Log = *escLog; *escLog != "" {
			if err := eng.Escalate.LoadLog(); err != nil {
				return fmt.Errorf("-escalate-log: %v", err)
			}
		}
		eng.Escalate.On = map[string]bool{}
		for _, r := range strings.Split(*escOn, ",") {
			eng.Escalate.On[strings.TrimSpace(r)] = true
		}
		defer func() {
			if n, h, c := eng.Escalate.Stats(); n+h > 0 {
				fmt.Fprintf(os.Stderr, "escalated %d answers to %s (+%d from cache), cost $%.6f\n", n, *escModel, h, c)
			}
		}()
	}
	if *useExperts {
		if eng.Experts, err = loadExperts(*rolePath, *textPath); err != nil {
			return err
		}
	}
	if *skillsRoots != "" {
		reg, err := s1.LoadSkillRegistry(strings.Split(*skillsRoots, ","), *skillsGloss)
		if err != nil {
			return err
		}
		eng.Skills = reg
		fmt.Fprintf(os.Stderr, "skills: %d indexed\n", len(reg.Skills))
		if *skillsExamples != "" && cmd != "skills-calibrate" {
			n, err := reg.LoadSkillExamples(*skillsExamples)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			fmt.Fprintf(os.Stderr, "skills: %d examples\n", n)
		}
		skillExamplesPath = *skillsExamples
	}
	// Hash auxiliary model files without retaining or eagerly loading their tensors.
	eng.AuxiliaryFingerprint, err = auxiliaryFingerprint(eng, *encPath, *rolePath, *textPath)
	if err != nil {
		return err
	}
	switch cmd {
	case "data-check":
		data, err := readLabelled(*input)
		if err != nil {
			return err
		}
		if err := validateDataset(eng, data); err != nil {
			return err
		}
		questions := 0
		for _, row := range data {
			questions += len(row.Labels)
		}
		return emit(*output, map[string]any{"valid": true, "examples": len(data), "questions": questions})
	case "decide":
		b, err := read(*input)
		if err != nil {
			return err
		}
		var r s1.Request
		if err := strict(b, &r); err != nil {
			return err
		}
		resp, err := eng.Decide(r)
		if err != nil {
			return err
		}
		return emit(*output, resp)
	case "eval":
		data, err := readLabelled(*input)
		if err != nil {
			return err
		}
		rep := eng.Evaluate(data)
		if err := emit(*output, rep); err != nil {
			return err
		}
		return checkQuality(rep, map[string]float64{"noul": *minNoul, "choice": *minChoice, "score": *minScore})
	case "calibrate":
		data, err := readLabelled(*input)
		if err != nil {
			return err
		}
		if err := validateDataset(eng, data); err != nil {
			return err
		}
		c, errs := eng.Calibrate(data)
		if len(errs) > 0 {
			return fmt.Errorf("calibration failed: %s", strings.Join(errs, "; "))
		}
		if *output == "" {
			*output = filepath.Join("models", "s1-calibration.json")
		}
		return emit(*output, c)
	case "skills-eval":
		if eng.Skills == nil {
			return fmt.Errorf("skills-eval needs -skills <dir>")
		}
		b, err := read(*input)
		if err != nil {
			return err
		}
		cases, err := s1.ReadSkillCases(bytes.NewReader(b))
		if err != nil {
			return err
		}
		rep, err := eng.EvaluateSkills(cases)
		if err != nil {
			return err
		}
		if err := emit(*output, rep); err != nil {
			return err
		}
		if *minChoice > 0 && rep.Top1 < *minChoice {
			return fmt.Errorf("skill routing top1 %.3f is below -min-choice %.3f", rep.Top1, *minChoice)
		}
		return nil
	case "skills-learn":
		if eng.Skills == nil || *skillsExamples == "" {
			return fmt.Errorf("skills-learn needs -skills <dir> and -skills-examples <file>")
		}
		return appendSkillExample(eng.Skills, *skillsExamples, *learnState, *learnSkill)
	case "skills-calibrate":
		if eng.Skills == nil {
			return fmt.Errorf("skills-calibrate needs -skills <dir>")
		}
		b, err := read(*input)
		if err != nil {
			return err
		}
		cases, err := s1.ReadSkillCases(bytes.NewReader(b))
		if err != nil {
			return err
		}
		t, n, err := s1.CalibrateSkills(func() (*s1.Engine, error) {
			e2 := *eng
			reg, err := s1.LoadSkillRegistry(strings.Split(*skillsRoots, ","), *skillsGloss)
			e2.Skills = reg
			return &e2, err
		}, cases)
		if err != nil {
			return err
		}
		cal := eng.Calib
		if eng.CalibrationIssue() != "" {
			cal = s1.DefaultCalibration()
		} // Do not bind stale temperatures for other tasks.
		temps, fitted := map[string]float64{}, map[string]int{}
		for k, v := range cal.Temps {
			temps[k] = v
		}
		for k, v := range cal.Fitted {
			fitted[k] = v
		}
		temps[s1.TaskSkillRouting], fitted[s1.TaskSkillRouting] = t, n
		cal.Temps, cal.Fitted = temps, fitted
		cal, err = eng.BindCalibration(cal)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "skill_routing: temperature %.3f fitted on %d cross-fitted cases\n", t, n)
		if *output == "" {
			*output = filepath.Join("models", "s1-calibration.json")
		}
		return emit(*output, cal)
	case "distill-export":
		// one JSONL line per labelled request: the exact chunks and per-option
		// hypotheses the engine scores, plus the label — input for scripts/distill
		data, err := readLabelled(*input)
		if err != nil {
			return err
		}
		if err := validateDataset(eng, data); err != nil {
			return err
		}
		var w io.Writer = os.Stdout
		if *output != "" {
			f, err := os.Create(*output)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		for i, l := range data {
			chunks, plans, err := eng.Plans(l.Request)
			if err != nil {
				return fmt.Errorf("record %d: %v", i+1, err)
			}
			type qrow struct {
				s1.QuestionPlan
				Label json.RawMessage `json:"label,omitempty"`
			}
			rows := make([]qrow, 0, len(plans))
			for _, p := range plans {
				rows = append(rows, qrow{p, l.Labels[p.ID]})
			}
			if err := enc.Encode(map[string]any{"group": l.Group, "chunks": chunks, "questions": rows}); err != nil {
				return err
			}
		}
		return nil
	case "bench":
		return bench(eng, *input, *n)
	case "serve":
		if *light {
			if err := vision.Warmup(); err != nil {
				return fmt.Errorf("vision warmup: %w", err)
			}
		}
		return serve(eng, *addr, *allowRemote)
	}
	return fmt.Errorf("unknown command %q", cmd)
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

func buildEngine(kind, encPath, nliPath, calibPath string, workers int) (*s1.Engine, error) {
	var backend s1.Backend = s1.LexicalBackend{}
	if p := findModel(encPath, "encoder-tiny.dte"); p != "" && kind == "embed" {
		enc, err := semai.LoadEncoder(p)
		if err != nil {
			return nil, fmt.Errorf("encoder: %v", err)
		}
		backend = s1.NewCachedBackend(s1.NewEmbedBackend(enc), s1.DefaultJudgementCacheBytes)
	} else if kind == "s1" {
		// Self-contained distilled models can serve ordinary decisions without
		// loading the base bi-encoder used only for skill routing.
		q := findModel(distilledPath, "s1-distilled.dte")
		if q == "" {
			fmt.Fprintln(os.Stderr, "warning: models/s1-distilled.dte not found, falling back to -backend embed")
			return buildEngine("embed", encPath, nliPath, calibPath, workers)
		}
		// v1.11: -distilled a.dte,b.dte (or models/s1-distilled.dte + models/s1-distilled-b.dte) = ensemble
		var members []s1.Backend
		paths := strings.Split(q, ",")
		if distilledPath == "" {
			if b := findModel("", "s1-distilled-b.dte"); b != "" {
				paths = append(paths, b)
			}
		}
		var bases []*semai.Encoder
		var enc *semai.Encoder
		loadBase := func() (*semai.Encoder, error) {
			if enc != nil {
				return enc, nil
			}
			if p == "" {
				return nil, fmt.Errorf("encoder-tiny.dte not found; use -encoder to supply the skill/shared-table base")
			}
			loaded, err := semai.LoadCrossEncoderAny(p, bases...)
			if err != nil {
				return nil, fmt.Errorf("encoder: %w", err)
			}
			enc = loaded
			return enc, nil
		}
		for _, path := range paths {
			// word table: own, or shared with an already loaded encoder of the same base checkpoint
			de, err := semai.LoadCrossEncoderAny(strings.TrimSpace(path), bases...)
			if errors.Is(err, semai.ErrBaseRequired) {
				// Legacy fine-tunes omit the word table. Load their base now,
				// then retry only this explicitly identified format condition.
				base, baseErr := loadBase()
				if baseErr != nil {
					return nil, baseErr
				}
				de, err = semai.LoadCrossEncoderAny(strings.TrimSpace(path), append(bases, base)...)
			}
			if err != nil {
				return nil, fmt.Errorf("s1-distilled %s: %v", path, err)
			}
			bases = append(bases, de)
			mb := s1.NewEmbedBackend(de)
			mb.Label = fmt.Sprintf("System One %c", 'A'+len(members))
			members = append(members, mb)
		}
		// v1.16.1: readable names (the .dte metadata still lists the v1.8 teachers)
		var general s1.Backend = members[0]
		members[0].(*s1.EmbedBackend).Label = "System One v" + s1.Version
		if len(members) > 1 {
			general = s1.EnsembleBackend{Members: members, Label: fmt.Sprintf("System One v%s · ансамбль из %d моделей", s1.Version, len(members))}
		}
		if calibPath == "" {
			// the distilled model has its own logit scale: prefer its calibration
			calibPath = findModel("", "s1-distilled-calibration.json")
		}
		eng, err := finishEngine(s1.NewCachedBackend(general, s1.DefaultJudgementCacheBytes), calibPath)
		if err != nil {
			return nil, err
		}
		eng.SkillBackendLoader = s1.NewBackendLoader(func() (s1.Backend, error) {
			base, err := loadBase()
			if err != nil {
				return nil, err
			}
			sk := s1.NewEmbedBackend(base)
			sk.Label = "System One · выбор скилла"
			return s1.NewCachedBackend(sk, s1.DefaultJudgementCacheBytes), nil
		})
		// per-type best dev log-loss (data/distill/dev: synthetic dev + golden-calib), never test sets
		eng.LexScale = map[string]float64{s1.TypeNoul: 0, s1.TypeChoice: 1, s1.TypeScore: 0.5}
		return eng, nil
	} else if p != "" && kind == "nli" {
		enc, err := semai.LoadEncoder(p)
		if err != nil {
			return nil, fmt.Errorf("encoder: %v", err)
		}
		if q := findModel(nliPath, "nli-tiny.dte"); q != "" {
			ce, err := semai.LoadCrossEncoder(q, enc)
			if err != nil {
				return nil, fmt.Errorf("nli: %v", err)
			}
			backend = s1.NewNLIBackend(ce, workers)
		}
	}
	return finishEngine(backend, calibPath)
}

// distilledPath is set from -distilled before buildEngine runs.
var distilledPath string

func finishEngine(backend s1.Backend, calibPath string) (*s1.Engine, error) {
	calib := s1.DefaultCalibration()
	if p := findModel(calibPath, "s1-calibration.json"); p != "" {
		c, err := s1.LoadCalibration(p)
		if err != nil {
			return nil, fmt.Errorf("calibration: %v", err)
		}
		calib = c
	}
	if backend.Name() == "lexical-fallback" {
		fmt.Fprintln(os.Stderr, "warning: NLI weights not found, using lexical fallback (answers routed to human)")
	}
	return s1.NewEngine(backend, calib), nil
}

func read(path string) ([]byte, error) {
	var rd io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		rd = f
	}
	b, err := io.ReadAll(io.LimitReader(rd, 64<<20+1))
	if len(b) > 64<<20 {
		return nil, fmt.Errorf("input exceeds 64 MiB")
	}
	return b, err
}

func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return fmt.Errorf("trailing data after JSON value")
	}
	return nil
}

// readLabelled accepts JSONL (one Labelled per line) or a JSON array.
func readLabelled(path string) ([]s1.Labelled, error) {
	b, err := read(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSpace(b)
	var out []s1.Labelled
	if len(b) > 0 && b[0] == '[' {
		return out, json.Unmarshal(b, &out)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for ln := 1; sc.Scan(); ln++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		var l s1.Labelled
		if err := json.Unmarshal(line, &l); err != nil {
			return nil, fmt.Errorf("line %d: %v", ln, err)
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

func emit(path string, v any) error {
	var w io.Writer = os.Stdout
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// checkQuality fails the eval when a gated question type regresses below its
// minimum agreement. A minimum of 0 disables the gate for that type.
func checkQuality(rep s1.EvalReport, mins map[string]float64) error {
	if len(rep.Errors) > 0 {
		return fmt.Errorf("eval contains %d invalid examples/labels: %s", len(rep.Errors), rep.Errors[0])
	}
	if rep.Questions == 0 {
		return fmt.Errorf("eval contains no labelled questions")
	}
	var bad []string
	for _, t := range []string{"noul", "choice", "score"} {
		min := mins[t]
		if min <= 0 {
			continue
		}
		m, ok := rep.ByType[t]
		if !ok {
			return fmt.Errorf("eval quality: no %s questions in report", t)
		}
		if m.Agreement < min {
			bad = append(bad, fmt.Sprintf("%s agreement %.4f < minimum %.4f", t, m.Agreement, min))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("eval quality regression: %s", strings.Join(bad, "; "))
	}
	return nil
}

func validateDataset(eng *s1.Engine, data []s1.Labelled) error {
	if len(data) == 0 {
		return fmt.Errorf("dataset contains no labelled examples")
	}
	for i, row := range data {
		if err := eng.ValidateLabelled(row); err != nil {
			return fmt.Errorf("record %d: %w", i+1, err)
		}
	}
	return nil
}

func bench(eng *s1.Engine, input string, n int) error {
	b, err := read(input)
	if err != nil {
		return err
	}
	var r s1.Request
	if err := strict(b, &r); err != nil {
		return err
	}
	// cold = first call (no cache); warm calls use a perturbed state to defeat the cache
	var lat []float64
	var calls int
	for i := 0; i < n; i++ {
		rr := r
		var st string
		if json.Unmarshal(r.State, &st) == nil {
			st = fmt.Sprintf("%s (#%d)", st, i)
		} else {
			st = fmt.Sprintf("%s\nrun: %d", string(r.State), i)
		}
		rr.State, _ = json.Marshal(st)
		t := time.Now()
		resp, err := eng.Decide(rr)
		if err != nil {
			return err
		}
		lat = append(lat, float64(time.Since(t).Microseconds())/1000)
		calls = resp.Usage.ModelCalls
	}
	sort.Float64s(lat)
	p := func(q float64) float64 { return lat[int(math.Min(float64(len(lat)-1), q*float64(len(lat))))] }
	return emit("", map[string]any{"backend": eng.Backend.Name(), "questions": len(r.Questions), "pairs_per_call": calls, "iterations": n,
		"latency_ms": map[string]float64{"p50": p(.5), "p95": p(.95), "min": lat[0], "max": lat[len(lat)-1]}})
}

func serve(eng *s1.Engine, addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	loopback := ip != nil && ip.IsLoopback()
	if !loopback && !allowRemote {
		return fmt.Errorf("non-loopback address requires -allow-remote")
	}
	token := os.Getenv("DAI_API_TOKEN")
	if token == "" {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		token = hex.EncodeToString(raw)
		fmt.Fprintln(os.Stderr, "DAI_API_TOKEN not set; generated token:", token)
	}
	h := Handler(eng, token, loopback)
	if loopback {
		h = hostGuard(addr, h)
	}
	srv := http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	fmt.Fprintf(os.Stderr, "DecisionAI System One %s on http://%s  (модель: %s, ядро: %s)\n", s1.Version, addr, eng.Backend.Name(), semai.AccelName())
	if loopback {
		fmt.Fprintf(os.Stderr, "Web Menu:   http://%s/\n", addr)
		fmt.Fprintf(os.Stderr, "Playground: http://%s/playground\n", addr)
		fmt.Fprintf(os.Stderr, "Games:      http://%s/games\n", addr)
		fmt.Fprintf(os.Stderr, "Collect:    http://%s/collect\n", addr)
		fmt.Fprintf(os.Stderr, "Text Q&A:   http://%s/text\n", addr)
		fmt.Fprintf(os.Stderr, "Eval:       http://%s/eval\n", addr)
		fmt.Fprintf(os.Stderr, "Rules:      http://%s/rules\n", addr)
	}
	return srv.ListenAndServe()
}

// Handler exposes /v1/decide, /v1/health and (loopback only) /playground.
func Handler(eng *s1.Engine, token string, playgroundEnabled bool) http.Handler {
	mux := http.NewServeMux()
	jsonErr := func(w http.ResponseWriter, code int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		names := []string{}
		for _, x := range eng.Experts {
			names = append(names, x.Name())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "version": s1.Version, "backend": eng.Backend.Name(), "model": eng.ModelName, "experts": names, "accel": semai.AccelName(), "configuration_fingerprint": eng.ConfigurationFingerprint(), "calibration_issue": eng.CalibrationIssue(), "vision_configured": eng.Vision != nil, "games": games.SupportedGames()})
	})
	mux.HandleFunc("/v1/game", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonErr(w, 405, "POST required")
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			jsonErr(w, 401, "invalid or missing bearer token")
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			jsonErr(w, 415, "application/json required")
			return
		}
		gameHandler(w, r)
	})
	mux.HandleFunc("/v1/see", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonErr(w, 405, "POST required")
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			jsonErr(w, 401, "invalid or missing bearer token")
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			jsonErr(w, 415, "application/json required")
			return
		}
		var input vision.Image
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if err != nil {
			jsonErr(w, 413, "request too large")
			return
		}
		if err := strict(b, &input); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		result, err := (vision.Local{}).Analyze(r.Context(), input)
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		// Feedback is advisory and never turns a rejected class into a safety
		// verdict. Keep the pixel observation even if its local log is unavailable.
		if collectFeedbackPath != "" {
			collectMu.Lock()
			model, modelErr := loadCollectModel(collectFeedbackPath)
			if modelErr == nil {
				match := model.predict(result.Vector)
				result.Preview.AddFeedbackMatch(match.Class, match.Score, vision.PreviewRegion{W: result.Width, H: result.Height})
				for _, box := range result.Boxes {
					match = model.predict(box.Vector)
					result.Preview.AddFeedbackMatch(match.Class, match.Score, vision.PreviewRegion{X: box.X, Y: box.Y, W: box.W, H: box.H})
				}
			}
			collectMu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/v1/skills/feedback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonErr(w, 405, "POST required")
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			jsonErr(w, 401, "invalid or missing bearer token")
			return
		}
		if eng.Skills == nil || skillExamplesPath == "" {
			jsonErr(w, 400, "start the server with -skills and -skills-examples")
			return
		}
		var fb struct {
			State string `json:"state"`
			Skill string `json:"skill"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&fb); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		if err := appendSkillExample(eng.Skills, skillExamplesPath, fb.State, fb.Skill); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"learned":true}`))
	})
	mux.HandleFunc("/v1/decide", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonErr(w, 405, "POST required")
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			jsonErr(w, 401, "invalid or missing bearer token")
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			jsonErr(w, 415, "application/json required")
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if err != nil {
			jsonErr(w, 413, "request too large")
			return
		}
		var req s1.Request
		if err := strict(b, &req); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		resp, err := eng.DecideContext(r.Context(), req)
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(resp)
	})
	if playgroundEnabled {
		registerWebMenu(mux, token)
		registerArena(mux, token)
		registerCollect(mux, token)
		mux.HandleFunc("/playground", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, strings.ReplaceAll(playground, "__TOKEN__", token))
		})
	}
	return limitInference(mux, 2)
}

// hostGuard blocks DNS-rebinding: on loopback only the exact listen host is accepted.
func hostGuard(addr string, next http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(addr)
	ok := map[string]bool{addr: true, "localhost:" + port: true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok[r.Host] {
			http.Error(w, "invalid Host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loadExperts(rolePath, textPath string) ([]s1.Expert, error) {
	var role *smalirole.Model
	if p := findModel(rolePath, "smalirole-model.json"); p != "" {
		m, err := smalirole.LoadModel(p)
		if err != nil {
			return nil, fmt.Errorf("role model %s: %v", p, err)
		}
		role = m
	}
	var text *textai.Model
	if p := findModel(textPath, "demo-text-model.json"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var m textai.Model
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("text model %s: %v", p, err)
		}
		if err := m.Validate(); err != nil {
			return nil, fmt.Errorf("text model %s: %v", p, err)
		}
		text = &m
	}
	return experts.Default(role, text), nil
}

var skillExamplesPath string
var learnMu sync.Mutex

// appendSkillExample teaches the router a corrected request: it is added to
// the live registry and appended to the examples file.
func appendSkillExample(reg *s1.SkillRegistry, path, state, skill string) error {
	state = strings.TrimSpace(state)
	if state == "" || !reg.Has(skill) {
		return fmt.Errorf("need a non-empty state and a known skill (got %q)", skill)
	}
	learnMu.Lock()
	defer learnMu.Unlock()
	if !reg.AddExample(skill, state) {
		return nil // already known
	}
	line, _ := json.Marshal(map[string]string{"state": state, "skill": skill})
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// isLoopbackURL reports whether u points at this machine (http://127.0.0.1, ::1 or localhost).
func isLoopbackURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return false
	}
	h := p.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
