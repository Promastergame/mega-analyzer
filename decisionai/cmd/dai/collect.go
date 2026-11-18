package main

import (
	"bufio"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"decisionai/vision"
)

//go:embed collect.html
var collectPage string

// collectFeedbackPath — JSONL для голосов RLHF. Задаётся флагом
// -collect-feedback (по умолчанию .tmp/collect-feedback.jsonl).
var collectFeedbackPath string

var collectMu sync.Mutex

// LikeBudget — максимум лайков (vote=+1) на одну картинку. Дизлайки без лимита.
const collectLikeMax = 25

type collectBox struct {
	Class string `json:"class"`
	X     int    `json:"x"`
	Y     int    `json:"y"`
	W     int    `json:"w"`
	H     int    `json:"h"`
}

type collectFeedback struct {
	ImgSHA256     string           `json:"img_sha256"`
	Width         int              `json:"width"`
	Height        int              `json:"height"`
	Box           collectBox       `json:"box"`
	Vote          int              `json:"vote"`
	Src           string           `json:"src"`
	Vector        *vision.VectorV1 `json:"vector,omitempty"`
	VectorVersion int              `json:"vector_version,omitempty"`
	Adult         *bool            `json:"adult,omitempty"`
}

var collectClasses = map[string]bool{
	"skin": true, "blood_dark": true, "blood_bright": true,
	"fluid_warm": true, "fluid_yellow": true, "fluid_white": true,
}

// Custom objects are annotation-only; they do not expand the color detector.
func validCustomCollectClass(class string) bool {
	if !strings.HasPrefix(class, "custom:") {
		return false
	}
	label := strings.TrimPrefix(class, "custom:")
	if !utf8.ValidString(label) || label != strings.TrimSpace(label) || utf8.RuneCountInString(label) < 1 || utf8.RuneCountInString(label) > 64 {
		return false
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
}

func (f collectFeedback) validate() error {
	if !validSHA256(strings.ToLower(f.ImgSHA256)) {
		return fmt.Errorf("img_sha256 must be 64 hex chars")
	}
	if f.Width < 1 || f.Height < 1 || f.Width > 10000 || f.Height > 10000 {
		return fmt.Errorf("width/height out of range 1..10000")
	}
	if !collectClasses[f.Box.Class] && !((f.Src == "hint" || (f.Src == "auto" && f.Vector != nil)) && validCustomCollectClass(f.Box.Class)) {
		return fmt.Errorf("unknown box class %q", f.Box.Class)
	}
	b := f.Box
	if b.X < 0 || b.Y < 0 || b.X >= f.Width || b.Y >= f.Height || b.W < 1 || b.H < 1 || b.W > f.Width-b.X || b.H > f.Height-b.Y {
		return fmt.Errorf("box is outside the image")
	}
	if f.Vote != 1 && f.Vote != -1 {
		return fmt.Errorf("vote must be 1 or -1")
	}
	if f.Src != "auto" && f.Src != "hint" {
		return fmt.Errorf("src must be auto or hint")
	}
	if (f.Vector == nil && f.VectorVersion != 0) || (f.Vector != nil && f.VectorVersion != vision.VectorVersion) {
		return fmt.Errorf("vector requires vector_version=1")
	}
	if f.Adult != nil && f.Vote != 1 {
		return fmt.Errorf("adult label requires a confirmed region")
	}
	return nil
}

// collectLikes counts stored likes for one image. Caller holds collectMu.
func collectLikes(path, sha string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	sha = strings.ToLower(sha)
	latest := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var row collectFeedback
		if json.Unmarshal(sc.Bytes(), &row) != nil || strings.ToLower(row.ImgSHA256) != sha || row.validate() != nil {
			continue
		}
		key := collectSampleKey(row)
		if _, ok := latest[key]; !ok && len(latest) >= collectModelMaxSamples {
			return 0, fmt.Errorf("annotation budget exceeded")
		}
		latest[key] = row.Vote
	}
	n := 0
	for _, vote := range latest {
		if vote == 1 {
			n++
		}
	}
	return n, sc.Err()
}

// Caller holds collectMu. Corrections to an existing positive do not consume
// another like; negative-to-positive changes still respect the active budget.
func collectPreviousVote(path string, f collectFeedback) (int, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	vote := 0
	key := collectSampleKey(f)
	for sc.Scan() {
		var row collectFeedback
		if json.Unmarshal(sc.Bytes(), &row) == nil && row.validate() == nil && collectSampleKey(row) == key {
			vote = row.Vote
		}
	}
	return vote, sc.Err()
}

func appendCollectFeedback(path string, f collectFeedback) error {
	collectMu.Lock()
	defer collectMu.Unlock()
	if f.Vote == 1 {
		n, err := collectLikes(path, f.ImgSHA256)
		if err != nil {
			return err
		}
		previous, err := collectPreviousVote(path, f)
		if err != nil {
			return err
		}
		if n >= collectLikeMax && previous != 1 {
			return fmt.Errorf("like budget exhausted (%d per image); dislikes and hints only", collectLikeMax)
		}
	}
	row := map[string]any{
		"ts": time.Now().Unix(), "img_sha256": strings.ToLower(f.ImgSHA256),
		"width": f.Width, "height": f.Height,
		"box": f.Box, "vote": f.Vote, "src": f.Src,
	}
	if f.Vector != nil {
		row["vector"] = f.Vector
		row["vector_version"] = f.VectorVersion
	}
	if f.Adult != nil {
		row["adult"] = *f.Adult
	}
	out, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	_, err = fh.Write(append(out, '\n'))
	if err == nil && collectModelCache.Path == path && collectModelCache.Model != nil {
		collectModelCache.Model.add(f)
		if info, e := fh.Stat(); e == nil {
			collectModelCache.Size = info.Size()
			collectModelCache.Modified = info.ModTime()
		}
	}
	return err
}

func registerCollect(mux *http.ServeMux, token string) {
	mux.HandleFunc("/v1/collect/model", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			collectJSONError(w, 405, "GET or POST required")
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(token)) != 1 {
			collectJSONError(w, 401, "invalid token")
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			collectJSONError(w, 415, "application/json required")
			return
		}
		serveCollectModel(w, r)
	})
	mux.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data: blob:; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		quoted, _ := json.Marshal(token)
		_, _ = io.WriteString(w, strings.ReplaceAll(collectPage, "__COLLECT_TOKEN__", string(quoted)))
	})
	mux.HandleFunc("/collect/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/collect", http.StatusFound)
	})
	mux.HandleFunc("/v1/collect/budget", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fail := func(code int, msg string) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
		}
		if r.Method != http.MethodGet {
			fail(405, "GET required")
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(token)) != 1 {
			fail(401, "invalid token")
			return
		}
		sha := r.URL.Query().Get("sha")
		if !validSHA256(sha) {
			fail(400, "invalid sha")
			return
		}
		if collectFeedbackPath == "" {
			fail(400, "start the server with -collect-feedback <file>")
			return
		}
		collectMu.Lock()
		n, err := collectLikes(collectFeedbackPath, sha)
		collectMu.Unlock()
		if err != nil {
			fail(500, err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]int{"likes": n, "max": collectLikeMax})
	})
	mux.HandleFunc("/v1/collect/feedback", func(w http.ResponseWriter, r *http.Request) {
		fail := func(code int, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		}
		if r.Method != http.MethodPost {
			fail(405, fmt.Errorf("POST required"))
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(token)) != 1 {
			fail(401, fmt.Errorf("invalid token"))
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			fail(415, fmt.Errorf("application/json required"))
			return
		}
		if collectFeedbackPath == "" {
			fail(400, fmt.Errorf("start the server with -collect-feedback <file>"))
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			fail(413, fmt.Errorf("request too large"))
			return
		}
		var f collectFeedback
		if err := strict(b, &f); err != nil {
			fail(400, err)
			return
		}
		if f.Src == "" {
			f.Src = "auto"
		}
		if err := f.validate(); err != nil {
			fail(400, err)
			return
		}
		if err := appendCollectFeedback(collectFeedbackPath, f); err != nil {
			if strings.Contains(err.Error(), "like budget") {
				fail(409, err)
				return
			}
			fail(500, err)
			return
		}
		collectMu.Lock()
		model, modelErr := loadCollectModel(collectFeedbackPath)
		learned := modelErr == nil && f.Vector != nil && model.Seen[collectSampleKey(f)]
		collectMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"saved": true, "learned": learned})
	})
}

func readCollectBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
}

func collectJSONError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
