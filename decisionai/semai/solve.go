package semai

import (
	"fmt"
	"strings"
)

// SolveRequest is the single entry point of the "ask anything" page: a question, optional context
// and optional files. Only Question is required.
type SolveRequest struct {
	Question string `json:"question"`
	Context  string `json:"context,omitempty"`
	Files    []Doc  `json:"files,omitempty"`
}

type SolveReport struct {
	Version    string        `json:"version"`
	Mode       string        `json:"mode"`   // files | facts | semantic | none
	Answer     string        `json:"answer"` // yes | no | file name | option label | value | unknown
	AnswerText string        `json:"answer_text,omitempty"`
	Confidence float64       `json:"confidence"`
	Reasoning  []string      `json:"reasoning"`
	Files      *DocPick      `json:"files,omitempty"`
	Semantic   *Report       `json:"semantic,omitempty"`
	Solver     string        `json:"solver,omitempty"`
	Steps      []EventClause `json:"steps,omitempty"`
	Total      *EventTotal   `json:"total,omitempty"`
}

const (
	maxSolveFiles = 500
	maxFileBytes  = 256 * 1024
)

func Solve(r SolveRequest, enc *Encoder) (SolveReport, error) {
	q := strings.TrimSpace(r.Question)
	if q == "" {
		return SolveReport{}, fmt.Errorf("напиши вопрос")
	}
	if len(r.Files) > maxSolveFiles {
		return SolveReport{}, fmt.Errorf("слишком много файлов: %d (максимум %d)", len(r.Files), maxSolveFiles)
	}
	out := SolveReport{Version: Version, Answer: "unknown", Reasoning: []string{}}
	if len(r.Files) > 0 {
		docs := make([]Doc, len(r.Files))
		for i, f := range r.Files {
			c := f.Content
			if len(c) > maxFileBytes {
				c = c[:maxFileBytes]
			}
			docs[i] = Doc{Name: f.Name, Content: c}
		}
		p := PickDoc(q, docs, enc)
		out.Mode, out.Files, out.Answer, out.Confidence, out.Reasoning = "files", &p, p.Answer, p.Confidence, p.Reasoning
		if p.Answer == "none" {
			out.AnswerText = "ни один файл не подходит"
		}
		return out, nil
	}
	if fa := SolveFacts(r.Context, q); fa != nil && fa.Answer != "unknown" {
		out.Mode, out.Answer, out.Confidence, out.Reasoning = "facts", fa.Answer, fa.Confidence, fa.Reasoning
		out.Solver, out.Steps, out.Total = fa.Solver, fa.Steps, fa.Total
		if len(fa.Who) > 0 {
			out.AnswerText = strings.Join(fa.Who, ", ")
		}
		return out, nil
	}
	rep, err := Analyze(Request{Question: q, State: r.Context}, enc)
	if err != nil {
		return out, err
	}
	out.Semantic = &rep
	out.Mode = "semantic"
	out.Answer, out.AnswerText, out.Confidence = rep.Answer, rep.AnswerText, rep.Confidence
	out.Reasoning = append(out.Reasoning, rep.Reasoning...)
	if rep.Verdict != "answer" {
		out.Answer = "unknown"
		if len(out.Reasoning) == 0 {
			out.Reasoning = append(out.Reasoning, "не понял, что тут считать или сравнивать")
		}
	}
	return out, nil
}
