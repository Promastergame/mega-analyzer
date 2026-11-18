package patcheffect

import (
	"strings"

	"decisionai/smalirole"
)

// Overwrite is another iput/sput of the field the patched literal is stored into.
type Overwrite struct {
	Field       string `json:"field"`
	Method      string `json:"method"` // Lcls;->name(params)
	Line        int    `json:"line"`   // line inside that method's text
	Text        string `json:"text"`
	DefaultOnly bool   `json:"default_only"` // the patched store is in <init>/<clinit>, the other one is not
}

const maxOverwrites = 8

func shortField(ref string) string {
	if i := strings.Index(ref, "->"); i >= 0 {
		return ref[i+2:]
	}
	return ref
}

// FieldOverwrites finds other writes of every field the literal is stored into (needs ctx.Writers, i.e. -app).
func FieldOverwrites(req Request, rr smalirole.Report, ctx *smalirole.Ctx) []Overwrite {
	if ctx == nil || ctx.Writers == nil || len(rr.Stored) == 0 {
		return nil
	}
	self := smalirole.ParseMethod(req.Class, req.Code)
	init := self.Name == "<init>" || self.Name == "<clinit>"
	var out []Overwrite
	for _, f := range rr.Stored {
		for _, w := range ctx.Writers(f) {
			m := w.Method
			if m.Name == self.Name && strings.Join(m.Params, "") == strings.Join(self.Params, "") && (req.Class == "" || m.Class == req.Class) {
				continue // the patched method itself
			}
			// a constructor of the same class writing the same default is not an overwrite of a static/default store
			other := m.Name == "<init>" || m.Name == "<clinit>"
			in := m.Insns[w.Index]
			out = append(out, Overwrite{Field: f, Method: smalirole.MethodKey(m), Line: in.Line, Text: strings.TrimSpace(in.Raw), DefaultOnly: init && !other})
			if len(out) >= maxOverwrites {
				return out
			}
		}
	}
	// lifecycle/setter overwrites of a default value matter most: show them first
	for i := range out {
		if out[i].DefaultOnly && i > 0 {
			out[0], out[i] = out[i], out[0]
			break
		}
	}
	return out
}
