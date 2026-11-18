package s1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"strings"
	"testing"

	"decisionai/vision"
)

type testVision struct{ calls int }

func (v *testVision) Describe(ctx context.Context, prompt string, images []vision.Image) (string, error) {
	v.calls++
	return "A red square is visible.", nil
}
func TestVisionDecisionAndMissingModel(t *testing.T) {
	var b bytes.Buffer
	_ = png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 1, 1)))
	r := Request{State: json.RawMessage(`"Describe the image"`), Images: []vision.Image{{Data: base64.StdEncoding.EncodeToString(b.Bytes()), MIMEType: "image/png"}}, Questions: map[string]Question{"q": {Type: TypeNoul, Instructions: json.RawMessage(`"Is a red square visible?"`)}}}
	e := NewEngine(LexicalBackend{}, DefaultCalibration())
	e.Vision = nil
	if _, err := e.Decide(r); err == nil || !strings.Contains(err.Error(), "image reader") {
		t.Fatalf("silently ignored image: %v", err)
	}
	v := &testVision{}
	e.Vision = v
	resp, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	if v.calls != 1 || resp.Answers["q"].Route == "auto" || len(resp.Warnings) == 0 || !strings.Contains(strings.Join(resp.Answers["q"].Evidence, " "), "red square") {
		t.Fatalf("missing image evidence: %+v", resp)
	}
	r.Questions = nil
	if _, err := e.Decide(r); err == nil || v.calls != 1 {
		t.Fatal("invalid request reached vision")
	}
}
