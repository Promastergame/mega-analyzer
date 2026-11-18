package decisionai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"
)

const MaxImageBytes = 1 << 20
const MaxImagePixels = 1_048_576

// ImagePreview affects report presentation only. Scores describe heuristic
// similarity; they never affect findings, severity, CI or malware risk.
type ImagePreview struct {
	PolicyVersion int             `json:"policy_version"`
	Status        string          `json:"status"`
	Blur          bool            `json:"blur"`
	Classes       []string        `json:"classes,omitempty"`
	Score         int             `json:"score"`
	Source        string          `json:"source"`
	Reason        string          `json:"reason"`
	Calibrated    bool            `json:"calibrated"`
	Regions       []PreviewRegion `json:"regions,omitempty"`
}

type PreviewRegion struct {
	Class string `json:"class"`
	X     int    `json:"x"`
	Y     int    `json:"y"`
	W     int    `json:"w"`
	H     int    `json:"h"`
}

type ImageAnalysis struct {
	Width     int           `json:"width"`
	Height    int           `json:"height"`
	ImgSHA256 string        `json:"img_sha256"`
	Scope     string        `json:"scope"`
	Preview   *ImagePreview `json:"preview"`
}

func imageConfig(data []byte) (image.Config, string, error) {
	if len(data) == 0 || len(data) > MaxImageBytes {
		return image.Config{}, "", fmt.Errorf("image must contain 1..%d bytes", MaxImageBytes)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg" && format != "gif") {
		return image.Config{}, "", fmt.Errorf("unsupported or corrupt PNG, JPEG or GIF")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > MaxImagePixels/cfg.Height {
		return image.Config{}, "", fmt.Errorf("image exceeds %d pixels", MaxImagePixels)
	}
	return cfg, format, nil
}

func (c *Client) AnalyzeImage(ctx context.Context, data []byte) (ImageAnalysis, error) {
	var out ImageAnalysis
	cfg, format, err := imageConfig(data)
	if err != nil {
		return out, err
	}
	b, err := json.Marshal(struct {
		MIME string `json:"mime_type"`
		Data string `json:"data"`
	}{MIME: "image/" + format, Data: base64.StdEncoding.EncodeToString(data)})
	if err != nil {
		return out, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/v1/see", bytes.NewReader(b))
	if err != nil {
		return out, err
	}
	r.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return out, fmt.Errorf("DecisionAI vision unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("DecisionAI vision returned HTTP %d", resp.StatusCode)
	}
	b, err = readBounded(resp.Body, MaxResponseBytes)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return ImageAnalysis{}, fmt.Errorf("invalid DecisionAI vision response: %w", err)
	}
	sum := sha256.Sum256(data)
	if out.Width != cfg.Width || out.Height != cfg.Height || out.ImgSHA256 != hex.EncodeToString(sum[:]) {
		return ImageAnalysis{}, fmt.Errorf("DecisionAI image identity or dimensions do not match")
	}
	p := out.Preview
	if p == nil || (p.PolicyVersion != 1 && p.PolicyVersion != 2) || (p.Status != "checked" && p.Status != "partial") || p.Score < 0 || p.Score > 100 || len(p.Classes) > 16 || len(p.Regions) > 16 || len(p.Reason) > 512 || len(p.Source) > 128 {
		return ImageAnalysis{}, fmt.Errorf("DecisionAI preview policy missing or invalid; update the local service")
	}
	if p.Status == "partial" && !p.Blur {
		return ImageAnalysis{}, fmt.Errorf("incomplete image coverage cannot certify a visible preview")
	}
	for _, class := range p.Classes {
		if len(class) > 128 {
			return ImageAnalysis{}, fmt.Errorf("DecisionAI preview class exceeds limit")
		}
	}
	for _, region := range p.Regions {
		if len(region.Class) > 128 || region.X < 0 || region.Y < 0 || region.W < 1 || region.H < 1 || region.W > cfg.Width || region.H > cfg.Height || region.X > cfg.Width-region.W || region.Y > cfg.Height-region.H {
			return ImageAnalysis{}, fmt.Errorf("DecisionAI preview region outside original image")
		}
	}
	return out, nil
}
