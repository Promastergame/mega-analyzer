// Package vision implements bounded CPU-only image analysis without model weights.
package vision

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"strings"
)

const MaxImages = 1
const MaxImageBytes = 1 << 20
const MaxPixels = 1_048_576

// Layout describes a board crop in the ORIGINAL image coordinate system.
// Zero width/height select the whole image. Maze screenshots need rows/columns.
type Layout struct {
	Left        int     `json:"left,omitempty"`
	Top         int     `json:"top,omitempty"`
	Width       int     `json:"width,omitempty"`
	Height      int     `json:"height,omitempty"`
	Rows        int     `json:"rows,omitempty"`
	Columns     int     `json:"columns,omitempty"`
	Profile     string  `json:"profile,omitempty"`
	Turn        *Region `json:"turn,omitempty"`
	Orientation string  `json:"orientation,omitempty"`
}

// Region is a visible UI rectangle in original image pixels.
type Region struct {
	Left   int `json:"left"`
	Top    int `json:"top"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

type Image struct {
	Data     string  `json:"data"`
	MIMEType string  `json:"mime_type"`
	Layout   *Layout `json:"layout,omitempty"`
}

type Describer interface {
	Describe(context.Context, string, []Image) (string, error)
}

// Validate inspects encoded bytes, including dimensions, without expanding pixels.
// Remote URLs and local file paths are deliberately not part of the wire format.
func Validate(images []Image) error {
	if len(images) == 0 || len(images) > MaxImages {
		return fmt.Errorf("images must contain 1..%d images", MaxImages)
	}
	for i, im := range images {
		if len(im.Data) == 0 || len(im.Data) > base64.StdEncoding.EncodedLen(MaxImageBytes) {
			return fmt.Errorf("image %d exceeds 1 MiB or is empty", i)
		}
		b, err := base64.StdEncoding.Strict().DecodeString(im.Data)
		if err != nil || len(b) > MaxImageBytes {
			return fmt.Errorf("image %d: invalid or oversized base64", i)
		}
		cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("image %d: unsupported or corrupt PNG, JPEG or GIF", i)
		}
		if im.MIMEType != "image/"+format {
			return fmt.Errorf("image %d: mime_type does not match %s bytes", i, format)
		}
		if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > MaxPixels/cfg.Height {
			return fmt.Errorf("image %d: dimensions exceed %d pixels", i, MaxPixels)
		}
	}
	return nil
}

func ValidateDescription(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("image reader returned an empty description")
	}
	if len(s) > 32<<10 {
		return fmt.Errorf("vision description exceeds 32 KiB")
	}
	return nil
}
