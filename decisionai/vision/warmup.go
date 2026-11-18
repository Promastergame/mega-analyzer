package vision

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
)

// Warmup prepares decoder/search code before a resident light server accepts
// requests. Startup is intentionally outside its response-latency budget.
func Warmup() error {
	im := image.NewGray(image.Rect(0, 0, 96, 96))
	for y := 0; y < 96; y++ {
		for x := 0; x < 96; x++ {
			c := uint8(255)
			if (x >= 31 && x <= 33) || (x >= 63 && x <= 65) || (y >= 31 && y <= 33) || (y >= 63 && y <= 65) {
				c = 0
			}
			im.SetGray(x, y, color.Gray{Y: c})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, im); err != nil {
		return err
	}
	_, err := (Local{}).ReadGame(context.Background(), "tic_tac_toe", []Image{{Data: base64.StdEncoding.EncodeToString(b.Bytes()), MIMEType: "image/png"}})
	return err
}
