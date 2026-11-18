package web

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"io"
	"testing"
)

type smallPNGReads struct {
	r    io.Reader
	size int
}

func (r smallPNGReads) Read(p []byte) (int, error) {
	if len(p) > r.size {
		p = p[:r.size]
	}
	return r.r.Read(p)
}

func screenPNGFixture(t *testing.T) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := png.Encode(&out, image.NewRGBA(image.Rect(0, 0, 2, 3))); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestLivePNGHandlesSplitHeadersAndConsecutiveFrames(t *testing.T) {
	frame := screenPNGFixture(t)
	for size := 1; size <= 11; size++ {
		r := smallPNGReads{r: bytes.NewReader(bytes.Repeat(frame, 2)), size: size}
		for i := 0; i < 2; i++ {
			got, err := readLivePNG(r)
			if err != nil || !bytes.Equal(got, frame) {
				t.Fatalf("read size %d, frame %d: %v", size, i, err)
			}
			if _, err := png.Decode(bytes.NewReader(got)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type unexpectedPNGRead struct{ t *testing.T }

func (r unexpectedPNGRead) Read([]byte) (int, error) {
	r.t.Fatal("a complete frame must not wait for the next frame or EOF")
	return 0, io.EOF
}

func TestLivePNGEmitsCompletedFrameBeforeNextRead(t *testing.T) {
	frame := screenPNGFixture(t)
	got, err := readLivePNG(io.MultiReader(bytes.NewReader(frame), unexpectedPNGRead{t}))
	if err != nil || !bytes.Equal(got, frame) {
		t.Fatalf("frame = %d bytes, error = %v", len(got), err)
	}
}

func TestLivePNGRejectsIncompleteAndOversizedFrames(t *testing.T) {
	frame := screenPNGFixture(t)
	oversized := append([]byte(nil), frame[:33]...)
	var chunk [8]byte
	binary.BigEndian.PutUint32(chunk[:4], maxLivePNGBytes)
	copy(chunk[4:], "IDAT")
	oversized = append(oversized, chunk[:]...)
	for _, input := range [][]byte{
		[]byte("screen capture error"), frame[:7], frame[:len(frame)-1], oversized,
	} {
		if got, err := readLivePNG(bytes.NewReader(input)); err == nil || got != nil {
			t.Fatalf("accepted malformed frame: %d bytes, %v", len(got), err)
		}
	}
}
