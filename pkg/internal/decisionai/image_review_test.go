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
	"image/color"
	"image/png"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type imageReviewTransport func(*http.Request) (*http.Response, error)

func (f imageReviewTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func imageReviewPNG(t *testing.T, shade uint8) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.SetRGBA(0, 0, color.RGBA{R: shade, G: 128, B: 64, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The transport exercises the real image request and response validation
// without a running service or network timing in concurrency tests.
func imageReviewClient(t *testing.T, before func(*http.Request) error) *Client {
	t.Helper()
	client, err := New(DefaultURL, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	client.http.Transport = imageReviewTransport(func(r *http.Request) (*http.Response, error) {
		if before != nil {
			if err := before(r); err != nil {
				return nil, err
			}
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}
		data, err := base64.StdEncoding.DecodeString(payload["data"])
		if err != nil {
			return nil, err
		}
		cfg, _, err := imageConfig(data)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		body, err := json.Marshal(ImageAnalysis{
			Width: cfg.Width, Height: cfg.Height, ImgSHA256: hex.EncodeToString(sum[:]), Scope: "full",
			Preview: &ImagePreview{PolicyVersion: 1, Status: "checked", Source: "test", Reason: "icon",
				Classes: []string{"icon"}, Regions: []PreviewRegion{{Class: "icon", W: 1, H: 1}}},
		})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	})
	return client
}

func TestImageReviewerDeduplicatesConcurrentImages(t *testing.T) {
	for _, limit := range []int{1, 8} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var requests atomic.Int32
				release := make(chan struct{})
				client := imageReviewClient(t, func(*http.Request) error {
					requests.Add(1)
					<-release
					return nil
				})
				reviewer := NewImageReviewer(context.Background(), client, limit)
				data := imageReviewPNG(t, 1)
				previews := make([]*ImagePreview, 8)
				go func() { previews[0] = reviewer.Review("0.png", data) }()
				synctest.Wait()
				for i := 1; i < len(previews); i++ {
					go func() { previews[i] = reviewer.Review(strconv.Itoa(i)+".png", data) }()
				}
				synctest.Wait()
				if report := reviewer.Report(); report.Requests != 1 || report.Total != 0 {
					t.Errorf("identical images must await one verdict: requests=%d completed=%d", report.Requests, report.Total)
				}
				close(release)
				synctest.Wait()
				for i, preview := range previews {
					if preview == nil || preview.Status != "checked" || preview.Blur {
						t.Errorf("image %d did not share the checked verdict: %+v", i, preview)
					}
				}
				report := reviewer.Report()
				if requests.Load() != 1 || report.Requests != 1 || report.Total != 8 || report.Checked != 8 || report.NotChecked != 0 || len(report.Entries) != 8 {
					t.Errorf("unexpected deduplication report: network requests=%d report=%+v", requests.Load(), report)
				}
			})
		})
	}
}

func TestImageReviewerUnsupportedImagesDoNotConsumeLimit(t *testing.T) {
	var requests atomic.Int32
	client := imageReviewClient(t, func(*http.Request) error { requests.Add(1); return nil })
	reviewer := NewImageReviewer(context.Background(), client, 1)
	for i, data := range [][]byte{nil, []byte("not an image"), make([]byte, MaxImageBytes+1)} {
		preview := reviewer.Review(strconv.Itoa(i), data)
		if preview.Reason != "unsupported_or_oversized_image" || !preview.Blur {
			t.Errorf("unsupported image received wrong verdict: %+v", preview)
		}
	}
	if preview := reviewer.Review("valid.png", imageReviewPNG(t, 1)); preview.Status != "checked" {
		t.Errorf("unsupported images exhausted the valid image's request slot: %+v", preview)
	}
	if report := reviewer.Report(); requests.Load() != 1 || report.Requests != 1 || report.Checked != 1 || report.NotChecked != 3 {
		t.Errorf("unexpected request accounting: network requests=%d report=%+v", requests.Load(), report)
	}
}

func TestImageReviewerConcurrentRequestLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var requests atomic.Int32
		release := make(chan struct{})
		client := imageReviewClient(t, func(*http.Request) error {
			requests.Add(1)
			<-release
			return nil
		})
		reviewer := NewImageReviewer(context.Background(), client, 2)
		for i := range 6 {
			data := imageReviewPNG(t, uint8(i))
			go reviewer.Review(strconv.Itoa(i)+".png", data)
		}
		synctest.Wait()
		if requests.Load() != 2 {
			t.Errorf("distinct images must use exactly two concurrent slots, got %d", requests.Load())
		}
		close(release)
		synctest.Wait()
		if report := reviewer.Report(); report.Requests != 2 || report.Total != 6 || report.Checked != 2 || report.NotChecked != 4 || report.Hidden != 4 {
			t.Errorf("request limit was not preserved: %+v", report)
		}
	})
}

func TestImageReviewerCancelsSharedRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var requests atomic.Int32
		client := imageReviewClient(t, func(r *http.Request) error {
			requests.Add(1)
			<-r.Context().Done()
			return r.Context().Err()
		})
		reviewer := NewImageReviewer(ctx, client, 8)
		data := imageReviewPNG(t, 1)
		previews := make([]*ImagePreview, 2)
		go func() { previews[0] = reviewer.Review("a.png", data) }()
		synctest.Wait()
		go func() { previews[1] = reviewer.Review("b.png", data) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		for i, preview := range previews {
			if preview == nil || preview.Status != "not_checked" || !preview.Blur {
				t.Errorf("cancelled image %d must finish with a hidden preview: %+v", i, preview)
			}
		}
		if report := reviewer.Report(); requests.Load() != 1 || report.Total != 2 || report.NotChecked != 2 || report.Hidden != 2 {
			t.Errorf("shared request did not finish on cancellation: network requests=%d report=%+v", requests.Load(), report)
		}
	})
}

func TestImageReviewerRespectsServiceCapacityAndDrainsQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var requests, active atomic.Int32
		release := make(chan struct{})
		client := imageReviewClient(t, func(*http.Request) error {
			requests.Add(1)
			n := active.Add(1)
			defer active.Add(-1)
			if n > 2 {
				return fmt.Errorf("inference capacity exceeded")
			}
			<-release
			return nil
		})
		reviewer := NewImageReviewer(context.Background(), client, 8)
		for i := range 8 {
			data := imageReviewPNG(t, uint8(i))
			go reviewer.Review(strconv.Itoa(i)+".png", data)
		}
		synctest.Wait()
		if requests.Load() != 2 || active.Load() != 2 {
			t.Errorf("service capacity must be two concurrent calls: requests=%d active=%d", requests.Load(), active.Load())
		}
		close(release)
		synctest.Wait()
		if report := reviewer.Report(); requests.Load() != 8 || report.Checked != 8 || report.NotChecked != 0 || report.Error != "" {
			t.Errorf("queued images were lost or overloaded the service: requests=%d report=%+v", requests.Load(), report)
		}
	})
}

func TestImageReviewerCancellationReleasesQueuedRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var requests atomic.Int32
		client := imageReviewClient(t, func(r *http.Request) error {
			requests.Add(1)
			<-r.Context().Done()
			return r.Context().Err()
		})
		reviewer := NewImageReviewer(ctx, client, 8)
		for i := range 8 {
			data := imageReviewPNG(t, uint8(i))
			go reviewer.Review(strconv.Itoa(i)+".png", data)
		}
		synctest.Wait()
		cancel()
		synctest.Wait()
		if report := reviewer.Report(); requests.Load() != 2 || report.Total != 8 || report.NotChecked != 8 || report.Hidden != 8 {
			t.Errorf("cancellation sent queued requests or lost hidden previews: requests=%d report=%+v", requests.Load(), report)
		}
	})
}

func TestImageReviewerServiceFailureStopsQueuedRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var requests atomic.Int32
		release := make(chan struct{})
		client := imageReviewClient(t, func(*http.Request) error {
			requests.Add(1)
			<-release
			return fmt.Errorf("service unavailable")
		})
		reviewer := NewImageReviewer(context.Background(), client, 8)
		for i := range 8 {
			data := imageReviewPNG(t, uint8(i))
			go reviewer.Review(strconv.Itoa(i)+".png", data)
		}
		synctest.Wait()
		close(release)
		synctest.Wait()
		if report := reviewer.Report(); requests.Load() != 2 || report.Total != 8 || report.NotChecked != 8 || report.Hidden != 8 || report.Error == "" {
			t.Errorf("service failure sent queued requests or was hidden: requests=%d report=%+v", requests.Load(), report)
		}
	})
}

func TestImageReviewerReportSnapshotIsIndependentAndSorted(t *testing.T) {
	reviewer := NewImageReviewer(context.Background(), imageReviewClient(t, nil), 1)
	data := imageReviewPNG(t, 1)
	preview := reviewer.Review("z.png", data)
	preview.Classes[0] = "changed"
	preview.Regions[0].Class = "changed"
	reviewer.Review("a.png", data)
	snapshot := reviewer.Report()
	if snapshot.Entries[0].Path != "a.png" || snapshot.Entries[1].Path != "z.png" {
		t.Errorf("report entries are not sorted by path: %+v", snapshot.Entries)
	}
	for _, entry := range snapshot.Entries {
		if entry.Preview.Classes[0] != "icon" || entry.Preview.Regions[0].Class != "icon" {
			t.Errorf("changing a returned preview corrupted the stored verdict: %+v", entry)
		}
	}
	snapshot.Entries[0].Path = "changed"
	snapshot.Entries[0].Preview.Classes[0] = "changed"
	snapshot.Entries[0].Preview.Regions[0].Class = "changed"
	for _, entry := range reviewer.Report().Entries {
		if entry.Path == "changed" || entry.Preview.Classes[0] != "icon" || entry.Preview.Regions[0].Class != "icon" {
			t.Errorf("changing a report snapshot corrupted reviewer state: %+v", entry)
		}
	}
	if cached := reviewer.Review("cached.png", data); cached.Classes[0] != "icon" || cached.Regions[0].Class != "icon" {
		t.Errorf("returned previews or reports corrupted the cache: %+v", cached)
	}
}
