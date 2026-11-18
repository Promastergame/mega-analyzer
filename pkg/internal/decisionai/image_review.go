package decisionai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
)

type ImageReviewEntry struct {
	Path    string       `json:"path"`
	SHA256  string       `json:"sha256"`
	Preview ImagePreview `json:"preview"`
}

type ImageReviewReport struct {
	SchemaVersion int                `json:"schema_version"`
	AdvisoryOnly  bool               `json:"advisory_only"`
	Total         int                `json:"total_images"`
	Requests      int                `json:"requests"`
	Checked       int                `json:"checked_images"`
	NotChecked    int                `json:"not_checked_images"`
	Hidden        int                `json:"hidden_previews"`
	Error         string             `json:"error,omitempty"`
	Entries       []ImageReviewEntry `json:"entries"`
}

func (r *ImageReviewReport) PreviewFor(path string) *ImagePreview {
	if r == nil {
		return nil
	}
	path = strings.ReplaceAll(path, "\\", "/")
	for i := range r.Entries {
		if r.Entries[i].Path == path {
			return &r.Entries[i].Preview
		}
	}
	return nil
}

type imageReviewCall struct {
	done    chan struct{}
	preview ImagePreview
}

// DecisionAI shares a two-request inference limit across /v1/see and /v1/decide.
const maxVisionInFlight = 2

// ImageReviewer accepts bytes already read by the artifact pipeline. It opens
// no model-provided paths, retains no pixels, deduplicates byte-identical images
// and stops extra requests on the first service failure or exhausted budget.
type ImageReviewer struct {
	ctx    context.Context
	client *Client
	limit  int
	slots  chan struct{}
	// mu guards cache, pending and report: Review is called concurrently from the
	// artifacts worker pool. The network call itself runs without the lock
	// while slots keeps requests within the service's inference capacity.
	mu      sync.Mutex
	cache   map[string]ImagePreview
	pending map[string]*imageReviewCall
	report  ImageReviewReport
}

func NewImageReviewer(ctx context.Context, client *Client, limit int) *ImageReviewer {
	return &ImageReviewer{
		ctx: ctx, client: client, limit: max(0, limit),
		slots:   make(chan struct{}, maxVisionInFlight),
		cache:   make(map[string]ImagePreview),
		pending: make(map[string]*imageReviewCall),
		report:  ImageReviewReport{SchemaVersion: 1, AdvisoryOnly: true, Entries: []ImageReviewEntry{}},
	}
}

func uncheckedPreview(reason string) ImagePreview {
	return ImagePreview{PolicyVersion: 1, Status: "not_checked", Blur: true, Source: "decision_ai_vision", Reason: reason}
}

func (r *ImageReviewer) Review(path string, data []byte) *ImagePreview {
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	preview := r.review(hash, data)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.report.Total++
	if preview.Status == "checked" {
		r.report.Checked++
	} else {
		r.report.NotChecked++
	}
	if preview.Blur {
		r.report.Hidden++
	}
	r.report.Entries = append(r.report.Entries, ImageReviewEntry{
		Path: strings.ReplaceAll(path, "\\", "/"), SHA256: hash, Preview: cloneImagePreview(preview),
	})
	return &preview
}

func (r *ImageReviewer) review(hash string, data []byte) ImagePreview {
	r.mu.Lock()
	if preview, cached := r.cache[hash]; cached {
		r.mu.Unlock()
		return cloneImagePreview(preview)
	}
	if call, pending := r.pending[hash]; pending {
		r.mu.Unlock()
		// Identical images share an in-flight result even when its request
		// used the last available slot. Cancellation also releases waiters.
		select {
		case <-call.done:
			return cloneImagePreview(call.preview)
		case <-r.ctx.Done():
			return uncheckedPreview("time_budget_exhausted")
		}
	}
	reason := ""
	switch {
	case r.report.Error != "":
		reason = "service_unavailable"
	case r.ctx.Err() != nil:
		reason = "time_budget_exhausted"
	case r.report.Requests >= r.limit:
		reason = "image_request_limit"
	}
	if reason != "" {
		r.mu.Unlock()
		return uncheckedPreview(reason)
	}
	if _, _, err := imageConfig(data); err != nil {
		r.mu.Unlock()
		return uncheckedPreview("unsupported_or_oversized_image")
	}
	call := &imageReviewCall{done: make(chan struct{})}
	r.pending[hash] = call
	r.report.Requests++
	r.mu.Unlock()

	preview := uncheckedPreview("service_unavailable")
	analysis, err := r.analyzeImage(data)
	if err == nil {
		preview = *analysis.Preview
	} else if r.ctx.Err() != nil {
		preview = uncheckedPreview("time_budget_exhausted")
	}
	r.mu.Lock()
	if err != nil {
		if r.report.Error == "" {
			r.report.Error = err.Error()
		}
	} else {
		r.cache[hash] = preview
	}
	call.preview = preview
	delete(r.pending, hash)
	close(call.done)
	r.mu.Unlock()
	return cloneImagePreview(preview)
}

func (r *ImageReviewer) analyzeImage(data []byte) (ImageAnalysis, error) {
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-r.ctx.Done():
		return ImageAnalysis{}, r.ctx.Err()
	}
	if err := r.ctx.Err(); err != nil {
		return ImageAnalysis{}, err
	}
	r.mu.Lock()
	failed := r.report.Error != ""
	r.mu.Unlock()
	if failed {
		return ImageAnalysis{}, fmt.Errorf("DecisionAI vision stopped after a service failure")
	}
	analysis, err := r.client.AnalyzeImage(r.ctx, data)
	if err != nil {
		// Publish failure before releasing a slot so queued calls cannot race
		// ahead of the reviewer's stop-on-failure policy.
		r.mu.Lock()
		if r.report.Error == "" {
			r.report.Error = err.Error()
		}
		r.mu.Unlock()
	}
	return analysis, err
}

func cloneImagePreview(preview ImagePreview) ImagePreview {
	preview.Classes = slices.Clone(preview.Classes)
	preview.Regions = slices.Clone(preview.Regions)
	return preview
}

func (r *ImageReviewer) Report() ImageReviewReport {
	r.mu.Lock()
	report := r.report
	report.Entries = slices.Clone(report.Entries)
	for i := range report.Entries {
		report.Entries[i].Preview = cloneImagePreview(report.Entries[i].Preview)
	}
	r.mu.Unlock()
	slices.SortFunc(report.Entries, func(a, b ImageReviewEntry) int {
		if n := strings.Compare(a.Path, b.Path); n != 0 {
			return n
		}
		return strings.Compare(a.SHA256, b.SHA256)
	})
	return report
}
