package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"time"

	"mega-analyzer/pkg/internal/decisionai"
	"mega-analyzer/pkg/internal/types"
)

func (a *App) runDecisionAIRequest() error {
	f, err := os.Open(a.opts.DecisionAIInput)
	if err != nil {
		return fmt.Errorf("read DecisionAI input: %w", err)
	}
	defer f.Close()
	req, err := decisionai.ReadRequest(f)
	if err != nil {
		return err
	}
	client, err := decisionai.New(a.opts.DecisionAIURL, os.Getenv("DAI_API_TOKEN"))
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.opts.DecisionAIBudget)*time.Second)
	defer cancel()
	resp, err := client.Decide(ctx, req)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

func (a *App) runDecisionAITriage(ctx context.Context, result *types.AnalysisResult, outputDir string) {
	if a.opts.DecisionAIURL == "" || result == nil {
		return
	}
	source := collectSourceEvidence(ctx, result)
	result.SourceEvidence = &source
	if err := writeSourceEvidenceReports(outputDir, source); err != nil {
		a.output.Warning("Source evidence report: %v", err)
	}
	client, err := decisionai.New(a.opts.DecisionAIURL, os.Getenv("DAI_API_TOKEN"))
	if err != nil {
		a.output.Warning("DecisionAI: %v", err)
		return
	}
	defer client.Close()
	a.output.Info("DecisionAI: reviewing existing findings (advisory only)...")
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.opts.DecisionAIBudget)*time.Second)
	defer cancel()
	var priorSource *decisionai.SourceReviewReport
	if result.DecisionAI != nil {
		priorSource = result.DecisionAI.SourceReview
	}
	sourceReview := decisionai.ReviewSource(ctx, client, source, priorSource)
	codeReview := decisionai.ReviewCodeRoles(ctx, client, source, decisionai.MaxNeuralRoles)
	report := decisionai.TriageWithPrior(ctx, client, result.Findings, a.opts.DecisionAIMaxFindings, result.DecisionAI)
	report.SourceReview = &sourceReview
	report.CodeReview = &codeReview
	result.DecisionAI = &report
	if report.Error != "" {
		a.output.Warning("DecisionAI: %s", report.Error)
	}
	if sourceReview.Error != "" {
		a.output.Warning("DecisionAI source review: %s", sourceReview.Error)
	}
	if codeReview.Error != "" {
		a.output.Warning("DecisionAI neural code roles: %s", codeReview.Error)
	}
	a.output.Info("DecisionAI neural code roles: %d predictions (%d uncertain), %d skipped, %d failed, %d not processed; scope: numeric literals in retained methods",
		codeReview.Inferred, codeReview.Uncertain, codeReview.Skipped, codeReview.Failed, codeReview.NotProcessed)
	a.output.Info("DecisionAI source checks: %d/%d reviewed, %d consistent with retained static evidence, %d need review",
		sourceReview.Processed, sourceReview.Total, sourceReview.Consistent, sourceReview.Unresolved)
	if err := writeDecisionAIReports(outputDir, report); err != nil {
		a.output.Warning("DecisionAI report: %v", err)
	}
	a.output.Info("DecisionAI: %d/%d risk findings reviewed; %d observations/protections remain in the main report. See DECISION_AI.txt and decision_ai.json", report.Processed, report.Reviewable, report.Observations)
}

func writeDecisionAIReports(dir string, report decisionai.Report) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "decision_ai.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "DECISION_AI.txt"), []byte(report.Text()), 0600)
}

func (a *App) beginDecisionAIImageReview(ctx context.Context) (*decisionai.ImageReviewer, func()) {
	if a.opts.DecisionAIURL == "" || !a.opts.DecisionAIImages {
		return nil, func() {}
	}
	client, err := decisionai.New(a.opts.DecisionAIURL, os.Getenv("DAI_API_TOKEN"))
	if err != nil {
		a.output.Warning("DecisionAI vision: %v", err)
		return nil, func() {}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.opts.DecisionAIImageBudget)*time.Second)
	return decisionai.NewImageReviewer(ctx, client, a.opts.DecisionAIMaxImages), func() { cancel(); client.Close() }
}

func (a *App) finishDecisionAIImageReview(reviewer *decisionai.ImageReviewer, result *types.AnalysisResult, outputDir string) {
	if reviewer == nil || result == nil {
		return
	}
	paths := make([]string, 0, len(result.Files))
	for path := range result.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		file := result.Files[path]
		if file == nil || file.MediaData == nil || file.MediaData.Classification.MediaExtra == nil {
			continue
		}
		thumbnail := file.MediaData.Classification.MediaExtra.Thumbnail
		if len(thumbnail) > 0 {
			// Embedded thumbnails can differ from the displayed photograph.
			reviewer.Review(file.Path+"::thumbnail", thumbnail)
		}
	}
	report := reviewer.Report()
	result.DecisionAIImages = &report
	if b, err := json.MarshalIndent(report, "", "  "); err == nil {
		if err := os.WriteFile(filepath.Join(outputDir, "decision_ai_images.json"), append(b, '\n'), 0600); err != nil {
			a.output.Warning("DecisionAI image report: %v", err)
		}
	}
	if report.Error != "" {
		a.output.Warning("DecisionAI vision: %s; unchecked previews remain hidden", report.Error)
	}
	a.output.Info("DecisionAI vision: %d images checked; %d unchecked; %d previews hidden", report.Checked, report.NotChecked, report.Hidden)
}
