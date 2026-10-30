package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	client, err := decisionai.New(a.opts.DecisionAIURL, os.Getenv("DAI_API_TOKEN"))
	if err != nil {
		a.output.Warning("DecisionAI: %v", err)
		return
	}
	defer client.Close()
	a.output.Info("DecisionAI: reviewing existing findings (advisory only)...")
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.opts.DecisionAIBudget)*time.Second)
	defer cancel()
	report := decisionai.Triage(ctx, client, result.Findings, a.opts.DecisionAIMaxFindings)
	result.DecisionAI = &report
	if report.Error != "" {
		a.output.Warning("DecisionAI: %s", report.Error)
	}
	if err := writeDecisionAIReports(outputDir, report); err != nil {
		a.output.Warning("DecisionAI report: %v", err)
	}
	a.output.Info("DecisionAI: %d/%d findings reviewed; %d skipped. See DECISION_AI.txt and decision_ai.json", report.Processed, report.Total, report.Skipped)
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
