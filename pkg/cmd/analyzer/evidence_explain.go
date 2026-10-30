package main

import (
	"encoding/json"
	"fmt"
	"os"

	"mega-analyzer/pkg/internal/evidencegraph"
	"mega-analyzer/pkg/internal/types"
)

func (a *App) runEvidenceExplain() error {
	data, err := os.ReadFile(a.opts.ExplainResult)
	if err != nil {
		return fmt.Errorf("read analysis result: %w", err)
	}
	var result types.AnalysisResult
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode analysis result: %w", err)
	}
	chain, err := evidencegraph.Query(result.EvidenceGraph, a.opts.ExplainNode, a.opts.ExplainFile)
	if err != nil {
		return err
	}
	if a.opts.ExplainFormat == "json" {
		encoded, err := json.MarshalIndent(chain, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, string(encoded))
		return err
	}
	if a.opts.ExplainFormat != "" && a.opts.ExplainFormat != "text" {
		return fmt.Errorf("unsupported explain format %q (use text or json)", a.opts.ExplainFormat)
	}
	fmt.Fprintln(os.Stdout, chain.Summary)
	for _, edge := range chain.Edges {
		fmt.Fprintf(os.Stdout, "- %s --%s--> %s", edge.From, edge.Relation, edge.To)
		if edge.Label != "" {
			fmt.Fprintf(os.Stdout, " (%s)", edge.Label)
		}
		fmt.Fprintln(os.Stdout)
	}
	return nil
}
