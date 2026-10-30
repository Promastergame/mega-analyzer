package web

import "strconv"

// Only the full static pipeline currently has typed findings for this adapter.
// The token stays in the process environment, never in logged CLI arguments.
func (s *Server) decisionAIArgs(mode string, args []string) []string {
	if mode != "full" || s.opts.DecisionAIURL == "" {
		return args
	}
	return append(args, "-decision-ai-url", s.opts.DecisionAIURL,
		"-decision-ai-max-findings", strconv.Itoa(s.opts.DecisionAIMaxFindings),
		"-decision-ai-budget", strconv.Itoa(s.opts.DecisionAIBudget))
}
