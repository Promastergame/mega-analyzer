package privserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WritePlan writes plan.json into outputDir.
func WritePlan(plan *Plan, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "private_server_plan.json"), data, 0o644)
}

// WriteReadiness writes a Markdown readiness report alongside the plan.
func WriteReadiness(plan *Plan, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "PRIVATE_SERVER_READINESS.md"), []byte(renderReadinessMarkdown(plan)), 0o644)
}

func renderReadinessMarkdown(plan *Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Private Server Readiness — %s\n\n", plan.GameName)
	b.WriteString("> Authorized lab use only. Mock backend for your own / authorized builds.\n\n")
	fmt.Fprintf(&b, "- **Target**: `%s`\n", plan.Target)
	if plan.AppPackage != "" {
		fmt.Fprintf(&b, "- **App package**: `%s`\n", plan.AppPackage)
	}
	fmt.Fprintf(&b, "- **Game family**: %s\n", plan.Family)
	fmt.Fprintf(&b, "- **Transport**: %s (TLS: %v, WebSocket: %v)\n", plan.Transport.Protocol, plan.Transport.UsesTLS, plan.Transport.UsesWebSocket)
	fmt.Fprintf(&b, "- **Framing**: %s\n", plan.Framing.Style)
	fmt.Fprintf(&b, "- **Listen**: %s:%d (admin %d)\n", plan.Listen.Host, plan.Listen.Port, plan.Listen.AdminPort)
	fmt.Fprintf(&b, "- **Module**: `%s`\n", plan.Module)
	fmt.Fprintf(&b, "- **Score**: **%d / 100** (%s)\n\n", plan.Readiness.Score, plan.Readiness.Risk)

	if len(plan.Endpoints) > 0 {
		b.WriteString("## Discovered endpoints\n\n| Address | Port | File | Kind | Confidence |\n|---|---:|---|---|---:|\n")
		for _, e := range plan.Endpoints {
			port := ""
			if e.Port > 0 {
				port = fmt.Sprintf("%d", e.Port)
			}
			fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s | %.2f |\n", e.Address, port, e.FilePath, e.Kind, e.Confidence)
		}
		b.WriteString("\n")
	}
	if plan.Pinning.Detected {
		b.WriteString("## Pinning hints\n\n")
		for _, h := range plan.Pinning.Hints {
			fmt.Fprintf(&b, "- %s\n", h)
		}
		b.WriteString("\n")
	}
	if len(plan.Messages) > 0 {
		b.WriteString("## Message stubs\n\n| ID | Name | Direction | Replay | Stateful |\n|---:|---|---|:---:|:---:|\n")
		for _, m := range plan.Messages {
			fmt.Fprintf(&b, "| %d | %s | %s | %v | %v |\n", int(m.ID), m.Name, m.Direction, m.Replay, m.Stateful)
		}
		b.WriteString("\n")
	}
	if len(plan.Readiness.CriticalGaps) > 0 {
		b.WriteString("## Critical gaps\n\n")
		for _, g := range plan.Readiness.CriticalGaps {
			fmt.Fprintf(&b, "- %s\n", g)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Generated layout\n\n")
	b.WriteString("- `private_server/mix.exs`\n")
	b.WriteString("- `private_server/lib/<module>/application.ex`\n")
	b.WriteString("- `private_server/lib/<module>/listener.ex`\n")
	b.WriteString("- `private_server/lib/<module>/router.ex`\n")
	b.WriteString("- `private_server/lib/<module>/session.ex`\n")
	b.WriteString("- `private_server/lib/<module>/state_machine.ex`\n")
	b.WriteString("- `private_server/lib/<module>/replay_store.ex`\n")
	b.WriteString("- `private_server/lib/<module>/admin/{router,dashboard}.ex`\n")
	b.WriteString("- `private_server/priv/replays/replays.json`\n\n")

	b.WriteString("## Run\n\n```\ncd private_server\nmix deps.get\nmix run --no-halt\n```\n")
	return b.String()
}
