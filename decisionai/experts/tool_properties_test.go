package experts

import (
	"encoding/json"
	"testing"

	"decisionai/s1"
)

func TestToolPropertiesSimpleCalls(t *testing.T) {
	for _, tc := range []struct {
		command  string
		readOnly bool
	}{
		{"df -h", true},
		{"ls -la /var/log/web", true},
		{"cat \"notes/a b.md\"", true},
		{"git log --oneline -n 10", true},
		{"rm --help", true},
		{"rm -rf build", false},
		{"git push --force origin main", false},
		{"git commit -am 'fix typo'", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			encoded, _ := json.Marshal(tc.command)
			state := "Task: preview a change.\nProposed tool call: shell(" + string(encoded) + ")\nContext: sandbox with fake data."
			for _, inverse := range []bool{false, true} {
				instruction := "Does the call only read data without changing anything?"
				if inverse {
					instruction = "Does the call change data?"
				}
				answer, handled := (ToolProperties{}).Answer(state, state, s1.ExpertQuestion{Type: s1.TypeNoul, Instr: instruction})
				if !handled || len(answer.Probs) != 1 || (answer.Probs[0] > .5) != (tc.readOnly != inverse) {
					t.Fatalf("inverse=%v: %+v, handled=%v", inverse, answer, handled)
				}
				if answer.Calibrated {
					t.Fatal("syntax analysis must not enable automatic execution")
				}
			}
		})
	}
}

func TestToolPropertiesRejectCompositionAndUnknownSemantics(t *testing.T) {
	for _, command := range []string{
		"df -h; rm -rf build", "df -h && touch output", "ls $(touch output)",
		"ls `touch output`", "ls > output", "ls | tee output", "sudo df -h",
		"./df -h", "X=1 df -h", "ls 'unterminated", "git log --ext-diff",
		"git -c alias.log=anything log", "git push --dry-run", "df -h\nrm -rf build",
	} {
		t.Run(command, func(t *testing.T) {
			encoded, _ := json.Marshal(command)
			_, handled := (ToolProperties{}).Answer("shell("+string(encoded)+")", "", s1.ExpertQuestion{Type: s1.TypeNoul, Instr: "Is this tool call read-only?"})
			if handled {
				t.Fatal("ambiguous or composed shell command was treated as a simple call")
			}
		})
	}
	state := `shell("df -h")`
	for _, question := range []s1.ExpertQuestion{
		{Type: s1.TypeNoul, Instr: "Is this action safe?"},
		{Type: s1.TypeNoul, Instr: "Does the tool call do only what the task asks for?"},
		{Type: s1.TypeNoul, Task: s1.TaskPatchEffect, Instr: "Is this tool call read-only?"},
		{Type: s1.TypeNoul, Instr: "Is this tool call read-only?", Options: []s1.Option{{Key: "true", Text: "Changes data"}}},
	} {
		if _, handled := (ToolProperties{}).Answer(state, state, question); handled {
			t.Fatalf("unrelated question was intercepted: %+v", question)
		}
	}
}

func TestToolPropertiesCurrentScopeAndSingleQuote(t *testing.T) {
	state := map[string]any{
		"current": map[string]any{"tool_call": "shell('df -h')"},
		"history": map[string]any{"tool_call": "shell('rm -rf build')"},
	}
	question := s1.ExpertQuestion{Type: s1.TypeNoul, Instr: "Этот вызов только читает данные?"}
	answer, handled := (ToolProperties{}).Answer(state, "", question)
	if !handled || answer.Probs[0] < .9 {
		t.Fatalf("current call was not selected: %+v", answer)
	}
	delete(state, "current")
	if _, handled := (ToolProperties{}).Answer(state, "", question); handled {
		t.Fatal("historical nested call was treated as current")
	}
	if _, handled := (ToolProperties{}).Answer("Proposed tool call: shell('df -h')\nProposed tool call: shell('rm -rf build')", "", question); handled {
		t.Fatal("multiple calls were silently reduced to one")
	}
}
