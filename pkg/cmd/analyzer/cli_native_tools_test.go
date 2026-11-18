package main

import (
	"strings"
	"testing"
)

func TestCLIRejectsRetiredSmaliTools(t *testing.T) {
	for _, flag := range []string{
		"--smali-jar", "--baksmali-jar", "--smali-heap-mb", "--smali-verbose",
		"--baksmali-use-locals", "--baksmali-seq-labels", "--baksmali-no-param-regs",
	} {
		t.Run(flag, func(t *testing.T) {
			_, err := NewCLIParser().Parse([]string{flag})
			if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
				t.Fatalf("retired flag must be rejected: %s: %v", flag, err)
			}
		})
	}
}
