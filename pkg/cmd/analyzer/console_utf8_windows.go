//go:build windows

package main

import (
	"errors"
	"fmt"
)

var (
	utf8GetInputCP  = modKernel32.NewProc("GetConsoleCP")
	utf8GetOutputCP = modKernel32.NewProc("GetConsoleOutputCP")
	utf8SetInputCP  = modKernel32.NewProc("SetConsoleCP")
	utf8SetOutputCP = modKernel32.NewProc("SetConsoleOutputCP")
)

// No chcp subprocess. Redirected Go streams remain UTF-8 without a BOM.
// No attached console is a normal no-op. Analyzed bytes are untouched.
func configureConsoleUTF8() error {
	var problems []error
	if cp, _, _ := utf8GetInputCP.Call(); cp != 0 {
		if ok, _, e := utf8SetInputCP.Call(65001); ok == 0 {
			problems = append(problems, fmt.Errorf("SetConsoleCP(CP_UTF8): %v", e))
		}
	}
	if cp, _, _ := utf8GetOutputCP.Call(); cp != 0 {
		if ok, _, e := utf8SetOutputCP.Call(65001); ok == 0 {
			problems = append(problems, fmt.Errorf("SetConsoleOutputCP(CP_UTF8): %v", e))
		}
	}
	return errors.Join(problems...)
}
