//go:build !linux

package main

import "fmt"

func writeProperty(path, key, value string) error {
	return fmt.Errorf("property writes require a Linux/Android guest")
}
