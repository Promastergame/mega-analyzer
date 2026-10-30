//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"mega-analyzer/pkg/internal/apkloader"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run debug_test_main.go <apk_or_dex_file>")
		os.Exit(1)
	}

	inputPath := os.Args[1]
	fmt.Printf("Testing DEX parsing for: %s\n", inputPath)
	fmt.Println(string(make([]byte, 60)))

	// Load the APK/DEX
	loader := apkloader.NewLoader(inputPath)
	if err := loader.Load(); err != nil {
		fmt.Printf("ERROR: Failed to load: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Loaded successfully\n")
	fmt.Printf("  Input type: %v\n", loader.InputType)
	fmt.Printf("  Warnings: %d\n", len(loader.Warnings))

	if len(loader.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for i, w := range loader.Warnings {
			fmt.Printf("  [%d] %s\n", i+1, w)
			if i >= 20 {
				fmt.Printf("  ... and %d more warnings\n", len(loader.Warnings)-20)
				break
			}
		}
	}

	// Get classes
	classes := loader.GetClasses()
	fmt.Printf("\n✓ Total classes: %d\n", len(classes))

	// Count methods
	totalMethods := 0
	classesWithMethods := 0
	classesWithoutMethods := 0

	for _, class := range classes {
		methodCount := len(class.DirectMethods) + len(class.VirtualMethods)
		totalMethods += methodCount

		if methodCount > 0 {
			classesWithMethods++
		} else {
			classesWithoutMethods++
		}
	}

	fmt.Printf("✓ Classes with methods: %d\n", classesWithMethods)
	fmt.Printf("✓ Classes without methods: %d\n", classesWithoutMethods)
	fmt.Printf("✓ Total methods: %d\n", totalMethods)

	// Show first few classes with methods
	fmt.Println("\nFirst 5 classes with methods:")
	shown := 0
	for _, class := range classes {
		methodCount := len(class.DirectMethods) + len(class.VirtualMethods)
		if methodCount > 0 {
			fmt.Printf("  %s: %d direct + %d virtual = %d methods\n",
				class.ClassName,
				len(class.DirectMethods),
				len(class.VirtualMethods),
				methodCount)
			shown++
			if shown >= 5 {
				break
			}
		}
	}

	if shown == 0 {
		fmt.Println("  ⚠️  NO CLASSES WITH METHODS FOUND!")
		fmt.Println("\nFirst 5 classes (regardless of methods):")
		for i, class := range classes {
			if i >= 5 {
				break
			}
			fmt.Printf("  %s: ClassDataOff=0x%x, %d direct + %d virtual\n",
				class.ClassName,
				class.ClassDataOff,
				len(class.DirectMethods),
				len(class.VirtualMethods))
		}
	}
}
