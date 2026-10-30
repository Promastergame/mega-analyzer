package deobfmetrics_test

import (
	"fmt"

	"mega-analyzer/pkg/internal/deobfmetrics"
)

func ExampleCalculator_Compute() {
	calc := deobfmetrics.NewCalculator()

	before := deobfmetrics.DeobfState{
		AvgNameEntropy:   4.0,
		TotalIdentifiers: 100,
		ObfuscatedNames:  80,
		TotalBlocks:      200,
		DispatcherBlocks: 20,
		TotalStrings:     50,
		EncryptedStrings: 40,
	}

	after := deobfmetrics.DeobfState{
		AvgNameEntropy:   2.0,
		TotalIdentifiers: 100,
		ObfuscatedNames:  20,
		MeaningfulNames:  60,
		ReadableNames:    20,
		TotalBlocks:      180,
		DispatcherBlocks: 5,
		TotalStrings:     50,
		EncryptedStrings: 10,
		DecryptedStrings: 30,
	}

	report, err := calc.Compute(before, after)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("Grade: %s\n", report.Grade())
	fmt.Printf("Confidence: %.0f%%\n", report.OverallConfidence*100)

	// Output:
	// Grade: B
	// Confidence: 69%
}
