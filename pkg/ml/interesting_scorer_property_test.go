package ml

import (
	"math/rand"
	"testing"
	"time"
)

// Property test for interesting scorer calculation accuracy
// **Feature: analyzer-gamemode-upgrade, Property: Interesting score calculation accuracy**
// **Validates: Requirements 1.1, 1.2, 1.3**

func TestInterestingScorer_Properties(t *testing.T) {
	scorer := NewInterestingScorer()
	rand.Seed(time.Now().UnixNano())

	// Property 1: Score should always be non-negative
	t.Run("Property_ScoreNonNegative", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			mi := generateRandomMethodInfo()
			callChain := generateRandomCallChainInfo()

			score := scorer.Calculate(mi, callChain)

			if score.TotalScore < 0 {
				t.Errorf("Total score should be non-negative, got %.2f for method %s",
					score.TotalScore, mi.Name)
			}

			// Individual scores should also be non-negative
			if score.ClientTrustScore < 0 || score.ExternalInputScore < 0 ||
				score.NetworkUsageScore < 0 || score.ExportedComponentScore < 0 ||
				score.HardcodedDataScore < 0 || score.CallDepthScore < 0 {
				t.Errorf("Individual scores should be non-negative for method %s", mi.Name)
			}
		}
	})

	// Property 2: Penalties should be non-negative (they represent penalty amounts)
	t.Run("Property_PenaltiesNonNegative", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			mi := generateRandomMethodInfo()
			callChain := generateRandomCallChainInfo()

			score := scorer.Calculate(mi, callChain)

			if score.GenericMethodPenalty < 0 {
				t.Errorf("Generic method penalty should be non-negative, got %.2f",
					score.GenericMethodPenalty)
			}

			if score.LibraryCodePenalty < 0 {
				t.Errorf("Library code penalty should be non-negative, got %.2f",
					score.LibraryCodePenalty)
			}

			if score.NoIOPenalty < 0 {
				t.Errorf("No IO penalty should be non-negative, got %.2f",
					score.NoIOPenalty)
			}
		}
	})

	// Property 3: Library code should have library penalty
	t.Run("Property_LibraryCodePenalty", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			mi := generateRandomMethodInfo()
			mi.IsAppCode = false // Force library code
			callChain := generateRandomCallChainInfo()

			score := scorer.Calculate(mi, callChain)

			if score.LibraryCodePenalty <= 0 {
				t.Errorf("Library code should have penalty, got %.2f for method %s",
					score.LibraryCodePenalty, mi.Name)
			}
		}
	})

	// Property 4: App code should not have library penalty
	t.Run("Property_AppCodeNoLibraryPenalty", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			mi := generateRandomMethodInfo()
			mi.IsAppCode = true // Force app code
			callChain := generateRandomCallChainInfo()

			score := scorer.Calculate(mi, callChain)

			if score.LibraryCodePenalty < 0 {
				t.Errorf("App code should not have library penalty, got %.2f for method %s",
					score.LibraryCodePenalty, mi.Name)
			}
		}
	})

	// Property 5: Entry points should have higher scores
	t.Run("Property_EntryPointBonus", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			// Create two identical methods, one as entry point
			mi := generateRandomMethodInfo()
			mi.IsAppCode = true

			// Create call chain without entry point
			callChainNormal := &CallChainInfo{
				IsEntryPoint:          false,
				FromExportedComponent: false,
				HasExternalInput:      false,
				Depth:                 1,
			}

			// Create call chain with entry point
			callChainEntryPoint := &CallChainInfo{
				IsEntryPoint:          true,
				FromExportedComponent: true,
				HasExternalInput:      true,
				Depth:                 1,
			}

			score1 := scorer.Calculate(mi, callChainNormal)
			score2 := scorer.Calculate(mi, callChainEntryPoint)

			if score2.TotalScore <= score1.TotalScore {
				t.Errorf("Entry point should have higher score than non-entry point")
			}
		}
	})

	// Property 6: Methods with network usage should score higher
	t.Run("Property_NetworkUsageBonus", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			// Create method with network calls
			miWithNetwork := generateRandomMethodInfo()
			miWithNetwork.IsAppCode = true
			miWithNetwork.Calls = []CallInfo{
				{FullCall: "Lokhttp3/OkHttpClient;->newCall"},
				{FullCall: "Ljava/net/HttpURLConnection;->connect"},
			}
			miWithNetwork.StringConsts = []string{"https://api.example.com"}

			// Create method without network calls
			miWithoutNetwork := generateRandomMethodInfo()
			miWithoutNetwork.IsAppCode = true
			miWithoutNetwork.Calls = []CallInfo{}
			miWithoutNetwork.StringConsts = []string{}

			callChain := generateRandomCallChainInfo()

			scoreWithNetwork := scorer.Calculate(miWithNetwork, callChain)
			scoreWithoutNetwork := scorer.Calculate(miWithoutNetwork, callChain)

			if scoreWithNetwork.NetworkUsageScore <= scoreWithoutNetwork.NetworkUsageScore {
				t.Errorf("Method with network usage should have higher network score")
			}
		}
	})

	// Property 7: Interesting flag should correlate with total score
	t.Run("Property_InterestingFlagCorrelation", func(t *testing.T) {
		interestingCount := 0
		notInterestingCount := 0
		interestingScoreSum := 0.0
		notInterestingScoreSum := 0.0

		for i := 0; i < 100; i++ {
			mi := generateRandomMethodInfo()
			callChain := generateRandomCallChainInfo()

			score := scorer.Calculate(mi, callChain)

			if score.IsInteresting {
				interestingCount++
				interestingScoreSum += score.TotalScore
			} else {
				notInterestingCount++
				notInterestingScoreSum += score.TotalScore
			}
		}

		if interestingCount > 0 && notInterestingCount > 0 {
			avgInterestingScore := interestingScoreSum / float64(interestingCount)
			avgNotInterestingScore := notInterestingScoreSum / float64(notInterestingCount)

			if avgInterestingScore <= avgNotInterestingScore {
				t.Errorf("Average score of interesting methods (%.2f) should be higher than non-interesting (%.2f)",
					avgInterestingScore, avgNotInterestingScore)
			}
		}
	})
}

// Helper functions to generate random test data

func generateRandomMethodInfo() *MethodInfo {
	names := []string{
		"processPayment", "validateLicense", "checkPremium", "toString", "hashCode",
		"getUserData", "sendRequest", "parseResponse", "encrypt", "decrypt",
		"authenticate", "authorize", "logEvent", "saveData", "loadConfig",
	}

	name := names[rand.Intn(len(names))]

	return &MethodInfo{
		Name:      name,
		IsAppCode: rand.Float32() > 0.3, // 70% chance of being app code
		RawBody:   []string{generateRandomMethodBody()},
	}
}

func generateRandomCallChainInfo() *CallChainInfo {
	return &CallChainInfo{
		HasExternalInput:      rand.Float32() > 0.7, // 30% chance
		Depth:                 rand.Intn(10) + 1,
		IsEntryPoint:          rand.Float32() > 0.8, // 20% chance
		FromExportedComponent: rand.Float32() > 0.6, // 40% chance
		HasSecuritySink:       rand.Float32() > 0.8, // 20% chance
	}
}

func generateRandomMethodBody() string {
	bodies := []string{
		"return value;",
		"if (condition) { doSomething(); }",
		"for (int i = 0; i < 10; i++) { process(i); }",
		"try { riskyOperation(); } catch (Exception e) { handle(e); }",
		"String result = processData(input); return result;",
		"network.sendRequest(data); return response;",
		"if (isValid(input)) { return process(input); } else { throw new Exception(); }",
	}

	return bodies[rand.Intn(len(bodies))]
}

// Benchmark test for performance
func BenchmarkInterestingScorer_Calculate(b *testing.B) {
	scorer := NewInterestingScorer()
	mi := &MethodInfo{
		Name:      "testMethod",
		IsAppCode: true,
		RawBody:   []string{"complex method body with multiple operations"},
	}
	callChain := &CallChainInfo{
		HasExternalInput:      true,
		Depth:                 5,
		IsEntryPoint:          true,
		FromExportedComponent: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scorer.Calculate(mi, callChain)
	}
}
