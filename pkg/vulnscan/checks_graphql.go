package vulnscan

import (
	"encoding/json"
	"net/http"
	"strings"
)

// checkGraphQL audits GraphQL endpoints for specific vulnerabilities like
// Query Batching and Introspection. (Introspection is partly covered in sensitive probes,
// but here we do deeper active checks).
func (s *Scanner) checkGraphQL() []Vulnerability {
	var list []Vulnerability

	// List of possible GraphQL endpoints
	endpoints := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}
	var targetEndpoint string

	// 1. Find the endpoint
	for _, ep := range endpoints {
		probeURL := strings.TrimRight(s.Target, "/") + ep
		req, _ := http.NewRequest("POST", probeURL, strings.NewReader(`{"query":"{__typename}"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", s.Config.UserAgent)

		resp, err := s.Client.Do(req)
		if err == nil {
			bodyBytes := s.readBody(resp)
			resp.Body.Close()
			if strings.Contains(string(bodyBytes), "data") && strings.Contains(string(bodyBytes), "__typename") {
				targetEndpoint = probeURL
				break
			}
		}
	}

	if targetEndpoint == "" {
		return list
	}

	// 2. Test Query Batching (can bypass rate limits / WAF)
	batchPayload := `[{"query":"{__typename}"},{"query":"{__typename}"}]`
	req, _ := http.NewRequest("POST", targetEndpoint, strings.NewReader(batchPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.Config.UserAgent)

	resp, err := s.Client.Do(req)

	if err == nil {
		bodyBytes := s.readBody(resp)
		resp.Body.Close()

		// If response is a JSON array with 2 results, batching is enabled
		var jsonRes []interface{}
		if err := json.Unmarshal(bodyBytes, &jsonRes); err == nil && len(jsonRes) == 2 {
			list = append(list, Vulnerability{
				ID:          "WS-GQL-001",
				Name:        "GraphQL Query Batching Enabled",
				Description: "The GraphQL endpoint accepts arrays of queries (Query Batching). This feature can be abused to bypass rate limits, perform brute-force attacks, or cause Denial of Service (DoS) by executing many queries in a single HTTP request.",
				Severity:    SeverityMedium,
				URL:         targetEndpoint,
				Payload:     batchPayload,
				Evidence:    "Server processed the batched array and returned an array of results.",
				Mitigation:  "Disable Query Batching if not strictly required, or implement object-level rate limiting that accounts for batched queries.",
			})
		}
	}

	// 3. Test Alias Overloading (DoS)
	aliasPayload := `{"query":"query { a:__typename b:__typename c:__typename d:__typename e:__typename }"}`
	req2, _ := http.NewRequest("POST", targetEndpoint, strings.NewReader(aliasPayload))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("User-Agent", s.Config.UserAgent)

	resp2, err2 := s.Client.Do(req2)

	if err2 == nil {
		bodyBytes := s.readBody(resp2)
		resp2.Body.Close()
		body := string(bodyBytes)

		if strings.Contains(body, `"a":`) && strings.Contains(body, `"e":`) {
			list = append(list, Vulnerability{
				ID:          "WS-GQL-002",
				Name:        "GraphQL Alias Overloading (DoS Vector)",
				Description: "The GraphQL endpoint accepts queries with multiple aliases without apparent restriction. Attackers can use this to request the same expensive field thousands of times in one query, causing Denial of Service.",
				Severity:    SeverityMedium,
				URL:         targetEndpoint,
				Payload:     aliasPayload,
				Evidence:    "Server successfully resolved all aliased fields in a single query.",
				Mitigation:  "Implement query complexity analysis and depth limiting on the GraphQL server.",
			})
		}
	}

	return list
}
