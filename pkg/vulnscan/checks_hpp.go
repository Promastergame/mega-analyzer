package vulnscan

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// testHPP tests for HTTP Parameter Pollution (HPP).
// It sends multiple parameters with the same name and checks the server's behavior.
func (s *Scanner) testHPP(form Form) []Vulnerability {
	var list []Vulnerability

	if form.Method != "GET" && form.Method != "POST" {
		return list
	}

	for _, inputName := range form.Inputs {
		// Prepare baseline values
		val1 := "HPP_TEST_VAL_1"
		val2 := "HPP_TEST_VAL_2"

		// Construct payload with duplicated parameters
		// E.g., ?param=val1&param=val2
		vals := url.Values{}
		for _, inp := range form.Inputs {
			if inp == inputName {
				vals.Add(inp, val1)
				vals.Add(inp, val2) // Add second time
			} else {
				vals.Set(inp, "test")
			}
		}

		var req *http.Request
		if form.Method == "POST" {
			req, _ = http.NewRequest("POST", form.Action, strings.NewReader(vals.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			u, _ := url.Parse(form.Action)
			u.RawQuery = vals.Encode()
			req, _ = http.NewRequest("GET", u.String(), nil)
		}
		req.Header.Set("User-Agent", s.Config.UserAgent)

		resp, err := s.Client.Do(req)

		if err != nil {
			continue
		}

		bodyBytes := s.readBody(resp)
		body := string(bodyBytes)
		resp.Body.Close()

		// Analyze the response to see how the server handled the duplication
		// PHP/Apache takes the last: val2
		// ASP.NET/IIS takes both comma-separated: val1,val2
		// JSP/Tomcat takes the first: val1
		// We look for errors or reflection that indicates confusion.

		triggered := false
		evidence := ""

		if strings.Contains(body, val1+","+val2) || strings.Contains(body, val1+"%2C"+val2) {
			triggered = true
			evidence = fmt.Sprintf("Server concatenated values: %s,%s", val1, val2)
		} else if strings.Contains(strings.ToLower(body), "error") && (!strings.Contains(body, val1) || !strings.Contains(body, val2)) {
			// Triggered a generic error (maybe type mismatch if it expected a string but got an array)
			triggered = true
			evidence = "Server returned an error when multiple parameters were supplied."
		}

		if triggered {
			list = append(list, Vulnerability{
				ID:          "WS-HPP-001",
				Name:        "HTTP Parameter Pollution (HPP)",
				Description: fmt.Sprintf("The application exhibits anomalous behavior when the parameter '%s' is supplied multiple times. This can be exploited to bypass WAFs, override logic, or trigger unexpected errors.", inputName),
				Severity:    SeverityLow, // Usually low on its own, acts as a multiplier
				URL:         form.Action,
				Parameter:   inputName,
				Payload:     fmt.Sprintf("%s=%s&%s=%s", inputName, val1, inputName, val2),
				Evidence:    evidence,
				Mitigation:  "Ensure the application strictly handles duplicated parameters. Use frameworks that provide consistent parameter parsing.",
			})
		}
	}

	return list
}
