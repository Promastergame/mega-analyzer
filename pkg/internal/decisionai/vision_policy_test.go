package decisionai

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
)

func TestImageAnalysisAcceptsKnownPreviewPolicyVersions(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			client := imageReviewClient(t, nil)
			original := client.http.Transport
			client.http.Transport = imageReviewTransport(func(r *http.Request) (*http.Response, error) {
				response, err := original.RoundTrip(r)
				if err != nil {
					return nil, err
				}
				var analysis ImageAnalysis
				err = json.NewDecoder(response.Body).Decode(&analysis)
				response.Body.Close()
				if err != nil {
					return nil, err
				}
				analysis.Preview.PolicyVersion = version
				body, err := json.Marshal(analysis)
				if err != nil {
					return nil, err
				}
				response.Body = io.NopCloser(bytes.NewReader(body))
				return response, nil
			})
			_, err := client.AnalyzeImage(context.Background(), imageReviewPNG(t, 20))
			if (err == nil) != (version == 1 || version == 2) {
				t.Fatalf("policy %d: %v", version, err)
			}
		})
	}
}
