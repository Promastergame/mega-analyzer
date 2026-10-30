package vulnscan

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// testFileUpload attempts to find file upload vulnerabilities by uploading
// potentially malicious files disguised as benign ones (e.g., bypass extension checks).
func (s *Scanner) testFileUpload(form Form) []Vulnerability {
	var list []Vulnerability

	// Only test forms that handle multipart/form-data
	if form.Enctype != "multipart/form-data" {
		return list
	}

	payloads := []struct {
		filename    string
		contentType string
		content     string
		desc        string
	}{
		{"test.php.jpg", "image/jpeg", "<?php echo 'VULNERABLE'; ?>", "Double extension bypass"},
		{"test.php%00.jpg", "image/jpeg", "<?php echo 'VULNERABLE'; ?>", "Null byte extension bypass"},
		{"test.jsp", "image/jpeg", "<% out.println(\"VULNERABLE\"); %>", "Content-Type spoofing"},
		{"eicar.com", "application/octet-stream", `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`, "EICAR test file to check server AV"},
	}

	for _, inputName := range form.Inputs { // form.Inputs is now a map[string]string (name -> type)
		// Assuming we modified extractForms to identify file inputs. Let's just try all inputs for now if enctype matches.
		// In a real scenario, we'd check if inputName is of type "file".

		for _, p := range payloads {
			body, status := s.sendFileUploadRequest(form, inputName, p.filename, p.contentType, p.content)

			// Simple verification: if we uploaded a script, try to access it (requires knowing the upload path, which is hard blindly)
			// For now, we flag if the upload succeeds (200 OK) and doesn't return an error.
			if status == 200 && !strings.Contains(strings.ToLower(body), "error") && !strings.Contains(strings.ToLower(body), "invalid file") {
				list = append(list, Vulnerability{
					ID:          "WS-UPLOAD-001",
					Name:        "Potential Unrestricted File Upload",
					Description: fmt.Sprintf("Successfully uploaded a file (%s) containing potentially malicious content using technique: %s. This might lead to Remote Code Execution if the file is stored in web root and executed.", p.filename, p.desc),
					Severity:    SeverityHigh,
					URL:         form.Action,
					Parameter:   inputName,
					Payload:     p.filename,
					Evidence:    fmt.Sprintf("Server responded with 200 OK upon uploading %s", p.filename),
					Mitigation:  "Validate file extensions against a strict allowlist. Validate content type and file signatures. Store uploaded files outside the web root or on a separate storage domain. Disable execution of scripts in the upload directory.",
				})
			}
		}
	}

	return list
}

func (s *Scanner) sendFileUploadRequest(form Form, fileFieldName, filename, contentType, content string) (string, int) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	// Add file field
	fw, err := w.CreateFormFile(fileFieldName, filename)
	if err == nil {
		io.Copy(fw, strings.NewReader(content))
	}

	// Add other empty text fields
	for _, inp := range form.Inputs {
		if inp != fileFieldName {
			w.WriteField(inp, "test")
		}
	}

	w.Close()

	req, err := http.NewRequest(form.Method, form.Action, &b)
	if err != nil {
		return "", 0
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("User-Agent", s.Config.UserAgent)

	resp, err := s.Client.Do(req)

	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()

	bodyBytes := s.readBody(resp)
	return string(bodyBytes), resp.StatusCode
}
