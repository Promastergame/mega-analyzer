package media

import (
	"bytes"
	"strings"
)

// PDFThreat describes a suspicious element found in a PDF file.
type PDFThreat struct {
	Type       string  `json:"type"` // "javascript", "embedded_file", "acroform", "launch_action"
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
	Offset     int     `json:"offset"` // approximate byte offset
}

// AnalyzePDF performs deep analysis on a PDF file, looking for executable
// content, embedded files, and suspicious actions.
func AnalyzePDF(data []byte) []PDFThreat {
	if len(data) < 4 || string(data[0:4]) != "%PDF" {
		return nil
	}

	var threats []PDFThreat

	// Search for JavaScript
	threats = append(threats, detectPDFJavaScript(data)...)

	// Search for embedded files / launch actions
	threats = append(threats, detectPDFEmbeddedFiles(data)...)

	// Search for AcroForm fields
	threats = append(threats, detectPDFAcroForm(data)...)

	return threats
}

func detectPDFJavaScript(data []byte) []PDFThreat {
	var threats []PDFThreat
	lower := bytes.ToLower(data)

	// /JavaScript or /JS
	for _, keyword := range []string{"/javascript", "/js "} {
		idx := 0
		for {
			pos := bytes.Index(lower[idx:], []byte(keyword))
			if pos == -1 {
				break
			}
			absPos := idx + pos
			threats = append(threats, PDFThreat{
				Type:       "javascript",
				Confidence: 0.9,
				Evidence:   "JavaScript embedded in PDF",
				Offset:     absPos,
			})
			idx = absPos + len(keyword)
			if len(threats) > 20 {
				return threats
			}
		}
	}

	return threats
}

func detectPDFEmbeddedFiles(data []byte) []PDFThreat {
	var threats []PDFThreat
	lower := bytes.ToLower(data)

	suspicious := []string{"/embeddedfile", "/launch", "/submitform", "/importdata"}
	for _, kw := range suspicious {
		idx := bytes.Index(lower, []byte(kw))
		if idx != -1 {
			threatType := strings.TrimPrefix(kw, "/")
			threats = append(threats, PDFThreat{
				Type:       threatType,
				Confidence: 0.8,
				Evidence:   "Suspicious PDF action: " + kw,
				Offset:     idx,
			})
		}
	}

	return threats
}

func detectPDFAcroForm(data []byte) []PDFThreat {
	lower := bytes.ToLower(data)
	idx := bytes.Index(lower, []byte("/acroform"))
	if idx == -1 {
		return nil
	}
	return []PDFThreat{{
		Type:       "acroform",
		Confidence: 0.3,
		Evidence:   "PDF contains interactive form fields (AcroForm)",
		Offset:     idx,
	}}
}
