package playstore

import (
	"fmt"
	"strings"
)

// RenderMarkdown generates a Markdown Play Store report.
func (r *Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("# Play Store Metadata Report\n\n")
	if r.Metadata == nil || !r.Metadata.Found {
		b.WriteString("App not found on Google Play Store.\n")
		return b.String()
	}
	m := r.Metadata
	b.WriteString(fmt.Sprintf("- **Package**: %s\n", m.PackageName))
	b.WriteString(fmt.Sprintf("- **Name**: %s\n", m.Name))
	b.WriteString(fmt.Sprintf("- **Developer**: %s\n", m.Developer))
	b.WriteString(fmt.Sprintf("- **Category**: %s\n", m.Category))
	b.WriteString(fmt.Sprintf("- **Rating**: %.1f (%s reviews)\n", m.Rating, m.RatingCount))
	b.WriteString(fmt.Sprintf("- **Installs**: %s\n", m.Installs))
	b.WriteString(fmt.Sprintf("- **Version**: %s\n", m.Version))
	b.WriteString(fmt.Sprintf("- **Updated**: %s\n", m.Updated))
	b.WriteString(fmt.Sprintf("- **Privacy Policy**: %s\n", m.PrivacyPolicy))
	b.WriteString(fmt.Sprintf("- **URL**: %s\n", m.URL))
	return b.String()
}
