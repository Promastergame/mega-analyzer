package media

import (
	"fmt"
	"time"
)

// TimelineEntry is a single timestamp extracted from the file's metadata.
type TimelineEntry struct {
	Source    string    `json:"source"` // "EXIF_DateTimeOriginal", "XMP_CreateDate", etc.
	Timestamp time.Time `json:"timestamp"`
	Raw       string    `json:"raw"`               // original unparsed string
	Anomaly   string    `json:"anomaly,omitempty"` // non-empty if suspicious
}

// Timeline holds all timestamps extracted from a file's metadata.
type Timeline struct {
	Entries   []TimelineEntry   `json:"entries"`
	Anomalies []TimelineAnomaly `json:"anomalies,omitempty"`
}

// TimelineAnomaly describes a timestamp consistency issue.
type TimelineAnomaly struct {
	Type        string `json:"type"` // "creation_after_modification", "time_gap", etc.
	Description string `json:"description"`
	Entry1      string `json:"entry1"` // source of first timestamp
	Entry2      string `json:"entry2"` // source of second timestamp
}

// BuildTimeline extracts all timestamps from MediaMetadata and builds a
// chronologically sorted timeline.
func BuildTimeline(meta *MediaMetadata) *Timeline {
	if meta == nil {
		return &Timeline{}
	}

	tl := &Timeline{}

	// EXIF timestamps
	addEXIFTimestamps(meta, tl)

	// XMP timestamps
	addXMPTimestamps(meta, tl)

	// Sort by timestamp
	sortTimelineEntries(tl.Entries)

	// Detect anomalies
	tl.Anomalies = detectTimelineAnomalies(tl)

	return tl
}

var exifTimeFormats = []string{
	"2006:01:02 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
}

func addEXIFTimestamps(meta *MediaMetadata, tl *Timeline) {
	if meta.Fields == nil {
		return
	}

	fields := map[string]string{
		"Date_Taken": "EXIF_DateTimeOriginal",
	}

	for field, source := range fields {
		if raw, ok := meta.Fields[field]; ok && raw != "" {
			if t, err := parseTimestamp(raw); err == nil {
				tl.Entries = append(tl.Entries, TimelineEntry{
					Source:    source,
					Timestamp: t,
					Raw:       raw,
				})
			}
		}
	}
}

func addXMPTimestamps(meta *MediaMetadata, tl *Timeline) {
	if meta.XMP == nil {
		return
	}

	fields := map[string]string{
		"CreateDate":  "XMP_CreateDate",
		"ModifyDate":  "XMP_ModifyDate",
		"DateCreated": "XMP_DateCreated",
	}

	for field, source := range fields {
		if raw, ok := meta.XMP[field]; ok && raw != "" {
			if t, err := parseTimestamp(raw); err == nil {
				tl.Entries = append(tl.Entries, TimelineEntry{
					Source:    source,
					Timestamp: t,
					Raw:       raw,
				})
			}
		}
	}
}

func parseTimestamp(raw string) (time.Time, error) {
	for _, layout := range exifTimeFormats {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable timestamp: %s", raw)
}

func sortTimelineEntries(entries []TimelineEntry) {
	// Simple insertion sort — timelines are small (typically <10 entries)
	for i := 1; i < len(entries); i++ {
		key := entries[i]
		j := i - 1
		for j >= 0 && entries[j].Timestamp.After(key.Timestamp) {
			entries[j+1] = entries[j]
			j--
		}
		entries[j+1] = key
	}
}

func detectTimelineAnomalies(tl *Timeline) []TimelineAnomaly {
	var anomalies []TimelineAnomaly

	if len(tl.Entries) < 2 {
		return anomalies
	}

	// Check: creation date after modification date
	var creation, modification *TimelineEntry
	for i := range tl.Entries {
		e := &tl.Entries[i]
		switch {
		case e.Source == "EXIF_DateTimeOriginal" || e.Source == "XMP_CreateDate" || e.Source == "XMP_DateCreated":
			if creation == nil || e.Timestamp.Before(creation.Timestamp) {
				creation = e
			}
		case e.Source == "XMP_ModifyDate":
			if modification == nil || e.Timestamp.After(modification.Timestamp) {
				modification = e
			}
		}
	}

	if creation != nil && modification != nil && creation.Timestamp.After(modification.Timestamp) {
		anomalies = append(anomalies, TimelineAnomaly{
			Type:        "creation_after_modification",
			Description: fmt.Sprintf("Creation date (%s) is after modification date (%s)", creation.Timestamp.Format("2006-01-02 15:04:05"), modification.Timestamp.Format("2006-01-02 15:04:05")),
			Entry1:      creation.Source,
			Entry2:      modification.Source,
		})
	}

	// Check: unreasonable time gaps between consecutive entries
	for i := 1; i < len(tl.Entries); i++ {
		prev := tl.Entries[i-1]
		curr := tl.Entries[i]
		gap := curr.Timestamp.Sub(prev.Timestamp)
		if gap < 0 {
			gap = -gap
		}
		// Flag gaps > 30 days between timestamps from the same "category"
		if gap > 30*24*time.Hour {
			anomalies = append(anomalies, TimelineAnomaly{
				Type:        "large_time_gap",
				Description: fmt.Sprintf("Large time gap (%.0f days) between %s and %s", gap.Hours()/24, prev.Source, curr.Source),
				Entry1:      prev.Source,
				Entry2:      curr.Source,
			})
		}
	}

	return anomalies
}
