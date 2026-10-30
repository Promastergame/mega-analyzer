package correlation

import "sort"

// BuildTimeline returns a stable, sequence-ordered timeline of every
// non-static signal that carries a timestamp. Static signals are
// excluded — they have no temporal location, and mixing them in only
// confuses the "what happened, in order" view.
//
// Signals without a timestamp are dropped from the timeline (but they
// still show up in the Findings/Chains sections).
func BuildTimeline(signals []*Signal) []TimelineEvent {
	events := make([]TimelineEvent, 0, len(signals))
	for _, s := range signals {
		if s == nil || s.IsStatic() || s.Timestamp.IsZero() {
			continue
		}
		events = append(events, TimelineEvent{
			Timestamp:  s.Timestamp,
			Kind:       s.Kind,
			ProcessKey: s.ProcessKey(),
			Title:      s.Title,
			Target:     s.Target,
			SignalID:   s.ID,
		})
	}

	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if a.Timestamp.Equal(b.Timestamp) {
			if a.ProcessKey == b.ProcessKey {
				return a.SignalID < b.SignalID
			}
			return a.ProcessKey < b.ProcessKey
		}
		return a.Timestamp.Before(b.Timestamp)
	})

	for i := range events {
		events[i].Order = i + 1
	}
	return events
}
