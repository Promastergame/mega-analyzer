package ncer

import (
	"testing"
	"time"
)

func TestParseTimeOfDayMS_Valid(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"00:00:00.000", 0},
		{"00:00:01.500", 1500},
		{"01:00:00.000", 3600000},
		{"12:34:56.789", 12*3600000 + 34*60000 + 56*1000 + 789},
		{"23:59:59.999", 23*3600000 + 59*60000 + 59*1000 + 999},
		{"10:00:01", 10*3600000 + 1000}, // no fractional part
		{"10:00:01.5", 10*3600000 + 1000 + 500},
		{"10:00:01.05", 10*3600000 + 1000 + 50},
		{"10:00:01.123456", 10*3600000 + 1000 + 123}, // truncated to ms
	}
	for _, tc := range cases {
		got, ok := parseTimeOfDayMS(tc.in)
		if !ok {
			t.Errorf("parseTimeOfDayMS(%q) reported not-ok, want ok", tc.in)
			continue
		}
		if got != tc.want {
			t.Errorf("parseTimeOfDayMS(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseTimeOfDayMS_Invalid(t *testing.T) {
	for _, in := range []string{
		"", "not-a-time", "10:00", "10", "aa:bb:cc.ddd",
		"24:00:00.000", "10:60:00.000", "10:00:99.000", "10:00:00.",
		"-1:00:00.000",
	} {
		if _, ok := parseTimeOfDayMS(in); ok {
			t.Errorf("parseTimeOfDayMS(%q) reported ok, want not-ok", in)
		}
	}
}

// TestParseTimestampMS_Deterministic verifies the same input stream always
// produces the same output regardless of wall-clock time (no time.Now()).
func TestParseTimestampMS_Deterministic(t *testing.T) {
	base := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	c1 := NewCollector(base)
	c2 := NewCollector(base)
	inputs := []string{"10:00:01.500", "10:00:02.000", "garbage", "10:00:03.250"}
	for _, in := range inputs {
		if c1.parseTimestampMS(in) != c2.parseTimestampMS(in) {
			t.Fatalf("parseTimestampMS(%q) not deterministic across collectors", in)
		}
	}
}

// TestParseTimestampMS_InvalidFallbackIsMonotonic verifies a malformed
// timestamp reuses the last good value rather than jumping to wall time.
func TestParseTimestampMS_InvalidFallbackIsMonotonic(t *testing.T) {
	base := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	c := NewCollector(base)
	good := c.parseTimestampMS("10:00:05.000")
	fallback := c.parseTimestampMS("not-a-time")
	if fallback != good {
		t.Errorf("invalid timestamp fallback = %d, want last-good %d", fallback, good)
	}
}

// TestParseTimestampMS_MidnightRollover verifies that a session crossing
// midnight keeps producing monotonically increasing timestamps instead of
// leaping ~24h backwards.
func TestParseTimestampMS_MidnightRollover(t *testing.T) {
	base := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	c := NewCollector(base)

	before := c.parseTimestampMS("23:59:59.000")
	after := c.parseTimestampMS("00:00:01.000") // one day later
	if after <= before {
		t.Fatalf("post-midnight timestamp %d <= pre-midnight %d (rollover not handled)", after, before)
	}
	// The gap should be ~2 seconds, not ~24h backwards.
	if delta := after - before; delta < 1500 || delta > 3000 {
		t.Errorf("rollover delta = %dms, want ~2000ms", delta)
	}

	// A small out-of-order step within the same day must NOT be treated as a
	// rollover.
	c2 := NewCollector(base)
	t1 := c2.parseTimestampMS("10:00:05.000")
	t2 := c2.parseTimestampMS("10:00:04.000") // 1s earlier, reordered
	if t2 >= t1+24*60*60*1000 {
		t.Errorf("small backward step wrongly treated as rollover: t1=%d t2=%d", t1, t2)
	}
}
