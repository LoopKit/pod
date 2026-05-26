package delivery

import (
	"testing"
	"time"
)

// TestPartialPulses_TwoSecond covers a 10-pulse user bolus running at 2 sec/
// pulse (regular Omnipod 5 bolus cadence). end = start + 20s.
func TestPartialPulses_TwoSecond(t *testing.T) {
	start := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	end := start.Add(20 * time.Second)

	cases := []struct {
		name string
		now  time.Time
		want uint16
	}{
		{"before start", start.Add(-time.Second), 0},
		{"at start", start, 0},
		{"one pulse in", start.Add(2 * time.Second), 1},
		{"five pulses in", start.Add(10 * time.Second), 5},
		{"exactly done", end, 10},
		{"past end clamps", start.Add(time.Hour), 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PartialPulses(10, start, end, tc.now); got != tc.want {
				t.Errorf("PartialPulses(10, …, %v) = %d, want %d", tc.now.Sub(start), got, tc.want)
			}
		})
	}
}

// TestPartialPulses_OneSecond covers prime/cannula at 1 sec/pulse.
// 52 pulses (prime) at 1s/pulse → end = start + 52s.
func TestPartialPulses_OneSecond(t *testing.T) {
	start := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	end := start.Add(52 * time.Second)

	cases := []struct {
		name string
		now  time.Time
		want uint16
	}{
		{"at start", start, 0},
		{"halfway (26s in)", start.Add(26 * time.Second), 26},
		{"fully done", end, 52},
		{"past end", start.Add(2 * time.Minute), 52},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PartialPulses(52, start, end, tc.now); got != tc.want {
				t.Errorf("PartialPulses(52, …, %v) = %d, want %d", tc.now.Sub(start), got, tc.want)
			}
		})
	}
}

// TestPartialPulses_Degenerate exercises the early-out paths.
func TestPartialPulses_Degenerate(t *testing.T) {
	start := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	end := start.Add(20 * time.Second)
	now := start.Add(5 * time.Second)

	if got := PartialPulses(0, start, end, now); got != 0 {
		t.Errorf("zero total -> %d, want 0", got)
	}
	if got := PartialPulses(10, time.Time{}, end, now); got != 0 {
		t.Errorf("zero start -> %d, want 0", got)
	}
	if got := PartialPulses(10, start, start, now); got != 0 {
		t.Errorf("end == start -> %d, want 0", got)
	}
	if got := PartialPulses(10, start, start.Add(-time.Second), now); got != 0 {
		t.Errorf("end < start -> %d, want 0", got)
	}
}
