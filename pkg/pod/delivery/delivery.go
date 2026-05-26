// Package delivery contains pure helpers for computing in-flight bolus
// progress. It deliberately has no external imports beyond `time` so it can
// be unit-tested on any platform (the parent `pod` package imports BLE
// libraries that are Linux-only).
package delivery

import "time"

// PartialPulses returns the number of pulses delivered between `start` and
// `now`, capped at `total`. The bolus duration is given by `end - start`,
// which lets the caller choose the pulse cadence: prime and cannula-insert
// boluses run at 1 second per pulse on a real Omnipod 5, while user-issued
// boluses run at 2 seconds per pulse.
//
// Behaviour at the boundaries:
//   - start.IsZero()  || total == 0 || !end.After(start) → 0
//   - now ≤ start                                        → 0
//   - now ≥ end                                          → total
func PartialPulses(total uint16, start, end, now time.Time) uint16 {
	if start.IsZero() || total == 0 || !end.After(start) {
		return 0
	}
	if !now.After(start) {
		return 0
	}
	if !now.Before(end) {
		return total
	}
	elapsed := now.Sub(start)
	duration := end.Sub(start)
	delivered := uint64(total) * uint64(elapsed) / uint64(duration)
	if delivered >= uint64(total) {
		return total
	}
	return uint16(delivered)
}
