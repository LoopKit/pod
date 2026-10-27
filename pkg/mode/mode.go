// Package mode names the pod the simulator plays: an Omnipod DASH or an
// Omnipod 5. The two share most of the protocol; the mode selects the
// advertisement, the BLE packet layout, the pairing exchange, the version
// responses and the Omnipod 5 extras (AID setup, signed commands).
package mode

import "fmt"

// Mode is stored in state.toml as its string form, so an older state file
// without a mode reads as the zero value, which is DASH.
type Mode string

const (
	Dash Mode = "dash"
	O5   Mode = "o5"
)

// Parse reads a -mode flag value.
func Parse(s string) (Mode, error) {
	switch Mode(s) {
	case Dash:
		return Dash, nil
	case O5:
		return O5, nil
	}
	return "", fmt.Errorf("mode %q: want dash or o5", s)
}

// IsO5 reports an Omnipod 5; anything else (including the zero value from
// an older state file) is a DASH pod.
func (m Mode) IsO5() bool { return m == O5 }

// Normalized maps the zero value to Dash.
func (m Mode) Normalized() Mode {
	if m.IsO5() {
		return O5
	}
	return Dash
}

func (m Mode) String() string { return string(m.Normalized()) }

// Describe names the pod for people: "Omnipod DASH" or "Omnipod 5".
func (m Mode) Describe() string {
	if m.IsO5() {
		return "Omnipod 5"
	}
	return "Omnipod DASH"
}

// ProductID is the pod type byte of the version responses: 4 for DASH, 5
// for Omnipod 5 (OmnipodKit PodType.PodModelType).
func (m Mode) ProductID() byte {
	if m.IsO5() {
		return 5
	}
	return 4
}
