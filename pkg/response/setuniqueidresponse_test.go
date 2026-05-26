package response

import (
	"encoding/hex"
	"testing"

	"github.com/avereha/pod/pkg/pair"
)

// TestSetUniqueIDMarshalDash pins the Dash mode byte stream so any unintended
// change to the response is caught by CI. This is the exact hex captured from
// a real Dash pod.
func TestSetUniqueIDMarshalDash(t *testing.T) {
	const want = "011B13881008340A50040A00010300040308146DB10006E45100001091"

	r := &SetUniqueID{Mode: pair.ModeDash}
	got, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if hex.EncodeToString(got) != hexLower(want) {
		t.Fatalf("Dash SetUniqueID bytes mismatch:\n got=%x\nwant=%s", got, hexLower(want))
	}
}

// TestSetUniqueIDMarshalZeroValueIsDash ensures legacy callers that construct
// &SetUniqueID{} without setting Mode keep getting the Dash bytes.
func TestSetUniqueIDMarshalZeroValueIsDash(t *testing.T) {
	const want = "011B13881008340A50040A00010300040308146DB10006E45100001091"

	r := &SetUniqueID{}
	got, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if hex.EncodeToString(got) != hexLower(want) {
		t.Fatalf("zero-value SetUniqueID bytes mismatch:\n got=%x\nwant=%s", got, hexLower(want))
	}
}

// TestSetUniqueIDMarshalO5 pins the Omnipod 5 mode byte stream as captured
// from a real Omnipod 5 pod (Pod Type ID 05, firmware 9.0.4, BLE firmware
// 5.0.2, Lot 261724721, TID 491153).
func TestSetUniqueIDMarshalO5(t *testing.T) {
	const want = "011B13881008340A5009000405000205030F999A3100077E9100000000"

	r := &SetUniqueID{Mode: pair.ModeO5}
	got, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if hex.EncodeToString(got) != hexLower(want) {
		t.Fatalf("O5 SetUniqueID bytes mismatch:\n got=%x\nwant=%s", got, hexLower(want))
	}
}

// hexLower normalises a hex literal to lowercase so comparisons against
// encoding/hex output don't trip on case differences.
func hexLower(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
