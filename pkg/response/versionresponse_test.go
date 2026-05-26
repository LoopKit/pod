package response

import (
	"encoding/hex"
	"testing"

	"github.com/avereha/pod/pkg/pair"
)

// TestVersionResponseMarshalDash pins the Dash mode byte stream so any
// unintended change to the response is caught by CI. This is the exact hex
// captured from a real Dash pod.
func TestVersionResponseMarshalDash(t *testing.T) {
	const want = "0115040A00010300040208146DB10006E45100FFFFFFFF"

	r := &VersionResponse{Mode: pair.ModeDash}
	got, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if hex.EncodeToString(got) != hexLower(want) {
		t.Fatalf("Dash VersionResponse bytes mismatch:\n got=%x\nwant=%s", got, hexLower(want))
	}
}

// TestVersionResponseMarshalZeroValueIsDash ensures legacy callers that
// construct &VersionResponse{} without setting Mode keep getting Dash bytes.
func TestVersionResponseMarshalZeroValueIsDash(t *testing.T) {
	const want = "0115040A00010300040208146DB10006E45100FFFFFFFF"

	r := &VersionResponse{}
	got, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if hex.EncodeToString(got) != hexLower(want) {
		t.Fatalf("zero-value VersionResponse bytes mismatch:\n got=%x\nwant=%s", got, hexLower(want))
	}
}

// TestVersionResponseMarshalO5 pins the Omnipod 5 mode byte stream as
// captured from a real Omnipod 5 pod (Pod Type ID 05, firmware 9.0.4, BLE
// firmware 5.0.2, Lot 261724721, TID 491153). Note this is 23 bytes vs the
// Dash response's 23 — same length, different field layout (no PR/PP/CP/PL
// preamble, but adds a 1-byte GS field before the trailing 0xFFFFFFFF).
func TestVersionResponseMarshalO5(t *testing.T) {
	const want = "011509000405000205020F999A3100077E9105FFFFFFFF"

	r := &VersionResponse{Mode: pair.ModeO5}
	got, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if hex.EncodeToString(got) != hexLower(want) {
		t.Fatalf("O5 VersionResponse bytes mismatch:\n got=%x\nwant=%s", got, hexLower(want))
	}
}
