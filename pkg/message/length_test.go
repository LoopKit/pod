package message

import (
	"bytes"
	"testing"
)

// TestUnmarshalLargePayloadLength reproduces the SPS2.1-sized 11-bit length
// encoding bug: with a payload of 651 bytes, the TWi length-field bytes are
// 0x51 0x60. The original Unmarshal computed `data[6]<<3 | data[7]>>5` in
// uint8 space, which truncates 0x51<<3 to 0x88 and yields 139 instead of 651.
// This test pins the cast-to-uint16 fix.
func TestUnmarshalLargePayloadLength(t *testing.T) {
	const wantLen = 651
	src := []byte{0xff, 0xff, 0xff, 0xfe}
	dst := []byte{0x00, 0x29, 0x21, 0xf0}

	m := &Message{
		Type:        MessageTypePairing,
		Source:      src,
		Destination: dst,
		Payload:     bytes.Repeat([]byte{0xCC}, wantLen),
	}
	wire, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	got, err := Unmarshal(wire)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Payload) != wantLen {
		t.Errorf("payload len = %d, want %d (uint8 shift overflow regression?)", len(got.Payload), wantLen)
	}
	if !bytes.Equal(got.Payload, m.Payload) {
		t.Error("payload bytes mismatch")
	}
}

// TestUnmarshalMaxPayloadLength tests the upper end of the 11-bit length
// field (2047 bytes). Marshal/Unmarshal must round-trip cleanly.
func TestUnmarshalMaxPayloadLength(t *testing.T) {
	const wantLen = 2047
	m := &Message{
		Type:        MessageTypePairing,
		Source:      []byte{1, 2, 3, 4},
		Destination: []byte{5, 6, 7, 8},
		Payload:     bytes.Repeat([]byte{0xAB}, wantLen),
	}
	wire, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(wire)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Payload) != wantLen {
		t.Errorf("payload len = %d, want %d", len(got.Payload), wantLen)
	}
}
