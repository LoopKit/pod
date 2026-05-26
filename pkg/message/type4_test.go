package message

import (
	"bytes"
	"testing"
)

// TestUnmarshalType4 builds a synthetic Type-4 wire frame and asserts that
// Unmarshal correctly splits the AES-CCM ciphertext (length-from-header + 8B
// tag) from the trailing 64-byte ECDSA signature.
//
// Wire layout:
//
//	[16-byte header (length field = plaintext length)]
//	[plaintext-length bytes ciphertext]
//	[8-byte CCM tag]
//	[64-byte ECDSA signature]
func TestUnmarshalType4(t *testing.T) {
	src := []byte{0x01, 0x02, 0x03, 0x04}
	dst := []byte{0x05, 0x06, 0x07, 0x08}
	plaintextLen := 16

	// Use Marshal with a plaintext-only Payload so the header's length
	// field gets set to plaintextLen.
	m := &Message{
		Type:           MessageTypeEncryptedSigned,
		Source:         src,
		Destination:    dst,
		SequenceNumber: 7,
		Eqos:           1,
		Payload:        bytes.Repeat([]byte{0xCC}, plaintextLen),
	}
	headerAndPlaintext, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	tag := bytes.Repeat([]byte{0x99}, 8)
	signature := bytes.Repeat([]byte{0xAB}, 64)
	wire := append([]byte{}, headerAndPlaintext...)
	wire = append(wire, tag...)
	wire = append(wire, signature...)

	got, err := Unmarshal(wire)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Type != MessageTypeEncryptedSigned {
		t.Fatalf("type = %d, want %d (raw bytes %x)", got.Type, MessageTypeEncryptedSigned, wire[:8])
	}
	wantPayload := append(append([]byte{}, m.Payload...), tag...)
	if !bytes.Equal(got.Payload, wantPayload) {
		t.Errorf("payload mismatch:\n got  %x\n want %x", got.Payload, wantPayload)
	}
	if !bytes.Equal(got.Signature, signature) {
		t.Errorf("signature mismatch:\n got  %x\n want %x", got.Signature, signature)
	}
}

func TestUnmarshalType4Truncated(t *testing.T) {
	m := &Message{
		Type:           MessageTypeEncryptedSigned,
		Source:         []byte{1, 2, 3, 4},
		Destination:    []byte{5, 6, 7, 8},
		SequenceNumber: 1,
		Payload:        bytes.Repeat([]byte{0xCC}, 16),
	}
	headerAndPlaintext, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte{}, headerAndPlaintext...)
	wire = append(wire, bytes.Repeat([]byte{0x99}, 8)...) // tag
	wire = append(wire, bytes.Repeat([]byte{0xAB}, 32)...) // partial sig
	if _, err := Unmarshal(wire); err == nil {
		t.Fatal("expected error for truncated Type-4 frame")
	}
}
