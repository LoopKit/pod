package pair

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestO5KDFInputLayout asserts the exact byte layout of the KDF input buffer.
// If this drifts, OmnipodKit will compute different keys and pairing will fail.
func TestO5KDFInputLayout(t *testing.T) {
	// Distinguishable test vectors (not real key material).
	pdmPub := bytes.Repeat([]byte{0xAA}, 64)
	podPub := bytes.Repeat([]byte{0xBB}, 64)
	shared := bytes.Repeat([]byte{0xCC}, 32)

	got := o5KDFInput(pdmPub, podPub, shared)

	// Hand-built expected layout: each field length-prefixed by a 64-bit
	// big-endian length.
	var want bytes.Buffer
	want.Write([]byte{0, 0, 0, 0, 0, 0, 0, 6})
	want.Write(FirmwareID)
	want.Write([]byte{0, 0, 0, 0, 0, 0, 0, 4})
	want.Write([]byte{0, 0, 0, 0})
	want.Write([]byte{0, 0, 0, 0, 0, 0, 0, 64})
	want.Write(pdmPub)
	want.Write([]byte{0, 0, 0, 0, 0, 0, 0, 64})
	want.Write(podPub)
	want.Write([]byte{0, 0, 0, 0, 0, 0, 0, 32})
	want.Write(shared)

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("KDF input mismatch\n got: %x\nwant: %x", got, want.Bytes())
	}
	if len(got) != 210 {
		t.Fatalf("KDF input expected 210 bytes, got %d", len(got))
	}
}

// TestO5DeriveKeysShape verifies the SHA-256 output is split as conf||ltk.
func TestO5DeriveKeysShape(t *testing.T) {
	pdmPub := bytes.Repeat([]byte{0xAA}, 64)
	podPub := bytes.Repeat([]byte{0xBB}, 64)
	shared := bytes.Repeat([]byte{0xCC}, 32)

	conf, ltk, err := o5DeriveKeys(pdmPub, podPub, shared)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf) != 16 || len(ltk) != 16 {
		t.Fatalf("expected 16+16-byte keys, got %d+%d", len(conf), len(ltk))
	}
	full := sha256.Sum256(o5KDFInput(pdmPub, podPub, shared))
	if !bytes.Equal(conf, full[0:16]) || !bytes.Equal(ltk, full[16:32]) {
		t.Fatalf("conf/ltk should be SHA-256(input)[0:16] / [16:32]")
	}
}

// TestO5KDFFirmwareID pins FIRMWARE_ID to the value baked into OmnipodKit.
func TestO5KDFFirmwareID(t *testing.T) {
	want, _ := hex.DecodeString("9b0ab96a76f4")
	if !bytes.Equal(FirmwareID, want) {
		t.Fatalf("FirmwareID mismatch: got %x want %x", FirmwareID, want)
	}
}

func TestO5DeriveKeysRejectsBadSizes(t *testing.T) {
	_, _, err := o5DeriveKeys(make([]byte, 63), make([]byte, 64), make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for short pdmPublic")
	}
	_, _, err = o5DeriveKeys(make([]byte, 64), make([]byte, 64), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for short sharedSecret")
	}
}
