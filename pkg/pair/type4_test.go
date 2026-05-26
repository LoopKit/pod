package pair

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// TestVerifyType4Signature_RoundTrip mirrors the controller-side signing
// behaviour from BleMessageTransport.swift: signing input is
// [16-byte header || ciphertext]. Pod-side verification must accept that
// exact input.
func TestVerifyType4Signature_RoundTrip(t *testing.T) {
	id, err := NewPodIdentity()
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 16)
	for i := range header {
		header[i] = byte(i)
	}
	ciphertext := []byte("pretend-this-is-AES-CCM-ciphertext-plus-tag-bytes")

	signingInput := append([]byte{}, header...)
	signingInput = append(signingInput, ciphertext...)
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, id.PrivateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := packRS(r, s)

	ok, err := VerifyType4Signature(id.PublicKeyRaw(), header, ciphertext, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature should verify")
	}

	// Tampered ciphertext should fail.
	ciphertext[0] ^= 0xff
	ok, err = VerifyType4Signature(id.PublicKeyRaw(), header, ciphertext, sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("signature should not verify after ciphertext tamper")
	}
}

func TestVerifyType4Signature_BadInputs(t *testing.T) {
	good := make([]byte, 64)
	if _, err := VerifyType4Signature(make([]byte, 63), make([]byte, 16), nil, good); err == nil {
		t.Error("short pubkey should error")
	}
	if _, err := VerifyType4Signature(good, make([]byte, 16), nil, make([]byte, 63)); err == nil {
		t.Error("short signature should error")
	}
	if _, err := VerifyType4Signature(good, make([]byte, 8), nil, good); err == nil {
		t.Error("short header should error")
	}
}
