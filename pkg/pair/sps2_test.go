package pair

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func makeNonceState(t *testing.T) *spsNonceState {
	t.Helper()
	pdm := make([]byte, 16)
	pod := make([]byte, 16)
	rand.Read(pdm)
	rand.Read(pod)
	s, err := newSPSNonceState(pdm, pod)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSPS21RoundTrip(t *testing.T) {
	conf := bytes.Repeat([]byte{0x42}, 16)
	plaintext := []byte("intermediate-CA-cert-DER-stand-in")

	// Two parallel state machines so write side advances independently of
	// read side, mirroring the controller/pod relationship.
	enc := makeNonceState(t)
	dec, err := newSPSNonceState(enc.pdm, enc.pod)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt as if pod->phone (read direction).
	ct, err := encryptSPS21(conf, enc, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) != len(plaintext)+8 {
		t.Fatalf("ciphertext should be plaintext+8B tag, got %d for %d-byte plaintext", len(ct), len(plaintext))
	}

	// Decrypt with a fresh state on the other side using the SPS *write* path
	// — i.e., the receiver of pod->phone, in our verifier model. To keep the
	// round-trip self-consistent we mirror by calling decrypt on a state that
	// agrees on the pod-side nonce. Simpler: just decrypt with a freshly
	// initialised state under the read path (matching directions).
	pt, err := decryptAsRead(conf, dec, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch: got %x want %x", pt, plaintext)
	}
}

// decryptAsRead is a test helper that decrypts a ciphertext that was produced
// in the read direction by encryptSPS21 — useful for in-process round-trip
// tests where there is no separate writer/reader.
func decryptAsRead(conf []byte, ns *spsNonceState, ciphertext []byte) ([]byte, error) {
	nonce := ns.build(SPSRead)
	c, err := sps2CCM(conf, nonce)
	if err != nil {
		return nil, err
	}
	pt, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	ns.increment(SPSRead)
	return pt, nil
}

// TestSPS2RoundTripWithSignature mints a pod identity, signs the pod
// transcript, encrypts SPS2, then decrypts and verifies the signature.
func TestSPS2RoundTripWithSignature(t *testing.T) {
	conf := bytes.Repeat([]byte{0x77}, 16)
	pdmPub := bytes.Repeat([]byte{0x11}, 64)
	podPub := bytes.Repeat([]byte{0x22}, 64)
	pdmNonce := bytes.Repeat([]byte{0x33}, 16)
	podNonce := bytes.Repeat([]byte{0x44}, 16)

	id, err := NewPodIdentity()
	if err != nil {
		t.Fatal(err)
	}

	transcript := buildPodTranscript(pdmPub, podPub, pdmNonce, podNonce)
	if len(transcript) != 171 {
		t.Fatalf("pod transcript expected 171 bytes, got %d", len(transcript))
	}

	sig, err := signTranscript(id.PrivateKey, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("sig should be 64 bytes, got %d", len(sig))
	}

	enc := makeNonceState(t)
	dec, err := newSPSNonceState(enc.pdm, enc.pod)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := encryptSPS2(conf, enc, id.CertDER, sig)
	if err != nil {
		t.Fatal(err)
	}
	gotCert, gotSig, err := decryptSPS2AsRead(conf, dec, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCert, id.CertDER) {
		t.Errorf("cert mismatch")
	}
	if !bytes.Equal(gotSig, sig) {
		t.Errorf("signature mismatch")
	}

	// Verify the signature using the cert (as OmnipodKit's verifier does).
	ok, err := verifyTranscript(gotCert, transcript, gotSig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature verification failed")
	}
}

func decryptSPS2AsRead(conf []byte, ns *spsNonceState, ciphertext []byte) ([]byte, []byte, error) {
	nonce := ns.build(SPSRead)
	c, err := sps2CCM(conf, nonce)
	if err != nil {
		return nil, nil, err
	}
	pt, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}
	ns.increment(SPSRead)
	certLen := len(pt) - 64
	return pt[:certLen], pt[certLen:], nil
}

func TestPodIdentityScalarRoundTrip(t *testing.T) {
	id, err := NewPodIdentity()
	if err != nil {
		t.Fatal(err)
	}
	scalar := id.PrivateScalar()
	if len(scalar) != 32 {
		t.Fatalf("scalar expected 32 bytes, got %d", len(scalar))
	}
	loaded, err := LoadPodIdentity(scalar, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PrivateKey.D.Cmp(id.PrivateKey.D) != 0 {
		t.Fatal("scalar round-trip mismatch")
	}
	// Public key should match too.
	if !bytes.Equal(loaded.PublicKeyRaw(), id.PublicKeyRaw()) {
		t.Fatal("public key round-trip mismatch")
	}
}

func TestExtractP256PublicKey(t *testing.T) {
	id, err := NewPodIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := extractP256PublicKey(id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(id.PrivateKey.PublicKey.X) != 0 || pub.Y.Cmp(id.PrivateKey.PublicKey.Y) != 0 {
		t.Fatal("extracted public key does not match cert's actual public key")
	}
}

func TestPDMTranscriptShape(t *testing.T) {
	pdmPub := bytes.Repeat([]byte{1}, 64)
	podPub := bytes.Repeat([]byte{2}, 64)
	pdmNonce := bytes.Repeat([]byte{3}, 16)
	podNonce := bytes.Repeat([]byte{4}, 16)
	tr := buildPDMTranscript(pdmPub, podPub, pdmNonce, podNonce)
	if len(tr) != 171 {
		t.Fatalf("PDM transcript expected 171 bytes, got %d", len(tr))
	}
	if tr[0] != 0x01 {
		t.Errorf("type byte should be 0x01 for PDM, got %x", tr[0])
	}
	if !bytes.Equal(tr[1:7], FirmwareID) {
		t.Errorf("PDM transcript should have FIRMWARE_ID at bytes 1-6")
	}
}
