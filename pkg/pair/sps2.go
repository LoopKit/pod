package pair

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	aesccm "github.com/pschlump/AesCCM"
	log "github.com/sirupsen/logrus"
)

// sps2CCM returns an AES-CCM mode with key=conf, 13-byte nonce, 8-byte tag.
// SPS2.1 / SPS2 do not bind any associated data — see O5LTKExchanger.swift
// (no AAD argument is passed to CryptoSwift's CCM constructor).
func sps2CCM(conf, nonce []byte) (aesccm.CCM, error) {
	block, err := aes.NewCipher(conf)
	if err != nil {
		return nil, err
	}
	return aesccm.NewCCM(block, 8, len(nonce))
}

// EncryptSPS21 produces the AES-CCM-encrypted pod SPS2.1 payload.
//
// Plaintext is the pod's intermediate-CA cert DER (any length the synthetic
// chain produces; pod-side just needs *a* DER cert wrapping its pubkey).
// Output is plaintext encrypted under conf with the read-direction SPS-nonce,
// followed by an 8-byte CCM authentication tag.
//
// Mirrors O5LTKExchanger.swift:347-369 (controller side) but emits the read
// direction since pod sends the response.
func encryptSPS21(conf []byte, nonceState *spsNonceState, certDER []byte) ([]byte, error) {
	nonce := nonceState.build(SPSRead)
	c, err := sps2CCM(conf, nonce)
	if err != nil {
		return nil, fmt.Errorf("SPS2.1 encrypt: %w", err)
	}
	out := c.Seal(nil, nonce, certDER, nil)
	nonceState.increment(SPSRead)
	log.Debugf("SPS2.1 encrypted: %d plaintext -> %d ciphertext", len(certDER), len(out))
	return out, nil
}

// DecryptSPS21 returns the plaintext PDM intermediate-CA cert DER.
// Mirrors O5LTKExchanger.swift:378-419 (controller validates pod direction;
// pod-side does the symmetric thing for the controller direction).
func decryptSPS21(conf []byte, nonceState *spsNonceState, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= 8 {
		return nil, fmt.Errorf("SPS2.1 ciphertext too short: %d bytes", len(ciphertext))
	}
	nonce := nonceState.build(SPSWrite)
	c, err := sps2CCM(conf, nonce)
	if err != nil {
		return nil, fmt.Errorf("SPS2.1 decrypt: %w", err)
	}
	pt, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("SPS2.1 decrypt: %w", err)
	}
	nonceState.increment(SPSWrite)
	log.Debugf("SPS2.1 decrypted: %d ciphertext -> %d plaintext", len(ciphertext), len(pt))
	return pt, nil
}

// EncryptSPS2 produces the AES-CCM-encrypted pod SPS2 payload, which is
// `cert_DER || ECDSA_signature(64 bytes raw r||s)` encrypted under conf with
// the read-direction SPS-nonce + 8-byte tag.
//
// Mirrors O5LTKExchanger.swift:431-469.
func encryptSPS2(conf []byte, nonceState *spsNonceState, certDER, signatureRaw []byte) ([]byte, error) {
	if len(signatureRaw) != 64 {
		return nil, fmt.Errorf("SPS2 encrypt: signature must be 64 bytes raw r||s, got %d", len(signatureRaw))
	}
	plaintext := make([]byte, 0, len(certDER)+64)
	plaintext = append(plaintext, certDER...)
	plaintext = append(plaintext, signatureRaw...)

	nonce := nonceState.build(SPSRead)
	c, err := sps2CCM(conf, nonce)
	if err != nil {
		return nil, fmt.Errorf("SPS2 encrypt: %w", err)
	}
	out := c.Seal(nil, nonce, plaintext, nil)
	nonceState.increment(SPSRead)
	log.Debugf("SPS2 encrypted: %d plaintext (cert=%d + sig=64) -> %d ciphertext", len(plaintext), len(certDER), len(out))
	return out, nil
}

// DecryptSPS2 returns the PDM cert DER and the 64-byte signature contained in
// the encrypted SPS2 payload.
//
// Mirrors O5LTKExchanger.swift:475-535.
func decryptSPS2(conf []byte, nonceState *spsNonceState, ciphertext []byte) (certDER, signatureRaw []byte, err error) {
	if len(ciphertext) <= 8+64 {
		return nil, nil, fmt.Errorf("SPS2 ciphertext too short: %d bytes", len(ciphertext))
	}
	nonce := nonceState.build(SPSWrite)
	c, err := sps2CCM(conf, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("SPS2 decrypt: %w", err)
	}
	pt, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("SPS2 decrypt: %w", err)
	}
	nonceState.increment(SPSWrite)

	certLen := len(pt) - 64
	certDER = make([]byte, certLen)
	signatureRaw = make([]byte, 64)
	copy(certDER, pt[:certLen])
	copy(signatureRaw, pt[certLen:])
	return certDER, signatureRaw, nil
}

// buildPDMTranscript builds the 171-byte channel-binding transcript that the
// PDM signed in SPS2. Mirrors O5KeyExchange.swift buildChannelBindingTranscript
// (lines 173-197). Pod uses this to verify the PDM's incoming signature.
//
//	[0x01] || FIRMWARE_ID(6) || zeros(4) || pdmPublic(64) || podPublic(64) || pdmNonce(16) || podNonce(16)
func buildPDMTranscript(pdmPublic, podPublic, pdmNonce, podNonce []byte) []byte {
	out := make([]byte, 0, 171)
	out = append(out, 0x01)
	out = append(out, FirmwareID...)
	out = append(out, 0x00, 0x00, 0x00, 0x00)
	out = append(out, pdmPublic...)
	out = append(out, podPublic...)
	out = append(out, pdmNonce...)
	out = append(out, podNonce...)
	return out
}

// buildPodTranscript builds the 171-byte channel-binding transcript that the
// pod signs in SPS2. Mirrors O5KeyExchange.swift buildPodChannelBindingTranscript
// (lines 224-253). Note the swapped FIRMWARE_ID/zeros position relative to the
// PDM transcript and the keys/nonces grouped pod-first, pdm-second.
//
//	[0x02] || zeros(4) || FIRMWARE_ID(6) || podPublic(64) || pdmPublic(64) || podNonce(16) || pdmNonce(16)
//
// The OmnipodKit verifier expects the pod to have signed its transcript with
// podNonce in the state it had AFTER incrementing for SPS2.1 only (i.e.
// before the pod incremented again for sending SPS2). On the pod side, that's
// exactly the value of podNonce at the moment we are about to encrypt SPS2 —
// so no manual decrement is needed here. The decrement quirk in the Swift
// verifier comes from the controller having advanced its `podNonce` mirror
// twice by the time it verifies.
func buildPodTranscript(pdmPublic, podPublic, pdmNonce, podNonce []byte) []byte {
	out := make([]byte, 0, 171)
	out = append(out, 0x02)
	out = append(out, 0x00, 0x00, 0x00, 0x00)
	out = append(out, FirmwareID...)
	out = append(out, podPublic...)
	out = append(out, pdmPublic...)
	out = append(out, podNonce...)
	out = append(out, pdmNonce...)
	return out
}

// signTranscript signs an already-built transcript with the pod's private key
// and returns the 64-byte raw r||s representation OmnipodKit expects.
func signTranscript(priv *ecdsa.PrivateKey, transcript []byte) ([]byte, error) {
	digest := sha256.Sum256(transcript)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	return packRS(r, s), nil
}

// VerifyType4Signature verifies the 64-byte raw r||s ECDSA signature on a
// Type-4 (ENCRYPTED_SIGNED) command. The signing input is exactly the 16-byte
// TWi header followed by the AES-CCM ciphertext (including the 8-byte tag);
// see OmnipodKit BleMessageTransport.swift getCmdMessage signing block.
//
// pubkeyRaw is the 64-byte raw P-256 public key (X||Y) extracted from the
// PDM's TLS leaf certificate at SPS2 time.
func VerifyType4Signature(pubkeyRaw, header, ciphertext, signatureRaw []byte) (bool, error) {
	if len(pubkeyRaw) != 64 {
		return false, fmt.Errorf("VerifyType4Signature: pubkey must be 64 bytes, got %d", len(pubkeyRaw))
	}
	if len(signatureRaw) != 64 {
		return false, fmt.Errorf("VerifyType4Signature: signature must be 64 bytes, got %d", len(signatureRaw))
	}
	if len(header) != 16 {
		return false, fmt.Errorf("VerifyType4Signature: header must be 16 bytes, got %d", len(header))
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(pubkeyRaw[:32]),
		Y:     new(big.Int).SetBytes(pubkeyRaw[32:]),
	}
	signingInput := make([]byte, 0, len(header)+len(ciphertext))
	signingInput = append(signingInput, header...)
	signingInput = append(signingInput, ciphertext...)
	digest := sha256.Sum256(signingInput)
	r := new(big.Int).SetBytes(signatureRaw[:32])
	s := new(big.Int).SetBytes(signatureRaw[32:])
	return ecdsa.Verify(pub, digest[:], r, s), nil
}

// verifyTranscript verifies a 64-byte raw r||s signature over a transcript
// using a public key extracted from a DER cert.
func verifyTranscript(certDER, transcript, signatureRaw []byte) (bool, error) {
	if len(signatureRaw) != 64 {
		return false, fmt.Errorf("signature must be 64 bytes, got %d", len(signatureRaw))
	}
	pub, err := extractP256PublicKey(certDER)
	if err != nil {
		return false, err
	}
	r := new(big.Int).SetBytes(signatureRaw[:32])
	s := new(big.Int).SetBytes(signatureRaw[32:])
	digest := sha256.Sum256(transcript)
	return ecdsa.Verify(pub, digest[:], r, s), nil
}

func packRS(r, s *big.Int) []byte {
	out := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):64], sb)
	return out
}

// p256SPKIHeader is the fixed 26-byte prefix of an X.509 SubjectPublicKeyInfo
// for an uncompressed P-256 public key. The next 64 bytes are the raw X||Y
// coordinates. Mirrors O5CertificateStore.swift p256SPKIHeader.
var p256SPKIHeader = []byte{
	0x30, 0x59,
	0x30, 0x13,
	0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	0x03, 0x42,
	0x00,
	0x04,
}

// extractP256PublicKey scans a DER cert for the SubjectPublicKeyInfo prefix
// for a P-256 uncompressed key and returns it as an *ecdsa.PublicKey.
// Mirrors O5CertificateStore.swift extractP256PublicKey(fromDERCert:).
func extractP256PublicKey(certDER []byte) (*ecdsa.PublicKey, error) {
	idx := bytes.Index(certDER, p256SPKIHeader)
	if idx < 0 {
		return nil, errors.New("extractP256PublicKey: SPKI header not found")
	}
	keyStart := idx + len(p256SPKIHeader)
	if keyStart+64 > len(certDER) {
		return nil, errors.New("extractP256PublicKey: cert truncated after SPKI header")
	}
	x := new(big.Int).SetBytes(certDER[keyStart : keyStart+32])
	y := new(big.Int).SetBytes(certDER[keyStart+32 : keyStart+64])
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// (kept for symmetry with binary.* helpers used elsewhere in the package)
var _ = binary.BigEndian
