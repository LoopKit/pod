package pair

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// PodIdentity is the P-256 keypair used to sign SPS2 channel-binding
// transcripts (and Type-4 post-pairing messages). The DER cert wraps the
// matching public key in an X.509 SubjectPublicKeyInfo OmnipodKit knows how to
// parse via O5CertificateStore.extractP256PublicKey.
type PodIdentity struct {
	PrivateKey *ecdsa.PrivateKey
	CertDER    []byte
}

// NewPodIdentity mints a fresh P-256 keypair and a self-signed certificate
// that wraps it. We don't bother with a real chain (INS00PG1 etc.) — OmnipodKit
// only extracts the leaf public key and verifies the signature, it does not
// validate the chain. See O5CertificateStore.swift `o5validatePodSps2`.
func NewPodIdentity() (*PodIdentity, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pod identity: generate key: %w", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "pod-five-simulator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("pod identity: self-sign: %w", err)
	}
	return &PodIdentity{PrivateKey: priv, CertDER: der}, nil
}

// LoadPodIdentity reconstructs a PodIdentity from its serialised parts.
// privScalar is the raw 32-byte P-256 private key as `D.Bytes()` (left-padded
// if needed). certDER is the X.509 DER produced by NewPodIdentity.
func LoadPodIdentity(privScalar, certDER []byte) (*PodIdentity, error) {
	if len(privScalar) == 0 || len(certDER) == 0 {
		return nil, errors.New("pod identity: empty private key or cert")
	}
	d := new(big.Int).SetBytes(privScalar)
	curve := elliptic.P256()
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("pod identity: scalar out of range")
	}
	priv := &ecdsa.PrivateKey{
		D: d,
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
	}
	priv.X, priv.Y = curve.ScalarBaseMult(privScalar)
	return &PodIdentity{PrivateKey: priv, CertDER: certDER}, nil
}

// PrivateScalar returns the raw 32-byte P-256 private key.
func (p *PodIdentity) PrivateScalar() []byte {
	d := p.PrivateKey.D.Bytes()
	if len(d) == 32 {
		return d
	}
	out := make([]byte, 32)
	copy(out[32-len(d):], d)
	return out
}

// PublicKeyRaw returns the 64-byte uncompressed P-256 public key (X || Y) with
// no 0x04 prefix, matching OmnipodKit's representation.
func (p *PodIdentity) PublicKeyRaw() []byte {
	x := p.PrivateKey.PublicKey.X.Bytes()
	y := p.PrivateKey.PublicKey.Y.Bytes()
	out := make([]byte, 64)
	copy(out[32-len(x):32], x)
	copy(out[64-len(y):64], y)
	return out
}
