package pair

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/avereha/pod/pkg/crc"
	aesccm "github.com/pschlump/AesCCM"
)

// The Omnipod 5 pairing, as OmnipodKit's O5LTKExchanger and O5KeyExchange
// run it from the phone's side.

// FirmwareID is the fixed 6-byte value the Omnipod 5 PDM firmware mixes
// into the key derivation and the signed transcripts (O5LTKExchanger.FIRMWARE_ID).
var FirmwareID = []byte{0x9b, 0x0a, 0xb9, 0x6a, 0x76, 0xf4}

const (
	o5PublicKeySize = 64 // P-256 point, X||Y, no 04 prefix
	o5NonceSize     = 16
	spsNonceSize    = 13
	spsTagSize      = 8
	o5SignatureSize = 64 // ECDSA r||s
	transcriptSize  = 171
)

// SPS0 is the first Omnipod 5 pairing exchange: 00, a direction byte (01
// from the phone, 00 from the pod), the algorithm 09, and the CRC-16/XMODEM
// of those three bytes (O5LTKExchanger.o5sps0, validatePodO5sps0).
func sps0Payload(fromPhone bool) []byte {
	direction := byte(0)
	if fromPhone {
		direction = 1
	}
	header := []byte{0x00, direction, 0x09}
	sum := crc.XMODEM(header)
	return append(header, byte(sum>>8), byte(sum))
}

func parseSPS0(payload []byte, fromPhone bool) error {
	want := sps0Payload(fromPhone)
	if len(payload) != len(want) {
		return fmt.Errorf("SPS0 payload is %d bytes, want %d", len(payload), len(want))
	}
	if !bytes.Equal(payload[:3], want[:3]) {
		return fmt.Errorf("unexpected SPS0 header %x", payload[:3])
	}
	if !bytes.Equal(payload[3:], want[3:]) {
		return fmt.Errorf("SPS0 CRC %x, want %x", payload[3:], want[3:])
	}
	return nil
}

// o5KDFInput is the buffer whose SHA-256 gives the pairing keys, each field
// behind its 64-bit big-endian length (O5KeyExchange.o5generateKeys):
//
//	FirmwareID (6) || 00000000 (4) || pdmPublic (64) || podPublic (64) || sharedSecret (32)
func o5KDFInput(pdmPublic, podPublic, sharedSecret []byte) []byte {
	var buf bytes.Buffer
	field := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	field(FirmwareID)
	field([]byte{0, 0, 0, 0})
	field(pdmPublic)
	field(podPublic)
	field(sharedSecret)
	return buf.Bytes()
}

// o5DeriveKeys splits the digest into conf (the SPS2.1/SPS2 AES-CCM key)
// and the LTK.
func o5DeriveKeys(pdmPublic, podPublic, sharedSecret []byte) (conf, ltk []byte, err error) {
	if len(pdmPublic) != o5PublicKeySize || len(podPublic) != o5PublicKeySize {
		return nil, nil, fmt.Errorf("public keys are %d and %d bytes, want %d", len(pdmPublic), len(podPublic), o5PublicKeySize)
	}
	if len(sharedSecret) != 32 {
		return nil, nil, fmt.Errorf("shared secret is %d bytes, want 32", len(sharedSecret))
	}
	sum := sha256.Sum256(o5KDFInput(pdmPublic, podPublic, sharedSecret))
	return sum[0:16], sum[16:32], nil
}

// o5ECDH is the P-256 shared secret of a raw private scalar and a raw
// public point.
func o5ECDH(private, public []byte) ([]byte, error) {
	priv, err := ecdh.P256().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, public...))
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// spsDirection names who is writing a pairing message under conf.
type spsDirection byte

const (
	spsPhoneToPod spsDirection = 0x01 // OmnipodKit's .write
	spsPodToPhone spsDirection = 0x02 // OmnipodKit's .read
)

// spsNonces are the two 16-byte SPS1 nonces as counters: the first 8 bytes
// of the writer's nonce, as a little-endian number, go up by one after each
// message it sends (O5KeyExchange.getSPSNonce, incrementNonce).
type spsNonces struct {
	pdm []byte
	pod []byte
}

func newSPSNonces(pdmNonce, podNonce []byte) (*spsNonces, error) {
	if len(pdmNonce) != o5NonceSize || len(podNonce) != o5NonceSize {
		return nil, fmt.Errorf("nonces are %d and %d bytes, want %d", len(pdmNonce), len(podNonce), o5NonceSize)
	}
	return &spsNonces{pdm: append([]byte(nil), pdmNonce...), pod: append([]byte(nil), podNonce...)}, nil
}

// nonce is the 13-byte AES-CCM nonce: the direction, then the writer's
// first 6 nonce bytes, then the reader's.
func (n *spsNonces) nonce(dir spsDirection) []byte {
	out := []byte{byte(dir)}
	if dir == spsPhoneToPod {
		out = append(out, n.pdm[:6]...)
		return append(out, n.pod[:6]...)
	}
	out = append(out, n.pod[:6]...)
	return append(out, n.pdm[:6]...)
}

func (n *spsNonces) increment(dir spsDirection) {
	target := n.pdm
	if dir == spsPodToPhone {
		target = n.pod
	}
	binary.LittleEndian.PutUint64(target[:8], binary.LittleEndian.Uint64(target[:8])+1)
}

func spsCCM(conf, nonce []byte) (aesccm.CCM, error) {
	block, err := aes.NewCipher(conf)
	if err != nil {
		return nil, err
	}
	return aesccm.NewCCM(block, spsTagSize, len(nonce))
}

// spsSeal encrypts a pairing payload for dir and advances its nonce. The
// SPS2.1 and SPS2 payloads have no associated data.
func (n *spsNonces) seal(conf []byte, dir spsDirection, plaintext []byte) ([]byte, error) {
	nonce := n.nonce(dir)
	c, err := spsCCM(conf, nonce)
	if err != nil {
		return nil, err
	}
	out := c.Seal(nil, nonce, plaintext, nil)
	n.increment(dir)
	return out, nil
}

// open decrypts a pairing payload written for dir and advances its nonce.
func (n *spsNonces) open(conf []byte, dir spsDirection, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= spsTagSize {
		return nil, fmt.Errorf("ciphertext of %d bytes has no room for a tag", len(ciphertext))
	}
	nonce := n.nonce(dir)
	c, err := spsCCM(conf, nonce)
	if err != nil {
		return nil, err
	}
	out, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	n.increment(dir)
	return out, nil
}

// phoneTranscript is what the phone signs in SPS2
// (O5KeyExchange.buildChannelBindingTranscript):
//
//	01 || FirmwareID || 00000000 || pdmPublic || podPublic || pdmNonce || podNonce
//
// with the nonces as the phone holds them after SPS2.1: both counters up by one.
func phoneTranscript(pdmPublic, podPublic, pdmNonce, podNonce []byte) []byte {
	out := make([]byte, 0, transcriptSize)
	out = append(out, 0x01)
	out = append(out, FirmwareID...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, pdmPublic...)
	out = append(out, podPublic...)
	out = append(out, pdmNonce...)
	return append(out, podNonce...)
}

// podTranscript is what the pod signs in SPS2
// (O5KeyExchange.buildPodChannelBindingTranscript):
//
//	02 || 00000000 || FirmwareID || podPublic || pdmPublic || podNonce || pdmNonce
//
// with the nonces as the pod holds them when it builds its SPS2: the pdm
// counter up by two (SPS2.1 and SPS2 received), the pod counter up by one
// (SPS2.1 sent). The phone verifies it after reading SPS2, so it steps its
// copy of the pod counter back by one first.
func podTranscript(pdmPublic, podPublic, pdmNonce, podNonce []byte) []byte {
	out := make([]byte, 0, transcriptSize)
	out = append(out, 0x02)
	out = append(out, 0, 0, 0, 0)
	out = append(out, FirmwareID...)
	out = append(out, podPublic...)
	out = append(out, pdmPublic...)
	out = append(out, podNonce...)
	return append(out, pdmNonce...)
}

func packRS(r, s *big.Int) []byte {
	out := make([]byte, o5SignatureSize)
	rb, sb := r.Bytes(), s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out
}

// signRaw is an ECDSA P-256 signature over SHA-256(data), as raw r||s.
func signRaw(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	return packRS(r, s), nil
}

// publicKeyFromRaw reads a 64-byte X||Y P-256 point.
func publicKeyFromRaw(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != o5PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), o5PublicKeySize)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(raw[:32]), Y: new(big.Int).SetBytes(raw[32:])}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("public key is not on P-256")
	}
	return pub, nil
}

// verifyRaw checks a raw r||s ECDSA P-256 signature over SHA-256(data).
func verifyRaw(publicRaw, data, signature []byte) (bool, error) {
	if len(signature) != o5SignatureSize {
		return false, fmt.Errorf("signature is %d bytes, want %d", len(signature), o5SignatureSize)
	}
	pub, err := publicKeyFromRaw(publicRaw)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(data)
	return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])), nil
}

// VerifySignedMessage checks the phone's signature on a type 4 message: the
// 16-byte header followed by the ciphertext and its tag, signed with the
// key in the phone's SPS2 certificate (OmnipodKit BleMessageTransport.getCmdMessage).
func VerifySignedMessage(phonePublicRaw, header, ciphertext, signature []byte) (bool, error) {
	if len(header) != 16 {
		return false, fmt.Errorf("header is %d bytes, want 16", len(header))
	}
	return verifyRaw(phonePublicRaw, append(append([]byte(nil), header...), ciphertext...), signature)
}

// p256SPKIHeader starts the SubjectPublicKeyInfo of a P-256 key in a DER
// certificate; the 64 bytes after it are the public point
// (O5CertificateStore.p256SPKIHeader).
var p256SPKIHeader = []byte{
	0x30, 0x59,
	0x30, 0x13,
	0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	0x03, 0x42,
	0x00,
	0x04,
}

// PublicKeyFromCert finds the P-256 public key in a DER certificate the way
// OmnipodKit does, by its SubjectPublicKeyInfo header, without validating
// the certificate.
func PublicKeyFromCert(certDER []byte) ([]byte, error) {
	i := bytes.Index(certDER, p256SPKIHeader)
	if i < 0 {
		return nil, errors.New("no P-256 SubjectPublicKeyInfo in the certificate")
	}
	start := i + len(p256SPKIHeader)
	if start+o5PublicKeySize > len(certDER) {
		return nil, errors.New("the certificate ends inside its public key")
	}
	return append([]byte(nil), certDER[start:start+o5PublicKeySize]...), nil
}

// PodIdentity is the P-256 key an Omnipod 5 pod signs with, and the
// certificate it sends in SPS2.1 and SPS2. The phone takes only the public
// key from the certificate and verifies the SPS2 signature with it, so a
// self-signed certificate serves.
type PodIdentity struct {
	Key     *ecdsa.PrivateKey
	CertDER []byte
}

// NewPodIdentity mints a key and a self-signed certificate.
func NewPodIdentity() (*PodIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "pod simulator"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &PodIdentity{Key: key, CertDER: der}, nil
}

// LoadPodIdentity restores an identity from its saved private scalar and
// certificate.
func LoadPodIdentity(private, certDER []byte) (*PodIdentity, error) {
	if len(private) != 32 || len(certDER) == 0 {
		return nil, errors.New("no saved pod identity")
	}
	d := new(big.Int).SetBytes(private)
	curve := elliptic.P256()
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("saved private key is not a P-256 scalar")
	}
	key := &ecdsa.PrivateKey{D: d, PublicKey: ecdsa.PublicKey{Curve: curve}}
	key.X, key.Y = curve.ScalarBaseMult(private)
	return &PodIdentity{Key: key, CertDER: certDER}, nil
}

// Private is the 32-byte scalar to save.
func (id *PodIdentity) Private() []byte {
	out := make([]byte, 32)
	d := id.Key.D.Bytes()
	copy(out[32-len(d):], d)
	return out
}

// PublicRaw is the 64-byte X||Y public point.
func (id *PodIdentity) PublicRaw() []byte {
	out := make([]byte, o5PublicKeySize)
	x, y := id.Key.X.Bytes(), id.Key.Y.Bytes()
	copy(out[32-len(x):32], x)
	copy(out[64-len(y):], y)
	return out
}
