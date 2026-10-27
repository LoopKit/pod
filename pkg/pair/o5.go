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
	"fmt"
	"math/big"
	"time"

	"github.com/avereha/pod/pkg/crc"
	"github.com/avereha/pod/pkg/message"

	aesccm "github.com/pschlump/AesCCM"
	log "github.com/sirupsen/logrus"
)

// The Omnipod 5 pairing exchange, from the pod's side. OmnipodKit runs the
// phone's side in O5LTKExchanger and O5KeyExchange; this follows those.
//
// It replaces the DASH exchange's Curve25519 and CMAC with P-256 ECDH, a
// SHA-256 key derivation, and two rounds in which each side shows an X.509
// certificate and signs what both have said so far. Neither side validates
// the other's certificate chain — the phone reads the public key out of the
// pod's certificate to check its signature, and the pod does the same with
// the phone's — so a self-signed certificate pairs with this simulator
// while a real pod would still want Insulet's.

const (
	o5sps0   = "SPS0="
	o5sps1   = "SPS1="
	o5sps21  = "SPS2.1="
	o5sps2   = "SPS2="
	o5p0     = "P0="
	o5sp0gp0 = "SP0,GP0"
)

const (
	publicKeySize = 64 // a P-256 point as X||Y, without the 04 prefix
	nonceSize     = 16
	spsNonceSize  = 13
	spsTagSize    = 8
	signatureSize = 64 // ECDSA P-256 as r||s
	transcriptLen = 171
)

// firmwareID is the fixed 6-byte value the PDM firmware mixes into the key
// derivation and into both signed transcripts (O5LTKExchanger.FIRMWARE_ID).
var firmwareID = []byte{0x9b, 0x0a, 0xb9, 0x6a, 0x76, 0xf4}

// O5 is one Omnipod 5 pairing exchange.
type O5 struct {
	podID []byte
	pdmID []byte

	ecdhPrivate *ecdh.PrivateKey
	podPublic   []byte
	podNonce    []byte
	pdmPublic   []byte
	pdmNonce    []byte

	conf   []byte // the key the SPS2.1 and SPS2 payloads are encrypted under
	ltk    []byte
	nonces *spsNonces

	// identity is the key the pod's certificate carries and signs with.
	identity *ecdsa.PrivateKey
	certDER  []byte

	// controllerPublic is the phone's signing key, read out of the
	// certificate it shows in SPS2. Signed commands are checked against it.
	controllerPublic []byte
}

// NewO5 makes a pod identity for one pairing: an ECDH key for the key
// exchange and a self-signed certificate for the two certificate rounds.
func NewO5() (*O5, error) {
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not make the pod's ECDH key: %w", err)
	}
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not make the pod's signing key: %w", err)
	}
	certDER, err := selfSignedCert(identity, "pod simulator pod")
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &O5{
		ecdhPrivate: ecdhKey,
		podPublic:   ecdhKey.PublicKey().Bytes()[1:], // drop the 04 prefix
		podNonce:    nonce,
		identity:    identity,
		certDER:     certDER,
	}, nil
}

// LTK is the long-term key the exchange produced.
func (c *O5) LTK() ([]byte, error) {
	if len(c.ltk) != 16 {
		return nil, fmt.Errorf("the pairing produced no long-term key")
	}
	return c.ltk, nil
}

// ControllerPublic is the phone's signing key, for checking the signature
// on the commands that must carry one.
func (c *O5) ControllerPublic() []byte { return c.controllerPublic }

// PodID is the id the phone assigned the pod in SP1.
func (c *O5) PodID() []byte { return c.podID }

// PdmID is the controller's id.
func (c *O5) PdmID() []byte { return c.pdmID }

// ParseSP1SP2 reads the first pairing message, which names the id the pod
// is to take (SP1) and carries a status command for it (SP2).
func (c *O5) ParseSP1SP2(msg *message.Message) error {
	sp, err := parseStringByte([]string{sp1, sp2}, msg.Payload)
	if err != nil {
		return err
	}
	if len(sp[sp1]) != 4 {
		return fmt.Errorf("SP1 holds %d bytes, want the pod's 4-byte id", len(sp[sp1]))
	}
	c.podID = append([]byte(nil), sp[sp1]...)
	c.pdmID = append([]byte(nil), msg.Source...)
	log.Infof("pkg pair; Omnipod 5 pairing for pod %x from controller %x", c.podID, c.pdmID)
	return nil
}

// ParseSPS0 checks the phone's SPS0, which names the encryption algorithm.
func (c *O5) ParseSPS0(msg *message.Message) error {
	sp, err := parseStringByte([]string{o5sps0}, msg.Payload)
	if err != nil {
		return err
	}
	return checkSPS0(sp[o5sps0], true)
}

// GenerateSPS0 answers with the pod's side of SPS0.
func (c *O5) GenerateSPS0() (*message.Message, error) {
	return c.pairMessage(o5sps0, sps0Payload(false))
}

// ParseSPS1 takes the phone's public key and nonce, and derives the keys.
func (c *O5) ParseSPS1(msg *message.Message) error {
	sp, err := parseStringByte([]string{o5sps1}, msg.Payload)
	if err != nil {
		return err
	}
	payload := sp[o5sps1]
	if len(payload) != publicKeySize+nonceSize {
		return fmt.Errorf("SPS1 holds %d bytes, want %d", len(payload), publicKeySize+nonceSize)
	}
	c.pdmPublic = append([]byte(nil), payload[:publicKeySize]...)
	c.pdmNonce = append([]byte(nil), payload[publicKeySize:]...)

	peer, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, c.pdmPublic...))
	if err != nil {
		return fmt.Errorf("the phone's public key is not a P-256 point: %w", err)
	}
	shared, err := c.ecdhPrivate.ECDH(peer)
	if err != nil {
		return fmt.Errorf("could not agree a shared secret: %w", err)
	}
	c.conf, c.ltk, err = deriveKeys(c.pdmPublic, c.podPublic, shared)
	if err != nil {
		return err
	}
	c.nonces, err = newSPSNonces(c.pdmNonce, c.podNonce)
	if err != nil {
		return err
	}
	log.Debugf("pkg pair; derived conf %x and LTK %x", c.conf, c.ltk)
	return nil
}

// GenerateSPS1 sends the pod's public key and nonce.
func (c *O5) GenerateSPS1() (*message.Message, error) {
	return c.pairMessage(o5sps1, append(append([]byte(nil), c.podPublic...), c.podNonce...))
}

// ParseSPS21 reads the phone's first certificate. Its contents are not
// checked: the phone's signing key arrives with SPS2, and no chain is
// validated on either side.
func (c *O5) ParseSPS21(msg *message.Message) error {
	sp, err := parseStringByte([]string{o5sps21}, msg.Payload)
	if err != nil {
		return err
	}
	plain, err := c.nonces.open(c.conf, spsPhoneToPod, sp[o5sps21])
	if err != nil {
		return fmt.Errorf("could not decrypt SPS2.1: %w", err)
	}
	log.Debugf("pkg pair; the phone's SPS2.1 certificate is %d bytes", len(plain))
	return nil
}

// GenerateSPS21 shows the pod's certificate.
func (c *O5) GenerateSPS21() (*message.Message, error) {
	sealed, err := c.nonces.seal(c.conf, spsPodToPhone, c.certDER)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt SPS2.1: %w", err)
	}
	return c.pairMessage(o5sps21, sealed)
}

// ParseSPS2 reads the phone's certificate and its signature over
// everything both sides have said, and checks that signature.
func (c *O5) ParseSPS2(msg *message.Message) error {
	sp, err := parseStringByte([]string{o5sps2}, msg.Payload)
	if err != nil {
		return err
	}

	// The phone signed before the write that carries the signature, so its
	// transcript holds the nonces as they are now, before open advances them.
	transcript := c.phoneTranscript()

	plain, err := c.nonces.open(c.conf, spsPhoneToPod, sp[o5sps2])
	if err != nil {
		return fmt.Errorf("could not decrypt SPS2: %w", err)
	}
	if len(plain) <= signatureSize {
		return fmt.Errorf("SPS2 holds %d bytes, too few for a certificate and a signature", len(plain))
	}
	certDER := plain[:len(plain)-signatureSize]
	signature := plain[len(plain)-signatureSize:]

	public, err := publicKeyFromCert(certDER)
	if err != nil {
		return fmt.Errorf("could not read the phone's certificate: %w", err)
	}
	c.controllerPublic = public

	if VerifyP256(public, transcript, signature) {
		log.Infof("pkg pair; the phone's SPS2 signature verifies")
	} else {
		// OmnipodKit logs its own mismatch and carries on, so the pod does
		// the same rather than refusing a pairing the phone thinks worked.
		log.Warnf("pkg pair; the phone's SPS2 signature does NOT verify over %d bytes", len(transcript))
	}
	return nil
}

// GenerateSPS2 shows the pod's certificate and signs the exchange.
func (c *O5) GenerateSPS2() (*message.Message, error) {
	signature, err := signP256(c.identity, c.podTranscript())
	if err != nil {
		return nil, err
	}
	plain := append(append([]byte(nil), c.certDER...), signature...)
	sealed, err := c.nonces.seal(c.conf, spsPodToPhone, plain)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt SPS2: %w", err)
	}
	return c.pairMessage(o5sps2, sealed)
}

// ParseSP0GP0 reads the message that ends the exchange.
func (c *O5) ParseSP0GP0(msg *message.Message) error {
	if string(msg.Payload) != o5sp0gp0 {
		return fmt.Errorf("expected SP0,GP0, got %x", msg.Payload)
	}
	return nil
}

// GenerateP0 sends the fixed byte the phone waits for last.
func (c *O5) GenerateP0() (*message.Message, error) {
	return c.pairMessage(o5p0, []byte{0xa5})
}

// pairMessage wraps a pairing payload under its key, from the pod to the
// phone.
func (c *O5) pairMessage(key string, payload []byte) (*message.Message, error) {
	msg := message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
	body, err := buildStringByte([]string{key}, map[string][]byte{key: payload})
	if err != nil {
		return nil, err
	}
	msg.Payload = body
	return msg, nil
}

// SPS0 is five bytes: 00, who is writing (01 the phone, 00 the pod), the
// algorithm 09, and the CRC-16/XMODEM of those three
// (O5LTKExchanger.o5sps0 and validatePodO5sps0).
func sps0Payload(fromPhone bool) []byte {
	direction := byte(0)
	if fromPhone {
		direction = 1
	}
	header := []byte{0x00, direction, 0x09}
	sum := crc.XMODEM(header)
	return append(header, byte(sum>>8), byte(sum))
}

func checkSPS0(payload []byte, fromPhone bool) error {
	want := sps0Payload(fromPhone)
	if !bytes.Equal(payload, want) {
		return fmt.Errorf("SPS0 is %x, want %x", payload, want)
	}
	return nil
}

// deriveKeys hashes the exchange into the conf key and the LTK. Each field
// goes in behind its length as a 64-bit big-endian number
// (O5KeyExchange.o5generateKeys).
func deriveKeys(pdmPublic, podPublic, shared []byte) (conf, ltk []byte, err error) {
	if len(pdmPublic) != publicKeySize || len(podPublic) != publicKeySize {
		return nil, nil, fmt.Errorf("public keys are %d and %d bytes, want %d", len(pdmPublic), len(podPublic), publicKeySize)
	}
	if len(shared) != 32 {
		return nil, nil, fmt.Errorf("the shared secret is %d bytes, want 32", len(shared))
	}
	var buf bytes.Buffer
	field := func(b []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(b)))
		buf.Write(length[:])
		buf.Write(b)
	}
	field(firmwareID)
	field([]byte{0, 0, 0, 0})
	field(pdmPublic)
	field(podPublic)
	field(shared)

	sum := sha256.Sum256(buf.Bytes())
	return append([]byte(nil), sum[:16]...), append([]byte(nil), sum[16:]...), nil
}

// phoneTranscript is what the phone signs in SPS2
// (O5KeyExchange.buildChannelBindingTranscript).
func (c *O5) phoneTranscript() []byte {
	out := make([]byte, 0, transcriptLen)
	out = append(out, 0x01)
	out = append(out, firmwareID...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, c.pdmPublic...)
	out = append(out, c.podPublic...)
	out = append(out, c.nonces.pdm...)
	out = append(out, c.nonces.pod...)
	return out
}

// podTranscript is what the pod signs in SPS2. The phone rebuilds it in
// buildPodChannelBindingTranscript: the two fixed fields swap places, each
// side's key and nonce swap, and the nonces are the ones the pod holds at
// this point in the exchange.
func (c *O5) podTranscript() []byte {
	out := make([]byte, 0, transcriptLen)
	out = append(out, 0x02)
	out = append(out, 0, 0, 0, 0)
	out = append(out, firmwareID...)
	out = append(out, c.podPublic...)
	out = append(out, c.pdmPublic...)
	out = append(out, c.nonces.pod...)
	out = append(out, c.nonces.pdm...)
	return out
}

// spsDirection says who is writing a message encrypted under conf.
type spsDirection byte

const (
	spsPhoneToPod spsDirection = 0x01 // OmnipodKit's Direction.write
	spsPodToPhone spsDirection = 0x02 // OmnipodKit's Direction.read
)

// spsNonces holds the two 16-byte nonces from SPS1. Each side's first
// eight bytes are a little-endian counter that goes up by one after every
// message that side writes (O5KeyExchange.getSPSNonce, incrementNonce).
type spsNonces struct {
	pdm []byte
	pod []byte
}

func newSPSNonces(pdmNonce, podNonce []byte) (*spsNonces, error) {
	if len(pdmNonce) != nonceSize || len(podNonce) != nonceSize {
		return nil, fmt.Errorf("nonces are %d and %d bytes, want %d", len(pdmNonce), len(podNonce), nonceSize)
	}
	return &spsNonces{
		pdm: append([]byte(nil), pdmNonce...),
		pod: append([]byte(nil), podNonce...),
	}, nil
}

// nonce is the 13-byte AES-CCM nonce: the direction, then six bytes of the
// writer's nonce and six of the reader's.
func (n *spsNonces) nonce(dir spsDirection) []byte {
	out := make([]byte, 0, spsNonceSize)
	out = append(out, byte(dir))
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

func spsCipher(conf, nonce []byte) (aesccm.CCM, error) {
	block, err := aes.NewCipher(conf)
	if err != nil {
		return nil, err
	}
	return aesccm.NewCCM(block, spsTagSize, len(nonce))
}

// seal encrypts a pairing payload for dir and advances that side's nonce.
// These payloads carry no associated data, unlike session messages.
func (n *spsNonces) seal(conf []byte, dir spsDirection, plaintext []byte) ([]byte, error) {
	nonce := n.nonce(dir)
	c, err := spsCipher(conf, nonce)
	if err != nil {
		return nil, err
	}
	out := c.Seal(nil, nonce, plaintext, nil)
	n.increment(dir)
	return out, nil
}

// open decrypts a pairing payload written for dir and advances that side's
// nonce.
func (n *spsNonces) open(conf []byte, dir spsDirection, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= spsTagSize {
		return nil, fmt.Errorf("%d bytes is too few to hold a tag", len(ciphertext))
	}
	nonce := n.nonce(dir)
	c, err := spsCipher(conf, nonce)
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

// signP256 signs the SHA-256 of data and returns r||s, the form CryptoKit's
// P256.Signing.ECDSASignature(rawRepresentation:) reads.
func signP256(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("could not sign: %w", err)
	}
	out := make([]byte, signatureSize)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// VerifyP256 checks an r||s signature over the SHA-256 of data against a
// raw X||Y public key.
func VerifyP256(publicKey, data, signature []byte) bool {
	if len(publicKey) != publicKeySize || len(signature) != signatureSize {
		return false
	}
	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(publicKey[:32]),
		Y:     new(big.Int).SetBytes(publicKey[32:]),
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return false
	}
	digest := sha256.Sum256(data)
	return ecdsa.Verify(key, digest[:],
		new(big.Int).SetBytes(signature[:32]),
		new(big.Int).SetBytes(signature[32:]))
}

// publicKeyFromCert reads the P-256 public key out of a DER certificate as
// raw X||Y.
func publicKeyFromCert(der []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the certificate does not carry a P-256 key")
	}
	out := make([]byte, publicKeySize)
	key.X.FillBytes(out[:32])
	key.Y.FillBytes(out[32:])
	return out, nil
}

// selfSignedCert makes the certificate a side shows during pairing. The
// phone finds the public key by looking for the standard P-256
// SubjectPublicKeyInfo bytes, which this layout gives it
// (O5CertificateStore.extractP256PublicKey).
func selfSignedCert(key *ecdsa.PrivateKey, commonName string) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"pod simulator"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: false,
	}
	return x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
}
