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
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/mode"
	"github.com/jacobsa/crypto/cmac"
	aesccm "github.com/pschlump/AesCCM"
)

var (
	controllerID = []byte{0x00, 0x2a, 0x1c, 0x6c}
	podID        = []byte{0x00, 0x2a, 0x1c, 0x6e}
	unpairedID   = []byte{0xff, 0xff, 0xff, 0xfe}
)

// phone is OmnipodKit's side of an Omnipod 5 pairing, written from
// O5LTKExchanger.swift and O5KeyExchange.swift.
type phone struct {
	t *testing.T

	private   *ecdh.PrivateKey
	public    []byte // 64 bytes
	nonce     []byte // 16, counted up after each message the phone writes
	podPublic []byte
	podNonce  []byte // counted up after each message the pod writes
	conf, ltk []byte

	signingKey      *ecdsa.PrivateKey
	intermediateDER []byte
	tlsDER          []byte
	podCertDER      []byte
}

func selfSigned(t *testing.T, key *ecdsa.PrivateKey, cn string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newPhone(t *testing.T) *phone {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &phone{t: t, private: priv, public: priv.PublicKey().Bytes()[1:], nonce: make([]byte, 16), signingKey: signing}
	rand.Read(p.nonce)
	p.intermediateDER = selfSigned(t, intermediate, "INS01PG1")
	p.tlsDER = selfSigned(t, signing, "controller")
	return p
}

func (p *phone) pairMessage(keys []string, payloads [][]byte) *message.Message {
	values := map[string][]byte{}
	for i, k := range keys {
		values[k] = payloads[i]
	}
	m := message.NewMessage(message.MessageTypePairing, controllerID, unpairedID)
	m.Payload, _ = buildStringByte(keys, values)
	m.Sas = true
	return m
}

func (p *phone) field(t *testing.T, m *message.Message, key string) []byte {
	t.Helper()
	sp, err := parseStringByte([]string{key}, m.Payload)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return sp[key]
}

func (p *phone) spsNonce(write bool) []byte {
	if write {
		return append(append([]byte{0x01}, p.nonce[:6]...), p.podNonce[:6]...)
	}
	return append(append([]byte{0x02}, p.podNonce[:6]...), p.nonce[:6]...)
}

func bump(nonce []byte, by int64) {
	v := binary.LittleEndian.Uint64(nonce[:8])
	binary.LittleEndian.PutUint64(nonce[:8], uint64(int64(v)+by))
}

func (p *phone) ccm(nonce []byte) aesccm.CCM {
	block, _ := aes.NewCipher(p.conf)
	c, _ := aesccm.NewCCM(block, 8, 13)
	return c
}

func (p *phone) encrypt(plaintext []byte) []byte {
	nonce := p.spsNonce(true)
	out := p.ccm(nonce).Seal(nil, nonce, plaintext, nil)
	bump(p.nonce, 1)
	return out
}

func (p *phone) decrypt(ciphertext []byte) []byte {
	nonce := p.spsNonce(false)
	out, err := p.ccm(nonce).Open(nil, nonce, ciphertext, nil)
	if err != nil {
		p.t.Fatalf("decrypting the pod's message: %v", err)
	}
	bump(p.podNonce, 1)
	return out
}

func (p *phone) deriveKeys(t *testing.T) {
	podPub, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, p.podPublic...))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := p.private.ECDH(podPub)
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	add := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		data = append(append(data, l[:]...), b...)
	}
	add([]byte{0x9b, 0x0a, 0xb9, 0x6a, 0x76, 0xf4})
	add([]byte{0, 0, 0, 0})
	add(p.public)
	add(p.podPublic)
	add(secret)
	if len(data) != 210 {
		t.Fatalf("KDF input is %d bytes", len(data))
	}
	sum := sha256.Sum256(data)
	p.conf, p.ltk = sum[:16], sum[16:]
}

func rawSig(t *testing.T, key *ecdsa.PrivateKey, data []byte) []byte {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	copy(out[32-len(r.Bytes()):32], r.Bytes())
	copy(out[64-len(s.Bytes()):], s.Bytes())
	return out
}

func verifySig(pubRaw, data, sig []byte) bool {
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pubRaw[:32]), Y: new(big.Int).SetBytes(pubRaw[32:])}
	digest := sha256.Sum256(data)
	return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// The whole Omnipod 5 pairing between OmnipodKit's phone and the pod, in
// the order O5LTKExchanger runs it.
func TestOmnipod5Pairing(t *testing.T) {
	ph := newPhone(t)
	pod := &Pair{Mode: mode.O5}
	identity, err := NewPodIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pod.SetIdentity(identity)

	// SP1,SP2: the pod's new id and a GetStatus command for it.
	sp2 := append(append([]byte{}, podID...), 0x08, 0x03, 0x0e, 0x01, 0x00, 0x00, 0x00)
	if err := pod.ParseSP1SP2(ph.pairMessage([]string{sp1, sp2Key}, [][]byte{podID, sp2})); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pod.ControllerID(), controllerID) || !bytes.Equal(pod.AssignedPodID(), podID) {
		t.Fatalf("controller %x, assigned %x", pod.ControllerID(), pod.AssignedPodID())
	}

	// SPS0
	if err := pod.ParseSPS0(ph.pairMessage([]string{sps0}, [][]byte{{0x00, 0x01, 0x09, 0xa2, 0x18}})); err != nil {
		t.Fatal(err)
	}
	reply, err := pod.GenerateSPS0()
	if err != nil {
		t.Fatal(err)
	}
	if got := ph.field(t, reply, sps0); !bytes.Equal(got, []byte{0x00, 0x00, 0x09, 0x91, 0x29}) {
		t.Fatalf("pod SPS0 %x", got)
	}
	if !bytes.Equal(reply.Source, unpairedID) || !bytes.Equal(reply.Destination, controllerID) {
		t.Fatalf("pod reply from %x to %x", reply.Source, reply.Destination)
	}

	// SPS1: 64-byte public keys and 16-byte nonces.
	if err := pod.ParseSPS1(ph.pairMessage([]string{sps1}, [][]byte{append(append([]byte{}, ph.public...), ph.nonce...)})); err != nil {
		t.Fatal(err)
	}
	reply, err = pod.GenerateSPS1()
	if err != nil {
		t.Fatal(err)
	}
	podSPS1 := ph.field(t, reply, sps1)
	if len(podSPS1) != 80 {
		t.Fatalf("pod SPS1 is %d bytes", len(podSPS1))
	}
	ph.podPublic, ph.podNonce = podSPS1[:64], append([]byte{}, podSPS1[64:]...)
	ph.deriveKeys(t)

	// SPS2.1: certificates only.
	if err := pod.ParseSPS21(ph.pairMessage([]string{sps21}, [][]byte{ph.encrypt(ph.intermediateDER)})); err != nil {
		t.Fatal(err)
	}
	reply, err = pod.GenerateSPS21()
	if err != nil {
		t.Fatal(err)
	}
	ph.podCertDER = ph.decrypt(ph.field(t, reply, sps21))
	if !bytes.Equal(ph.podCertDER, identity.CertDER) {
		t.Fatal("the phone read a different pod certificate from SPS2.1")
	}

	// SPS2: certificate and signature over the transcript, both ways.
	transcript := append([]byte{0x01}, FirmwareID...)
	transcript = append(transcript, 0, 0, 0, 0)
	transcript = append(append(transcript, ph.public...), ph.podPublic...)
	transcript = append(append(transcript, ph.nonce...), ph.podNonce...)
	if len(transcript) != 171 {
		t.Fatalf("transcript is %d bytes", len(transcript))
	}
	sps2Plain := append(append([]byte{}, ph.tlsDER...), rawSig(t, ph.signingKey, transcript)...)
	if err := pod.ParseSPS2(ph.pairMessage([]string{sps2}, [][]byte{ph.encrypt(sps2Plain)})); err != nil {
		t.Fatal(err)
	}
	reply, err = pod.GenerateSPS2()
	if err != nil {
		t.Fatal(err)
	}
	plain := ph.decrypt(ph.field(t, reply, sps2))
	podCert, podSig := plain[:len(plain)-64], plain[len(plain)-64:]
	if !bytes.Equal(podCert, identity.CertDER) {
		t.Fatal("the phone read a different pod certificate from SPS2")
	}
	podPub, err := PublicKeyFromCert(podCert)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(podPub, identity.PublicRaw()) {
		t.Fatal("the certificate's key is not the pod's")
	}
	// o5validatePodSps2: the pod signed before its SPS2 advanced its counter.
	adjusted := append([]byte{}, ph.podNonce...)
	bump(adjusted, -1)
	podTranscript := append([]byte{0x02}, 0, 0, 0, 0)
	podTranscript = append(podTranscript, FirmwareID...)
	podTranscript = append(append(podTranscript, ph.podPublic...), ph.public...)
	podTranscript = append(append(podTranscript, adjusted...), ph.nonce...)
	if !verifySig(podPub, podTranscript, podSig) {
		t.Fatal("the pod's SPS2 signature does not verify the way OmnipodKit checks it")
	}

	// SP0,GP0 and P0.
	m := message.NewMessage(message.MessageTypePairing, controllerID, unpairedID)
	m.Payload = []byte(sp0gp0)
	if err := pod.ParseSP0GP0(m); err != nil {
		t.Fatal(err)
	}
	reply, err = pod.GenerateP0()
	if err != nil {
		t.Fatal(err)
	}
	if got := ph.field(t, reply, p0); !bytes.Equal(got, []byte{0xa5}) {
		t.Fatalf("P0 %x", got)
	}

	ltk, err := pod.LTK()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ltk, ph.ltk) || len(ltk) != 16 {
		t.Fatalf("pod LTK %x, phone LTK %x", ltk, ph.ltk)
	}

	// The pod kept the phone's signing key for its type 4 commands.
	header := []byte("TW\x00\x04\x05\x00\x05\x00\x00\x2a\x1c\x6c\x00\x2a\x1c\x6e")
	ciphertext := bytes.Repeat([]byte{7}, 48)
	sig := rawSig(t, ph.signingKey, append(append([]byte{}, header...), ciphertext...))
	ok, err := VerifySignedMessage(pod.PDMPublicKey(), header, ciphertext, sig)
	if err != nil || !ok {
		t.Fatalf("type 4 signature: ok=%v err=%v", ok, err)
	}
	ciphertext[0] ^= 1
	if ok, _ := VerifySignedMessage(pod.PDMPublicKey(), header, ciphertext, sig); ok {
		t.Fatal("a changed ciphertext still verified")
	}
}

const sp2Key = sp2

func TestSPS0Checks(t *testing.T) {
	if err := parseSPS0([]byte{0x00, 0x01, 0x09, 0xa2, 0x18}, true); err != nil {
		t.Fatal(err)
	}
	if err := parseSPS0([]byte{0x00, 0x01, 0x09, 0xa2, 0x19}, true); err == nil {
		t.Fatal("a bad CRC passed")
	}
	if err := parseSPS0([]byte{0x00, 0x00, 0x09, 0x91, 0x29}, true); err == nil {
		t.Fatal("the pod's direction passed as the phone's")
	}
	if err := parseSPS0([]byte{0x00, 0x01, 0x09, 0xa2}, true); err == nil {
		t.Fatal("a short payload passed")
	}
}

func TestSPSNoncesCountUpLittleEndian(t *testing.T) {
	pdm := bytes.Repeat([]byte{0xff}, 16)
	podN := []byte{1, 0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9}
	n, err := newSPSNonces(pdm, podN)
	if err != nil {
		t.Fatal(err)
	}
	if got := n.nonce(spsPhoneToPod); !bytes.Equal(got, append(append([]byte{1}, pdm[:6]...), podN[:6]...)) {
		t.Fatalf("write nonce %x", got)
	}
	n.increment(spsPodToPhone)
	if !bytes.Equal(n.pod[:8], []byte{2, 0, 0, 0, 0, 0, 0, 0}) || !bytes.Equal(n.pod[8:], podN[8:]) {
		t.Fatalf("pod counter %x", n.pod)
	}
	n.increment(spsPhoneToPod)
	if !bytes.Equal(n.pdm[:8], make([]byte, 8)) || !bytes.Equal(n.pdm[8:], pdm[8:]) {
		t.Fatalf("pdm counter wrapped to %x", n.pdm)
	}
	if got := n.nonce(spsPodToPhone); got[0] != 2 || !bytes.Equal(got[1:7], n.pod[:6]) || !bytes.Equal(got[7:], n.pdm[:6]) {
		t.Fatalf("read nonce %x", got)
	}
}

func TestPodIdentityIsSavedAndRestored(t *testing.T) {
	id, err := NewPodIdentity()
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadPodIdentity(id.Private(), id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.PublicRaw(), id.PublicRaw()) {
		t.Fatal("the restored key differs")
	}
	fromCert, err := PublicKeyFromCert(id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromCert, id.PublicRaw()) {
		t.Fatal("the certificate holds another key")
	}
	if _, err := LoadPodIdentity(nil, nil); err == nil {
		t.Fatal("an empty identity loaded")
	}
}

// dashPhone is OmnipodKit's DashKeyExchange, to check the DASH pairing is
// still the same exchange.
func TestDashPairingStillMatchesOmnipodKit(t *testing.T) {
	pdmPrivate := make([]byte, 32)
	rand.Read(pdmPrivate)
	pdmPublic, _ := curve25519.X25519(pdmPrivate, curve25519.Basepoint)
	pdmNonce := make([]byte, 16)
	rand.Read(pdmNonce)

	pod := &Pair{Mode: mode.Dash}
	ph := &phone{}
	if err := pod.ParseSP1SP2(ph.pairMessage([]string{sp1, sp2}, [][]byte{podID, {0xff, 0xc3, 0x2d, 0xbd, 0x08, 0x03, 0x0e, 0x01, 0x00, 0x00, 0x8a}})); err != nil {
		t.Fatal(err)
	}
	if err := pod.ParseSPS1(ph.pairMessage([]string{sps1}, [][]byte{append(append([]byte{}, pdmPublic...), pdmNonce...)})); err != nil {
		t.Fatal(err)
	}
	reply, err := pod.GenerateSPS1()
	if err != nil {
		t.Fatal(err)
	}
	podSPS1 := ph.field(t, reply, sps1)
	podPublic, podNonce := podSPS1[:32], podSPS1[32:]

	// DashKeyExchange.generateKeys
	mac := func(key, data []byte) []byte {
		h, err := cmac.New(key)
		if err != nil {
			t.Fatal(err)
		}
		h.Write(data)
		return h.Sum(nil)
	}
	shared, _ := curve25519.X25519(pdmPrivate, podPublic)
	firstKey := append(append(append(append([]byte{}, podPublic[28:]...), pdmPublic[28:]...), podNonce[12:]...), pdmNonce[12:]...)
	intermediate := mac(firstKey, shared)
	ltkData := append(append(append([]byte{0x02}, []byte("TWIt")...), podNonce...), pdmNonce...)
	ltk := mac(intermediate, append(ltkData, 0x00, 0x01))
	confData := append(append(append([]byte{0x01}, []byte("TWIt")...), podNonce...), pdmNonce...)
	confKey := mac(intermediate, append(confData, 0x00, 0x01))
	pdmConf := mac(confKey, append(append([]byte("KC_2_U"), pdmNonce...), podNonce...))
	podConf := mac(confKey, append(append([]byte("KC_2_V"), podNonce...), pdmNonce...))

	if err := pod.ParseSPS2(ph.pairMessage([]string{sps2}, [][]byte{pdmConf})); err != nil {
		t.Fatal(err)
	}
	reply, err = pod.GenerateSPS2()
	if err != nil {
		t.Fatal(err)
	}
	if got := ph.field(t, reply, sps2); !bytes.Equal(got, podConf) {
		t.Fatalf("pod conf %x, phone expects %x", got, podConf)
	}
	got, err := pod.LTK()
	if err != nil || !bytes.Equal(got, ltk) {
		t.Fatalf("LTK %x (%v), phone %x", got, err, ltk)
	}
	if pod.PDMPublicKey() != nil {
		t.Fatal("a DASH pairing has no phone signing key")
	}
}
