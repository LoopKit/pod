package pair

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/avereha/pod/pkg/message"
)

// o5Phone is the phone's side of the Omnipod 5 pairing, written from the
// order OmnipodKit's O5LTKExchanger does things in, so that a mistake
// shared with the pod's side cannot hide: it signs and encrypts from its
// own copy of the rules rather than calling the pod's code.
type o5Phone struct {
	t *testing.T

	myID  []byte
	podID []byte

	ecdhPrivate *ecdh.PrivateKey
	public      []byte
	nonce       []byte

	podPublic []byte
	podNonce  []byte

	conf []byte
	ltk  []byte

	// the phone tracks each side's nonce as a counter it advances itself
	pdmCounter []byte
	podCounter []byte

	signing *ecdsa.PrivateKey
	certDER []byte

	seq uint8
}

func newO5Phone(t *testing.T, myID, podID []byte) *o5Phone {
	t.Helper()
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := selfSignedCert(signing, "pod simulator controller")
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return &o5Phone{
		t: t, myID: myID, podID: podID,
		ecdhPrivate: ecdhKey,
		public:      ecdhKey.PublicKey().Bytes()[1:],
		nonce:       nonce,
		signing:     signing,
		certDER:     certDER,
		seq:         1,
	}
}

func (p *o5Phone) send(keys []string, payloads [][]byte) *message.Message {
	p.t.Helper()
	values := map[string][]byte{}
	for i, k := range keys {
		values[k] = payloads[i]
	}
	body, err := buildStringByte(keys, values)
	if err != nil {
		p.t.Fatal(err)
	}
	msg := message.NewMessage(message.MessageTypePairing, p.myID, []byte{0xff, 0xff, 0xff, 0xfe})
	msg.Payload = body
	msg.SequenceNumber = p.seq
	p.seq++
	return msg
}

func (p *o5Phone) read(msg *message.Message, key string) []byte {
	p.t.Helper()
	fields, err := parseStringByte([]string{key}, msg.Payload)
	if err != nil {
		p.t.Fatalf("reading %s: %v", key, err)
	}
	return fields[key]
}

// deriveFromPod is O5KeyExchange.o5updatePodPublicData plus o5generateKeys.
func (p *o5Phone) deriveFromPod(sps1 []byte) {
	p.t.Helper()
	if len(sps1) != publicKeySize+nonceSize {
		p.t.Fatalf("the pod's SPS1 is %d bytes, want %d", len(sps1), publicKeySize+nonceSize)
	}
	p.podPublic = sps1[:publicKeySize]
	p.podNonce = sps1[publicKeySize:]

	peer, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, p.podPublic...))
	if err != nil {
		p.t.Fatal(err)
	}
	shared, err := p.ecdhPrivate.ECDH(peer)
	if err != nil {
		p.t.Fatal(err)
	}

	var buf bytes.Buffer
	field := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	field(firmwareID)
	field([]byte{0, 0, 0, 0})
	field(p.public)
	field(p.podPublic)
	field(shared)
	sum := sha256.Sum256(buf.Bytes())
	p.conf, p.ltk = sum[:16], sum[16:]

	p.pdmCounter = append([]byte(nil), p.nonce...)
	p.podCounter = append([]byte(nil), p.podNonce...)
}

// writeNonce and readNonce are O5KeyExchange.getSPSNonce.
func (p *o5Phone) writeNonce() []byte {
	out := []byte{0x01}
	out = append(out, p.pdmCounter[:6]...)
	return append(out, p.podCounter[:6]...)
}

func (p *o5Phone) readNonce() []byte {
	out := []byte{0x02}
	out = append(out, p.podCounter[:6]...)
	return append(out, p.pdmCounter[:6]...)
}

func bump(counter []byte) {
	binary.LittleEndian.PutUint64(counter[:8], binary.LittleEndian.Uint64(counter[:8])+1)
}

func (p *o5Phone) seal(plaintext []byte) []byte {
	p.t.Helper()
	nonce := p.writeNonce()
	c, err := spsCipher(p.conf, nonce)
	if err != nil {
		p.t.Fatal(err)
	}
	out := c.Seal(nil, nonce, plaintext, nil)
	bump(p.pdmCounter)
	return out
}

func (p *o5Phone) open(ciphertext []byte) []byte {
	p.t.Helper()
	nonce := p.readNonce()
	c, err := spsCipher(p.conf, nonce)
	if err != nil {
		p.t.Fatal(err)
	}
	out, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		p.t.Fatalf("the pod's message did not decrypt: %v", err)
	}
	bump(p.podCounter)
	return out
}

// transcript is O5KeyExchange.buildChannelBindingTranscript.
func (p *o5Phone) transcript() []byte {
	out := []byte{0x01}
	out = append(out, firmwareID...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, p.public...)
	out = append(out, p.podPublic...)
	out = append(out, p.pdmCounter...)
	out = append(out, p.podCounter...)
	return out
}

// podTranscript is O5KeyExchange.buildPodChannelBindingTranscript: the pod
// signed with its own counter one behind where the phone's now stands.
func (p *o5Phone) podTranscript() []byte {
	adjusted := append([]byte(nil), p.podCounter...)
	binary.LittleEndian.PutUint64(adjusted[:8], binary.LittleEndian.Uint64(adjusted[:8])-1)

	out := []byte{0x02}
	out = append(out, 0, 0, 0, 0)
	out = append(out, firmwareID...)
	out = append(out, p.podPublic...)
	out = append(out, p.public...)
	out = append(out, adjusted...)
	out = append(out, p.pdmCounter...)
	return out
}

// TestO5PairingAgainstPhone runs the whole exchange and checks that both
// sides end up with the same long-term key and that each side's signature
// verifies under the other's rules.
func TestO5PairingAgainstPhone(t *testing.T) {
	myID := []byte{0x00, 0x2a, 0x1c, 0x6c}
	podID := []byte{0x00, 0x2a, 0x1c, 0x6d}

	phone := newO5Phone(t, myID, podID)
	pod, err := NewO5()
	if err != nil {
		t.Fatal(err)
	}

	// SP1 + SP2
	if err := pod.ParseSP1SP2(phone.send([]string{sp1, sp2}, [][]byte{podID, make([]byte, 11)})); err != nil {
		t.Fatalf("SP1SP2: %v", err)
	}
	if !bytes.Equal(pod.PodID(), podID) {
		t.Errorf("the pod took id %x, want %x", pod.PodID(), podID)
	}
	if !bytes.Equal(pod.PdmID(), myID) {
		t.Errorf("the pod read controller %x, want %x", pod.PdmID(), myID)
	}

	// SPS0 both ways
	if err := pod.ParseSPS0(phone.send([]string{o5sps0}, [][]byte{sps0Payload(true)})); err != nil {
		t.Fatalf("SPS0: %v", err)
	}
	podSPS0, err := pod.GenerateSPS0()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSPS0(phone.read(podSPS0, o5sps0), false); err != nil {
		t.Fatalf("the pod's SPS0: %v", err)
	}

	// SPS1 both ways, then each side derives the keys
	if err := pod.ParseSPS1(phone.send([]string{o5sps1}, [][]byte{append(append([]byte(nil), phone.public...), phone.nonce...)})); err != nil {
		t.Fatalf("SPS1: %v", err)
	}
	podSPS1, err := pod.GenerateSPS1()
	if err != nil {
		t.Fatal(err)
	}
	phone.deriveFromPod(phone.read(podSPS1, o5sps1))

	podLTK, err := pod.LTK()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(podLTK, phone.ltk) {
		t.Fatalf("long-term keys differ:\n  pod   %x\n  phone %x", podLTK, phone.ltk)
	}
	if !bytes.Equal(pod.conf, phone.conf) {
		t.Fatalf("conf keys differ:\n  pod   %x\n  phone %x", pod.conf, phone.conf)
	}

	// SPS2.1: each side shows a certificate
	if err := pod.ParseSPS21(phone.send([]string{o5sps21}, [][]byte{phone.seal(phone.certDER)})); err != nil {
		t.Fatalf("SPS2.1: %v", err)
	}
	podSPS21, err := pod.GenerateSPS21()
	if err != nil {
		t.Fatal(err)
	}
	if got := phone.open(phone.read(podSPS21, o5sps21)); len(got) == 0 {
		t.Fatal("the pod's SPS2.1 certificate was empty")
	}

	// SPS2: each side signs the exchange. The transcript has to be kept:
	// sealing the message advances the phone's nonce past it.
	phoneTranscript := phone.transcript()
	phoneSignature, err := signP256(phone.signing, phoneTranscript)
	if err != nil {
		t.Fatal(err)
	}
	sps2 := phone.seal(append(append([]byte(nil), phone.certDER...), phoneSignature...))
	if err := pod.ParseSPS2(phone.send([]string{o5sps2}, [][]byte{sps2})); err != nil {
		t.Fatalf("SPS2: %v", err)
	}
	// The pod must have accepted the phone's signature and kept its key.
	if !VerifyP256(pod.ControllerPublic(), phoneTranscript, phoneSignature) {
		t.Error("the pod did not keep a controller key that verifies the phone's signature")
	}

	podSPS2, err := pod.GenerateSPS2()
	if err != nil {
		t.Fatal(err)
	}
	plain := phone.open(phone.read(podSPS2, o5sps2))
	if len(plain) <= signatureSize {
		t.Fatalf("the pod's SPS2 is %d bytes, too few", len(plain))
	}
	podCert, podSignature := plain[:len(plain)-signatureSize], plain[len(plain)-signatureSize:]
	podKey, err := publicKeyFromCert(podCert)
	if err != nil {
		t.Fatalf("the pod's certificate: %v", err)
	}
	if !VerifyP256(podKey, phone.podTranscript(), podSignature) {
		t.Error("the pod's SPS2 signature does not verify over the transcript the phone rebuilds")
	}

	// SP0,GP0 then P0
	last := message.NewMessage(message.MessageTypePairing, myID, podID)
	last.Payload = []byte(o5sp0gp0)
	if err := pod.ParseSP0GP0(last); err != nil {
		t.Fatalf("SP0GP0: %v", err)
	}
	p0, err := pod.GenerateP0()
	if err != nil {
		t.Fatal(err)
	}
	if got := phone.read(p0, o5p0); !bytes.Equal(got, []byte{0xa5}) {
		t.Errorf("P0 is %x, want a5", got)
	}
}

// TestO5SPS0Direction checks that each side's SPS0 names itself.
func TestO5SPS0Direction(t *testing.T) {
	if err := checkSPS0(sps0Payload(true), true); err != nil {
		t.Errorf("the phone's SPS0 should pass its own check: %v", err)
	}
	if err := checkSPS0(sps0Payload(true), false); err == nil {
		t.Error("the phone's SPS0 should not pass as the pod's")
	}
}
