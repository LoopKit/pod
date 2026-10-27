package pod

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
	"encoding/hex"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/crc"
	"github.com/avereha/pod/pkg/eap"
	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/mode"
	"github.com/avereha/pod/pkg/pair"
	"github.com/jacobsa/crypto/cmac"
	aesccm "github.com/pschlump/AesCCM"
	"github.com/wmnsk/milenage"
)

// phone is OmnipodKit's side of a pod's life: pairing (DashLTKExchanger or
// O5LTKExchanger), the EAP-AKA session (SessionEstablisher) and encrypted
// commands (BlePodMessageTransport), talking to the pod over an in-memory
// link.
type phone struct {
	t    *testing.T
	m    mode.Mode
	ble  *bluetooth.Ble
	pod  *bluetooth.Ble // the pod's end of the link
	link *radio         // the pod's radio: what it sends us and advertises

	controllerID, podID []byte
	msgSeq              uint8

	// pairing
	ltk        []byte
	signingKey *ecdsa.PrivateKey

	// session
	ck, noncePrefix []byte
	nonceSeq        uint64
}

var (
	testController = []byte{0x00, 0x2a, 0x1c, 0x6c}
	testPodID      = []byte{0x00, 0x2a, 0x1c, 0x6d}
	unpaired       = []byte{0xff, 0xff, 0xff, 0xfe}
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// startPod brings up a pod of mode m and a phone connected to it, with the
// phone's HELLO already written.
func startPod(t *testing.T, m mode.Mode) (*Pod, *phone) {
	toPhone, toPod := &radio{hungUp: make(chan bool, 1), advertised: make(chan []byte, 4)}, &radio{}
	podBle, err := bluetooth.New(m, func(*bluetooth.Ble) (bluetooth.Radio, error) { return toPhone, nil })
	if err != nil {
		t.Fatal(err)
	}
	phoneBle, err := bluetooth.New(m, func(*bluetooth.Ble) (bluetooth.Radio, error) { return toPod, nil })
	if err != nil {
		t.Fatal(err)
	}
	toPod.peer, toPhone.peer = podBle, phoneBle

	state := NewFreshState(filepath.Join(t.TempDir(), "state.toml"), m)
	p := New(podBle, state)
	// The pod saves state.toml once it reads the phone's ACK, which can be
	// after the test has its response; it holds its lock until then.
	// Cleanups run last-registered first, so this one waits out that save
	// before t.TempDir's removes the directory. It gives up after 3 s, as a
	// test that failed mid-exchange can leave the pod waiting for an ACK.
	t.Cleanup(func() {
		idle := make(chan bool)
		go func() {
			p.mtx.Lock()
			p.mtx.Unlock()
			close(idle)
		}()
		select {
		case <-idle:
		case <-time.After(3 * time.Second):
		}
	})
	podBle.Connected()
	go p.StartAcceptingCommands()
	podBle.CmdWritten(append(bluetooth.Packet{6, 1, 4}, testController...))
	phoneBle.Connected()
	phoneBle.StartMessageLoop()

	ph := &phone{t: t, m: m, ble: phoneBle, pod: podBle, link: toPhone, controllerID: testController, podID: testPodID, msgSeq: 1}
	ph.signingKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return p, ph
}

func (ph *phone) read() *message.Message {
	ph.t.Helper()
	msg, timedOut, _ := ph.ble.ReadMessageWithTimeout(3 * time.Second)
	if timedOut || msg == nil {
		ph.t.Fatal("the pod did not answer")
	}
	return msg
}

func slpe(keys []string, payloads [][]byte) []byte {
	var out []byte
	for i, k := range keys {
		out = append(out, k...)
		if len(payloads[i]) > 0 {
			out = append(out, byte(len(payloads[i])>>8), byte(len(payloads[i])))
			out = append(out, payloads[i]...)
		}
	}
	return out
}

func (ph *phone) unslpe(key string, payload []byte) []byte {
	ph.t.Helper()
	if !bytes.HasPrefix(payload, []byte(key)) {
		ph.t.Fatalf("expected %q, got %q", key, payload)
	}
	rest := payload[len(key):]
	n := int(rest[0])<<8 | int(rest[1])
	return rest[2 : 2+n]
}

func (ph *phone) pairMessage(keys []string, payloads [][]byte) {
	m := message.NewMessage(message.MessageTypePairing, ph.controllerID, unpaired)
	m.Payload = slpe(keys, payloads)
	m.SequenceNumber = ph.msgSeq
	m.Sas = true
	ph.msgSeq++
	ph.ble.WriteMessage(m)
}

func (ph *phone) sp1sp2() {
	// SP2 is a GetStatus command for the new id, with its CRC.
	cmd := append(append([]byte{}, ph.podID...), 0x08, 0x03, 0x0e, 0x01, 0x00)
	cmd = append(cmd, crc.CRC16(cmd)...)
	ph.pairMessage([]string{"SP1=", ",SP2="}, [][]byte{ph.podID, cmd})
}

func (ph *phone) finishPairing() {
	ph.pairMessage([]string{"SP0,GP0"}, [][]byte{nil})
	if got := ph.unslpe("P0=", ph.read().Payload); !bytes.Equal(got, []byte{0xa5}) {
		ph.t.Fatalf("P0 %x", got)
	}
}

func (ph *phone) pairDash() {
	private := make([]byte, 32)
	rand.Read(private)
	public, _ := curve25519.X25519(private, curve25519.Basepoint)
	nonce := make([]byte, 16)
	rand.Read(nonce)

	ph.sp1sp2()
	ph.pairMessage([]string{"SPS1="}, [][]byte{append(append([]byte{}, public...), nonce...)})
	podSPS1 := ph.unslpe("SPS1=", ph.read().Payload)
	podPublic, podNonce := podSPS1[:32], podSPS1[32:]

	mac := func(key, data []byte) []byte {
		h, _ := cmac.New(key)
		h.Write(data)
		return h.Sum(nil)
	}
	shared, _ := curve25519.X25519(private, podPublic)
	first := append(append(append(append([]byte{}, podPublic[28:]...), public[28:]...), podNonce[12:]...), nonce[12:]...)
	intermediate := mac(first, shared)
	ph.ltk = mac(intermediate, append(append(append(append([]byte{0x02}, "TWIt"...), podNonce...), nonce...), 0, 1))
	confKey := mac(intermediate, append(append(append(append([]byte{0x01}, "TWIt"...), podNonce...), nonce...), 0, 1))
	pdmConf := mac(confKey, append(append([]byte("KC_2_U"), nonce...), podNonce...))
	podConf := mac(confKey, append(append([]byte("KC_2_V"), podNonce...), nonce...))

	ph.pairMessage([]string{"SPS2="}, [][]byte{pdmConf})
	if got := ph.unslpe("SPS2=", ph.read().Payload); !bytes.Equal(got, podConf) {
		ph.t.Fatalf("pod conf %x, want %x", got, podConf)
	}
	ph.finishPairing()
}

func selfSignedCert(t *testing.T, key *ecdsa.PrivateKey) []byte {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "phone"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func rawSignature(t *testing.T, key *ecdsa.PrivateKey, data []byte) []byte {
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

func (ph *phone) pairO5() {
	t := ph.t
	private, _ := ecdh.P256().GenerateKey(rand.Reader)
	public := private.PublicKey().Bytes()[1:]
	pdmNonce := make([]byte, 16)
	rand.Read(pdmNonce)

	ph.sp1sp2()
	ph.pairMessage([]string{"SPS0="}, [][]byte{{0x00, 0x01, 0x09, 0xa2, 0x18}})
	if got := ph.unslpe("SPS0=", ph.read().Payload); !bytes.Equal(got, []byte{0x00, 0x00, 0x09, 0x91, 0x29}) {
		t.Fatalf("pod SPS0 %x", got)
	}
	ph.pairMessage([]string{"SPS1="}, [][]byte{append(append([]byte{}, public...), pdmNonce...)})
	podSPS1 := ph.unslpe("SPS1=", ph.read().Payload)
	podPublic, podNonce := podSPS1[:64], append([]byte{}, podSPS1[64:]...)

	podPub, _ := ecdh.P256().NewPublicKey(append([]byte{0x04}, podPublic...))
	secret, _ := private.ECDH(podPub)
	var kdf []byte
	add := func(b []byte) {
		kdf = binary.BigEndian.AppendUint64(kdf, uint64(len(b)))
		kdf = append(kdf, b...)
	}
	add(pair.FirmwareID)
	add([]byte{0, 0, 0, 0})
	add(public)
	add(podPublic)
	add(secret)
	sum := sha256.Sum256(kdf)
	conf, ltk := sum[:16], sum[16:]
	ph.ltk = ltk

	block, _ := aes.NewCipher(conf)
	ccm, _ := aesccm.NewCCM(block, 8, 13)
	bump := func(n []byte, by int64) {
		binary.LittleEndian.PutUint64(n[:8], uint64(int64(binary.LittleEndian.Uint64(n[:8]))+by))
	}
	seal := func(plain []byte) []byte {
		nonce := append(append([]byte{0x01}, pdmNonce[:6]...), podNonce[:6]...)
		out := ccm.Seal(nil, nonce, plain, nil)
		bump(pdmNonce, 1)
		return out
	}
	open := func(ct []byte) []byte {
		nonce := append(append([]byte{0x02}, podNonce[:6]...), pdmNonce[:6]...)
		out, err := ccm.Open(nil, nonce, ct, nil)
		if err != nil {
			t.Fatalf("decrypting the pod's pairing message: %v", err)
		}
		bump(podNonce, 1)
		return out
	}

	intermediate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ph.pairMessage([]string{"SPS2.1="}, [][]byte{seal(selfSignedCert(t, intermediate))})
	podCert := open(ph.unslpe("SPS2.1=", ph.read().Payload))

	transcript := append(append([]byte{0x01}, pair.FirmwareID...), 0, 0, 0, 0)
	transcript = append(append(transcript, public...), podPublic...)
	transcript = append(append(transcript, pdmNonce...), podNonce...)
	sps2 := append(selfSignedCert(t, ph.signingKey), rawSignature(t, ph.signingKey, transcript)...)
	ph.pairMessage([]string{"SPS2="}, [][]byte{seal(sps2)})
	plain := open(ph.unslpe("SPS2=", ph.read().Payload))
	cert, sig := plain[:len(plain)-64], plain[len(plain)-64:]
	if !bytes.Equal(cert, podCert) {
		t.Fatal("the pod sent different certificates in SPS2.1 and SPS2")
	}
	podKey, err := pair.PublicKeyFromCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	adjusted := append([]byte{}, podNonce...)
	bump(adjusted, -1)
	podTranscript := append(append([]byte{0x02}, 0, 0, 0, 0), pair.FirmwareID...)
	podTranscript = append(append(podTranscript, podPublic...), public...)
	podTranscript = append(append(podTranscript, adjusted...), pdmNonce...)
	digest := sha256.Sum256(podTranscript)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(podKey[:32]), Y: new(big.Int).SetBytes(podKey[32:])}
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the pod's SPS2 signature does not verify")
	}
	ph.finishPairing()
}

func (ph *phone) pair() {
	if ph.m.IsO5() {
		ph.pairO5()
	} else {
		ph.pairDash()
	}
}

// session is SessionEstablisher.negotiateSessionKeysPrimary: the phone's
// challenge, the pod's RES and IV, the phone's EAP-Success.
func (ph *phone) session(sqn uint64) {
	t := ph.t
	op := unhex("cdc202d5123e20f62b6d676ac72cb318")
	rnd := make([]byte, 16)
	rand.Read(rnd)
	iv := make([]byte, 4)
	rand.Read(iv)
	mil := milenage.New(ph.ltk, op, rnd, sqn, 0xb9b9)
	res, ck, _, ak, err := mil.F2345()
	if err != nil {
		t.Fatal(err)
	}
	maca, err := mil.F1()
	if err != nil {
		t.Fatal(err)
	}
	var sqnBytes [8]byte
	binary.BigEndian.PutUint64(sqnBytes[:], sqn)
	autn := make([]byte, 0, 16)
	for i := 0; i < 6; i++ {
		autn = append(autn, sqnBytes[2+i]^ak[i])
	}
	autn = append(autn, 0xb9, 0xb9)
	autn = append(autn, maca...)

	challenge := &eap.EapAka{Code: eap.CodeRequest, Identifier: 0x11, SubType: eap.SubTypeAkaChallenge, Attributes: map[eap.AttributeType]*eap.Attribute{
		eap.AT_RAND: {Data: rnd}, eap.AT_AUTN: {Data: autn}, eap.AT_CUSTOM_IV: {Data: iv},
	}}
	m := message.NewMessage(message.MessageTypeSessionEstablishment, ph.controllerID, ph.podID)
	m.Payload, _ = challenge.Marshal()
	m.SequenceNumber = ph.msgSeq
	ph.msgSeq++
	ph.ble.WriteMessage(m)

	reply, err := eap.Unmarshal(ph.read().Payload)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != eap.CodeResponse || !bytes.Equal(reply.Attributes[eap.AT_RES].Data, res) {
		t.Fatalf("EAP response %+v, want RES %x", reply, res)
	}
	success := &eap.EapAka{Code: eap.CodeSuccess, Identifier: 0x11}
	m = message.NewMessage(message.MessageTypeSessionEstablishment, ph.controllerID, ph.podID)
	m.Payload, _ = success.Marshal()
	m.SequenceNumber = ph.msgSeq
	ph.msgSeq++
	ph.ble.WriteMessage(m)

	ph.ck = ck
	ph.noncePrefix = append(append([]byte{}, iv...), reply.Attributes[eap.AT_CUSTOM_IV].Data...)
	ph.nonceSeq = 0
}

func sessionNonce(prefix []byte, seq uint64, podReceiving bool) []byte {
	seq &= 0x7fffffffff
	b := []byte{byte(seq >> 32), byte(seq >> 24), byte(seq >> 16), byte(seq >> 8), byte(seq)}
	if podReceiving {
		b[0] &= 0x7f
	} else {
		b[0] |= 0x80
	}
	return append(append([]byte{}, prefix...), b...)
}

func (ph *phone) sessionCCM() aesccm.CCM {
	block, _ := aes.NewCipher(ph.ck)
	c, _ := aesccm.NewCCM(block, 8, 13)
	return c
}

// encrypt builds the phone's encrypted message, signed when the command
// must be (BlePodMessageTransport.getCmdMessage).
func (ph *phone) encrypt(plain []byte, signed bool, ack bool, ackNumber uint8) *message.Message {
	typ := message.MessageTypeEncrypted
	if signed {
		typ = message.MessageTypeEncryptedSigned
	}
	m := message.NewMessage(typ, ph.controllerID, ph.podID)
	m.Payload = plain
	m.SequenceNumber = ph.msgSeq
	ph.msgSeq++
	if ack {
		m.Ack, m.AckNumber = true, ackNumber
	} else {
		m.Eqos = 1
	}
	raw, _ := m.Marshal()
	header := raw[:16]
	ph.nonceSeq++
	ct := ph.sessionCCM().Seal(nil, sessionNonce(ph.noncePrefix, ph.nonceSeq, true), plain, header)
	full := append(append([]byte{}, header...), ct...)
	if signed {
		full = append(full, rawSignature(ph.t, ph.signingKey, full)...)
	}
	out, err := message.Unmarshal(full)
	if err != nil {
		ph.t.Fatal(err)
	}
	return out
}

func (ph *phone) decrypt(msg *message.Message) []byte {
	ph.nonceSeq++
	plain, err := ph.sessionCCM().Open(nil, sessionNonce(ph.noncePrefix, ph.nonceSeq, false), msg.Payload, msg.Raw[:16])
	if err != nil {
		ph.t.Fatalf("decrypting the pod's response: %v", err)
	}
	return plain
}

// exchange sends plain, reads the pod's reply and acknowledges it, as
// BlePodMessageTransport does for commands and AID commands alike.
func (ph *phone) exchange(plain []byte, signed bool) []byte {
	ph.ble.WriteMessage(ph.encrypt(plain, signed, false, 0))
	reply := ph.read()
	decrypted := ph.decrypt(reply)
	ph.ble.WriteMessage(ph.encrypt(nil, false, true, reply.SequenceNumber+1))
	return decrypted
}

// omnipodMessage is an Omnipod command message: address, sequence and
// length, the blocks, the CRC16.
func omnipodMessage(address []byte, seq uint8, blocks []byte) []byte {
	out := append([]byte{}, address...)
	out = append(out, (seq&0xf)<<2|byte(len(blocks)>>8), byte(len(blocks)))
	out = append(out, blocks...)
	return append(out, crc.CRC16(out)...)
}

// command sends an Omnipod command and returns the response's blocks,
// after checking its framing and, on an Omnipod 5, its CRC16.
func (ph *phone) command(address []byte, seq uint8, blocks []byte, signed bool) []byte {
	t := ph.t
	plain := slpe([]string{"S0.0=", ",G0.0"}, [][]byte{omnipodMessage(address, seq, blocks), nil})
	body := ph.unslpe("0.0=", ph.exchange(plain, signed))
	if len(body) < 8 {
		t.Fatalf("response %x too short", body)
	}
	if ph.m.IsO5() {
		if got, want := binary.BigEndian.Uint16(body[len(body)-2:]), crc.CRC16Value(body[:len(body)-2]); got != want {
			t.Fatalf("response CRC %04x, want %04x", got, want)
		}
	} else if !bytes.Equal(body[len(body)-2:], []byte{0, 0}) {
		t.Fatalf("a DASH response with a CRC: %x", body)
	}
	if got := (body[4] >> 2) & 0xf; got != (seq+1)&0xf {
		t.Fatalf("response sequence %d, want %d", got, (seq+1)&0xf)
	}
	return body[6 : len(body)-2]
}

// bolusBlocks is SetInsulinSchedule for a 1 U bolus and the BolusExtra
// block, in the DASH shape or the Omnipod 5 shape with its bolus info.
func (ph *phone) bolusBlocks() []byte {
	schedule := unhex("1a0e" + "12345678" + "02" + "0028" + "01" + "0014" + "0014" + "0014")
	extra := unhex("170d7c001400030d4000000000000000")
	if ph.m.IsO5() {
		extra = unhex("17120000c800030d400000000000000100c80000")
	}
	return append(schedule, extra...)
}

// waitStatus waits for the pod to finish the last exchange: its status
// snapshot is taken once the phone's ACK is read.
func waitStatus(t *testing.T, p *Pod, ready func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := p.Status()
		if ready(s) || time.Now().After(deadline) {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (ph *phone) hello() {
	ph.pod.CmdWritten(append(bluetooth.Packet{6, 1, 4}, ph.controllerID...))
}

// A phone pairs, opens a session and runs a pod: AssignAddress, the Omnipod
// 5 setup commands, SetupPod, a status read and a bolus. On an Omnipod 5 the
// bolus must be signed.
func TestAPhonePairsAndRunsThePod(t *testing.T) {
	for _, m := range []mode.Mode{mode.Dash, mode.O5} {
		t.Run(string(m), func(t *testing.T) {
			p, ph := startPod(t, m)
			ph.pair()
			ph.session(2)

			// AssignAddress (0x07) with the unpaired address.
			ph.msgSeq = 10
			blocks := ph.command(unhex("ffffffff"), 0, unhex("0704ffffffff"), false)
			if blocks[0] != 0x01 || blocks[1] != 0x15 || blocks[8] != m.ProductID() || blocks[9] != 0x02 {
				t.Fatalf("AssignAddress answered %x", blocks)
			}

			if m.IsO5() {
				// The AID setup, plain text in the same encrypted stream.
				for _, tc := range []struct{ send, want string }{
					{"53453235352e323d31373830323134373932", "45533235352e323d30"},   // UTC → ES255.2=0
					{"53332e323d0003000e002c47332e32", "332e323d0003000e00"},         // TDI → 3.2=<echo>
					{"53332e393d382c47332e39", "332e393d38"},                         // DIA → 3.9=8
					{"53332e373d333637303031352c47332e37", "332e373d33363730303135"}, // EGV → 3.7=<echo>
				} {
					if got := ph.exchange(unhex(tc.send), false); !bytes.Equal(got, unhex(tc.want)) {
						t.Fatalf("AID %x answered %q", tc.send, got)
					}
				}
				history := append(unhex("5345322e313d00a8"), make([]byte, 168)...)
				if got := ph.exchange(history, false); string(got) != "ES2.1=0" {
					t.Fatalf("insulin history answered %q", got)
				}
			}

			// SetupPod (0x03) names the pod; its response carries the id.
			setup := append(unhex("0313"), ph.podID...)
			setup = append(setup, make([]byte, 15)...)
			blocks = ph.command(unhex("ffffffff"), 1, setup, false)
			if blocks[0] != 0x01 || blocks[1] != 0x1b || blocks[15] != m.ProductID() || blocks[16] != 0x03 || !bytes.Equal(blocks[25:29], ph.podID) {
				t.Fatalf("SetupPod answered %x", blocks)
			}
			// A paired pod advertises its new id: its own on DASH, the
			// phone's on an Omnipod 5.
			select {
			case id := <-ph.link.advertised:
				want := ph.podID
				if m.IsO5() {
					want = ph.controllerID
				}
				if !bytes.Equal(id, want) {
					t.Fatalf("advertising %x after pairing, want %x", id, want)
				}
			case <-time.After(time.Second):
				t.Fatal("the pod did not advertise its new id")
			}

			// GetStatus (0x0e) answers with a status.
			blocks = ph.command(ph.podID, 2, unhex("0e0100"), false)
			if blocks[0] != 0x1d || blocks[1]&0xf != 0x03 {
				t.Fatalf("GetStatus answered %x", blocks)
			}

			if m.IsO5() {
				// An unsigned bolus is refused with 0x2A and does not run.
				blocks = ph.command(ph.podID, 3, ph.bolusBlocks(), false)
				if !bytes.Equal(blocks, []byte{0x06, 0x03, 0x2a, 0x00, 0x03}) {
					t.Fatalf("an unsigned bolus answered %x", blocks)
				}
				if s := waitStatus(t, p, func(s Status) bool { return s.BadSignatures == 1 }); s.BolusActive || s.BadSignatures != 1 {
					t.Fatalf("after an unsigned bolus: %+v", s)
				}
			}
			// A (signed, on an Omnipod 5) bolus runs: 20 pulses, prime progress.
			blocks = ph.command(ph.podID, 4, ph.bolusBlocks(), m.IsO5())
			if blocks[0] != 0x1d || blocks[1]&0xf != 0x04 || blocks[1]>>4&0x4 == 0 {
				t.Fatalf("the bolus answered %x", blocks)
			}
			s := waitStatus(t, p, func(s Status) bool { return s.BolusActive })
			if !s.BolusActive || s.Mode != string(m) || (m.IsO5() && s.BadSignatures != 1) || (!m.IsO5() && s.BadSignatures != 0) {
				t.Fatalf("status %+v", s)
			}
		})
	}
}

// A pod that has paired re-establishes a session on a new connection and
// takes commands again.
func TestAPairedPodTakesANewSession(t *testing.T) {
	p, ph := startPod(t, mode.O5)
	ph.pair()
	ph.session(2)
	ph.msgSeq = 10
	ph.command(unhex("ffffffff"), 0, unhex("0704ffffffff"), false)
	if s := waitStatus(t, p, func(s Status) bool { return s.Progress == 2 }); s.Progress != 2 {
		t.Fatalf("after AssignAddress: %+v", s)
	}

	// The phone reconnects: HELLO, then a new EAP-AKA exchange.
	ph.pod.Connected()
	ph.hello()
	ph.ble.Connected()
	ph.ble.StartMessageLoop()
	ph.session(3)
	ph.msgSeq = 20
	blocks := ph.command(unhex("ffffffff"), 1, unhex("0704ffffffff"), false)
	if blocks[0] != 0x01 || blocks[1] != 0x15 {
		t.Fatalf("after reconnecting, AssignAddress answered %x", blocks)
	}
}
