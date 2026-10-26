package pod

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/eap"
	"github.com/avereha/pod/pkg/message"
	"github.com/wmnsk/milenage"
)

// radio carries one side's notifications to the other side, and records
// when the pod hangs up.
type radio struct {
	mu     sync.Mutex
	peer   *bluetooth.Ble
	hungUp chan bool
}

func (r *radio) to() *bluetooth.Ble {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peer
}

func (r *radio) NotifyCmd(p bluetooth.Packet) error {
	if b := r.to(); b != nil {
		b.CmdWritten(p)
	}
	return nil
}

func (r *radio) NotifyData(p bluetooth.Packet) error {
	if b := r.to(); b != nil {
		b.DataWritten(p)
	}
	return nil
}

func (r *radio) Advertise([]byte) error                     { return nil }
func (r *radio) AdvertiseState(bluetooth.AdvertState) error { return nil }

func (r *radio) Disconnect() {
	select {
	case r.hungUp <- true:
	default:
	}
}

func newBle(t *testing.T, r *radio) *bluetooth.Ble {
	b, err := bluetooth.New(func(*bluetooth.Ble) (bluetooth.Radio, error) { return r, nil })
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A session message the pod can't parse ends the connection, not the pod.
func TestAGarbledSessionMessageHangsUp(t *testing.T) {
	toPhone, toPod := &radio{hungUp: make(chan bool, 1)}, &radio{}
	podBle, phone := newBle(t, toPhone), newBle(t, toPod)
	toPod.peer = podBle
	toPhone.peer = phone

	state := NewFreshState(filepath.Join(t.TempDir(), "state.toml"))
	state.LTK = make([]byte, 16)
	p := New(podBle, state)

	podBle.Connected()
	go p.StartAcceptingCommands()
	podBle.CmdWritten(bluetooth.Packet{6, 1, 4})
	phone.Connected()
	phone.StartMessageLoop()

	garbled := message.NewMessage(message.MessageTypeSessionEstablishment, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	garbled.Payload = []byte{0x2b, 0x97, 0x1c, 0x90, 0xb9, 0xdc, 0x43, 0x9b}
	phone.WriteMessage(garbled)

	select {
	case <-toPhone.hungUp:
	case <-time.After(2 * time.Second):
		t.Fatal("the pod did not hang up")
	}
}

var milenageOP, _ = hex.DecodeString("cdc202d5123e20f62b6d676ac72cb318")

// challenge is the controller's EAP-AKA challenge: AUTN = SQN xor AK || AMF || MAC-A.
func challenge(t *testing.T, ltk, rand []byte, sqn uint64) *message.Message {
	m := milenage.New(ltk, milenageOP, rand, sqn, 0xb9b9)
	_, _, _, ak, err := m.F2345()
	if err != nil {
		t.Fatal(err)
	}
	mac, err := m.F1()
	if err != nil {
		t.Fatal(err)
	}
	autn := make([]byte, 0, 16)
	for i := 0; i < 6; i++ {
		autn = append(autn, m.SQN[i]^ak[i])
	}
	autn = append(append(autn, 0xb9, 0xb9), mac...)
	msg := message.NewMessage(message.MessageTypeSessionEstablishment, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	msg.Payload, err = (&eap.EapAka{Code: eap.CodeRequest, SubType: eap.SubTypeAkaChallenge,
		Attributes: map[eap.AttributeType]*eap.Attribute{
			eap.AT_RAND:      {Data: rand},
			eap.AT_AUTN:      {Data: autn},
			eap.AT_CUSTOM_IV: {Data: []byte{1, 2, 3, 4}},
		}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func readEap(t *testing.T, phone *bluetooth.Ble) *eap.EapAka {
	msg, didTimeout, _ := phone.ReadMessageWithTimeout(2 * time.Second)
	if didTimeout || msg == nil {
		t.Fatal("no answer from the pod")
	}
	e, err := eap.Unmarshal(msg.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A controller whose SQN is behind gets the pod's in AUTS, as OmnipodKit reads it, and its
// retry with the next SQN on the same connection establishes the session.
func TestAStaleSqnGetsASynchronizationFailure(t *testing.T) {
	toPhone, toPod := &radio{hungUp: make(chan bool, 1)}, &radio{}
	podBle, phone := newBle(t, toPhone), newBle(t, toPod)
	toPod.peer = podBle
	toPhone.peer = phone

	ltk := bytes.Repeat([]byte{0x5a}, 16)
	state := NewFreshState(filepath.Join(t.TempDir(), "state.toml"))
	state.LTK = ltk
	state.EapAkaSeq = 40
	p := New(podBle, state)

	podBle.Connected()
	go p.StartAcceptingCommands()
	podBle.CmdWritten(bluetooth.Packet{6, 1, 4})
	phone.Connected()
	phone.StartMessageLoop()

	rand := bytes.Repeat([]byte{0x11}, 16)
	phone.WriteMessage(challenge(t, ltk, rand, 37))
	answer := readEap(t, phone)
	if answer.SubType != eap.SubTypeAkaSynchronizationFailure || answer.Attributes[eap.AT_AUTS] == nil {
		t.Fatalf("expected a synchronization failure, got %+v", answer)
	}
	auts := answer.Attributes[eap.AT_AUTS].Data
	m := milenage.New(ltk, milenageOP, rand, 0, 0)
	aks, err := m.F5Star()
	if err != nil {
		t.Fatal(err)
	}
	sqnMs := make([]byte, 6)
	for i := range sqnMs {
		sqnMs[i] = auts[i] ^ aks[i]
	}
	if !bytes.Equal(sqnMs, []byte{0, 0, 0, 0, 0, 40}) {
		t.Fatalf("AUTS carries SQN %x, want 40", sqnMs)
	}
	macS, err := m.F1Star(sqnMs, []byte{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(macS, auts[6:]) {
		t.Fatalf("MAC-S %x, want %x", auts[6:], macS)
	}

	phone.WriteMessage(challenge(t, ltk, bytes.Repeat([]byte{0x22}, 16), 41))
	if answer = readEap(t, phone); answer.SubType != eap.SubTypeAkaChallenge || answer.Attributes[eap.AT_RES] == nil {
		t.Fatalf("expected a challenge response, got %+v", answer)
	}
	success := message.NewMessage(message.MessageTypeSessionEstablishment, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	success.Payload, _ = (&eap.EapAka{Code: eap.CodeSuccess}).Marshal()
	phone.WriteMessage(success)

	deadline := time.Now().Add(2 * time.Second)
	for {
		p.mtx.Lock()
		sqn := p.state.EapAkaSeq
		p.mtx.Unlock()
		if sqn == 41 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pod SQN %d after the session, want 41", sqn)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An AUTN whose MAC-A doesn't verify ends the connection.
func TestABadAutnHangsUp(t *testing.T) {
	toPhone, toPod := &radio{hungUp: make(chan bool, 1)}, &radio{}
	podBle, phone := newBle(t, toPhone), newBle(t, toPod)
	toPod.peer = podBle
	toPhone.peer = phone

	state := NewFreshState(filepath.Join(t.TempDir(), "state.toml"))
	state.LTK = bytes.Repeat([]byte{0x5a}, 16)
	p := New(podBle, state)

	podBle.Connected()
	go p.StartAcceptingCommands()
	podBle.CmdWritten(bluetooth.Packet{6, 1, 4})
	phone.Connected()
	phone.StartMessageLoop()

	phone.WriteMessage(challenge(t, bytes.Repeat([]byte{0x77}, 16), bytes.Repeat([]byte{0x11}, 16), 1))
	select {
	case <-toPhone.hungUp:
	case <-time.After(2 * time.Second):
		t.Fatal("the pod did not hang up")
	}
}
