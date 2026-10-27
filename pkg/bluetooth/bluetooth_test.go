package bluetooth

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/mode"
)

// wire delivers one side's notifications as the other side's writes, or
// drops them while it has no peer.
type wire struct {
	mu   sync.Mutex
	peer *Ble
}

func (w *wire) to() *Ble {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.peer
}

func (w *wire) NotifyCmd(p Packet) error {
	if b := w.to(); b != nil {
		b.CmdWritten(p)
	}
	return nil
}

func (w *wire) NotifyData(p Packet) error {
	if b := w.to(); b != nil {
		b.DataWritten(p)
	}
	return nil
}

func (w *wire) Advertise([]byte) error           { return nil }
func (w *wire) AdvertiseState(AdvertState) error { return nil }
func (w *wire) Disconnect()                      {}

func newEnd(t *testing.T, w *wire) *Ble {
	b, err := New(mode.Dash, func(*Ble) (Radio, error) { return w, nil })
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The pod waits for a phone's first command before the phone connects.
func TestReadCmdFollowsANewConnection(t *testing.T) {
	pod := newEnd(t, &wire{})
	got := make(chan Packet, 1)
	go func() {
		p, _ := pod.ReadCmd()
		got <- p
	}()
	time.Sleep(50 * time.Millisecond)
	pod.Connected()
	pod.CmdWritten(CmdRTS)
	select {
	case p := <-got:
		if !bytes.Equal(p, CmdRTS) {
			t.Fatalf("read %x", p)
		}
	case <-time.After(time.Second):
		t.Fatal("the first command of a new connection went unread")
	}
}

// A message the phone abandoned when its connection ended leaves no part of
// itself in the pod's reading of the next connection's messages.
func TestANewConnectionReadsOnlyItsOwnPackets(t *testing.T) {
	toPhone, toPod := &wire{}, &wire{}
	pod, phone := newEnd(t, toPhone), newEnd(t, toPod)
	toPod.peer = pod

	// The phone starts a message, the pod clears it to send, and the
	// connection ends with one packet of it written.
	pod.Connected()
	pod.StartMessageLoop()
	pod.CmdWritten(CmdRTS)
	time.Sleep(50 * time.Millisecond)
	pod.DataWritten(append(Packet{0, 3, 0x54, 0x57, 0x10, 0x02}, make([]byte, 14)...))
	time.Sleep(50 * time.Millisecond)

	pod.Connected()
	pod.StartMessageLoop()
	toPhone.mu.Lock()
	toPhone.peer = phone
	toPhone.mu.Unlock()
	phone.Connected()
	phone.StartMessageLoop()

	sent := message.NewMessage(message.MessageTypeClear, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	sent.Payload = bytes.Repeat([]byte{0xA5}, 40)
	phone.WriteMessage(sent)
	got, timedOut, _ := pod.ReadMessageWithTimeout(2 * time.Second)
	if timedOut {
		t.Fatal("the pod did not read the new connection's message")
	}
	if !bytes.Equal(got.Payload, sent.Payload) {
		t.Fatalf("read payload % x, want % x", got.Payload, sent.Payload)
	}
}

// An Omnipod 5 phone writes its packets without RTS/CTS and acknowledges
// the pod's with SUCCESS, as the pod does its (OmnipodKit
// PeripheralManager+OmnipodKit.swift sendMessagePacket/readMessagePacket).
func TestO5MessagesNeedNoRTS(t *testing.T) {
	toPhone, toPod := &wire{}, &wire{}
	pod, err := New(mode.O5, func(*Ble) (Radio, error) { return toPhone, nil })
	if err != nil {
		t.Fatal(err)
	}
	toPod.peer = pod
	pod.Connected()
	pod.StartMessageLoop()

	// A phone that writes the data packets of a 651-byte message straight
	// away, as OmnipodKit's does for an Omnipod 5.
	phoneCmds := make(chan Packet, 8)
	phoneData := make(chan Packet, 8)
	toPhone.mu.Lock()
	toPhone.peer = &Ble{in: &input{cmd: phoneCmds, data: phoneData, closed: make(chan bool)}}
	toPhone.mu.Unlock()

	sent := message.NewMessage(message.MessageTypePairing, []byte{1, 2, 3, 4}, []byte{0xff, 0xff, 0xff, 0xfe})
	sent.Payload = bytes.Repeat([]byte{0x5a}, 651)
	raw, _ := sent.Marshal()
	for _, p := range O5Layout.Split(raw) {
		pod.DataWritten(p)
	}
	got, timedOut, _ := pod.ReadMessageWithTimeout(2 * time.Second)
	if timedOut {
		t.Fatal("the pod did not read the message")
	}
	if !bytes.Equal(got.Payload, sent.Payload) {
		t.Fatalf("read payload % x", got.Payload)
	}
	select {
	case c := <-phoneCmds:
		if !bytes.Equal(c, CmdSuccess) {
			t.Fatalf("the pod answered %x, want SUCCESS", c)
		}
	case <-time.After(time.Second):
		t.Fatal("the pod sent no SUCCESS")
	}

	// The pod's own message goes out as data packets with no RTS first.
	reply := message.NewMessage(message.MessageTypePairing, []byte{0xff, 0xff, 0xff, 0xfe}, []byte{1, 2, 3, 4})
	reply.Payload = bytes.Repeat([]byte{0xa5}, 300)
	pod.WriteMessage(reply)
	var packets []Packet
	timeout := time.After(time.Second)
	for len(packets) < 2 {
		select {
		case p := <-phoneData:
			packets = append(packets, p)
		case c := <-phoneCmds:
			t.Fatalf("the pod wrote command %x before its data", c)
		case <-timeout:
			t.Fatal("the pod wrote no data")
		}
	}
	rest := packets[1:]
	joined, err := O5Layout.Join(packets[0], func() (Packet, error) {
		if len(rest) == 0 {
			select {
			case p := <-phoneData:
				return p, nil
			case <-time.After(time.Second):
				return nil, errStopped
			}
		}
		p := rest[0]
		rest = rest[1:]
		return p, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wantRaw, _ := reply.Marshal()
	if !bytes.Equal(joined, wantRaw) {
		t.Fatal("the phone read a different message")
	}
	pod.CmdWritten(CmdSuccess)
}

// A packet out of order gets a NACK naming the expected index.
func TestAnOutOfOrderPacketIsNACKed(t *testing.T) {
	toPhone := &wire{}
	pod, _ := New(mode.O5, func(*Ble) (Radio, error) { return toPhone, nil })
	phoneCmds := make(chan Packet, 8)
	toPhone.mu.Lock()
	toPhone.peer = &Ble{in: &input{cmd: phoneCmds, data: make(chan Packet, 8), closed: make(chan bool)}}
	toPhone.mu.Unlock()
	pod.Connected()
	pod.StartMessageLoop()

	msg := message.NewMessage(message.MessageTypeClear, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	msg.Payload = bytes.Repeat([]byte{1}, 500)
	raw, _ := msg.Marshal()
	packets := O5Layout.Split(raw)
	pod.DataWritten(packets[0])
	pod.DataWritten(packets[2])
	select {
	case c := <-phoneCmds:
		if !bytes.Equal(c, Packet{2, 1}) {
			t.Fatalf("the pod answered %x, want NACK 1", c)
		}
	case <-time.After(time.Second):
		t.Fatal("no NACK")
	}
}
