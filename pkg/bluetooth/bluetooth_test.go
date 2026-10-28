package bluetooth

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/avereha/pod/pkg/message"
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

func (w *wire) Advertise([]byte, uint32) error   { return nil }
func (w *wire) AdvertiseState(AdvertState) error { return nil }
func (w *wire) Disconnect()                      {}
func (w *wire) LinkMTU() int                     { return 0 }

func newEnd(t *testing.T, w *wire) *Ble {
	b, err := New(func(*Ble) (Radio, error) { return w, nil }, ProfileFor(ModeDash))
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

// mtuRadio reports a fixed ATT MTU and goes nowhere else.
type mtuRadio struct{ mtu int }

func (mtuRadio) NotifyCmd(Packet) error           { return nil }
func (mtuRadio) NotifyData(Packet) error          { return nil }
func (mtuRadio) Advertise([]byte, uint32) error   { return nil }
func (mtuRadio) AdvertiseState(AdvertState) error { return nil }
func (mtuRadio) Disconnect()                      {}
func (r mtuRadio) LinkMTU() int                   { return r.mtu }

// A phone fragments a message into packets but never fragments a packet, so
// a link that cannot carry one truncates every write silently. The pod
// refuses to pair over such a link rather than stall on the first message
// that needs more than one packet.
func TestMTUShortfall(t *testing.T) {
	for _, c := range []struct {
		name  string
		mode  Mode
		mtu   int
		short bool
	}{
		{"what a Bluetooth 4.0 adapter got from an iPhone", ModeO5, 185, true},
		{"the 23-byte ATT default", ModeO5, 23, true},
		{"exactly a packet and its header", ModeO5, 247, false},
		{"what a Pi 4's own radio got from an iPhone 11", ModeO5, 256, false},
		{"a DASH packet fits the ATT default", ModeDash, 23, false},
		{"a radio with no MTU to report", ModeO5, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			radio := mtuRadio{c.mtu}
			b, err := New(func(*Ble) (Radio, error) { return radio, nil }, ProfileFor(c.mode))
			if err != nil {
				t.Fatal(err)
			}
			err = b.MTUShortfall()
			if c.short && err == nil {
				t.Fatalf("an MTU of %d carries no %s packet, but it was accepted", c.mtu, c.mode)
			}
			if !c.short && err != nil {
				t.Fatalf("an MTU of %d was refused: %s", c.mtu, err)
			}
		})
	}
}
