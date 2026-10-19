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
