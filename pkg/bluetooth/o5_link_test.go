package bluetooth

import (
	"bytes"
	"testing"
	"time"

	"github.com/avereha/pod/pkg/message"
)

// phoneWire stands for the phone at the other end of the radio: it takes
// the pod's notifications and lets a test answer them.
type phoneWire struct {
	cmd  chan Packet
	data chan Packet
}

func newPhoneWire() *phoneWire {
	return &phoneWire{cmd: make(chan Packet, 64), data: make(chan Packet, 64)}
}

func (w *phoneWire) NotifyCmd(p Packet) error {
	w.cmd <- append(Packet(nil), p...)
	return nil
}

func (w *phoneWire) NotifyData(p Packet) error {
	w.data <- append(Packet(nil), p...)
	return nil
}

func (w *phoneWire) Advertise([]byte, uint32) error   { return nil }
func (w *phoneWire) AdvertiseState(AdvertState) error { return nil }
func (w *phoneWire) Disconnect()                      {}
func (w *phoneWire) LinkMTU() int                     { return 0 }

func (w *phoneWire) nextCmd(t *testing.T) Packet {
	t.Helper()
	select {
	case p := <-w.cmd:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("the pod sent no command")
		return nil
	}
}

func (w *phoneWire) nextData(t *testing.T) Packet {
	t.Helper()
	select {
	case p := <-w.data:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("the pod sent no data")
		return nil
	}
}

// An Omnipod 5 has no RTS/CTS handshake: a message simply begins with its
// first data packet, and the side that received it answers SUCCESS on the
// command characteristic (OmnipodKit's PeripheralManager.sendMessagePacket
// and readMessagePacket, which skip RTS/CTS unless the pod is a DASH).
func TestO5LinkLayerBothWays(t *testing.T) {
	w := newPhoneWire()
	pod, err := New(func(*Ble) (Radio, error) { return w, nil }, ProfileFor(ModeO5))
	if err != nil {
		t.Fatal(err)
	}
	layout := pod.Profile().Layout
	pod.Connected()
	pod.StartMessageLoop()
	defer pod.StopMessageLoop()

	// A pairing-sized message, big enough to need several packets.
	payload := make([]byte, 700)
	for i := range payload {
		payload[i] = byte(i)
	}

	t.Run("the phone writes a message", func(t *testing.T) {
		out := message.NewMessage(message.MessageTypePairing, []byte{0, 0x2a, 0x1c, 0x6c}, []byte{0xff, 0xff, 0xff, 0xfe})
		out.Payload = payload
		raw, err := out.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range layout.Split(raw) {
			pod.DataWritten(p)
		}

		// The pod must say it has the message, without being asked first.
		if got := w.nextCmd(t); len(got) == 0 || got[0] != CmdSuccess[0] {
			t.Fatalf("the pod answered %x, want SUCCESS %x", got, CmdSuccess)
		}

		got, timedOut, _ := pod.ReadMessageWithTimeout(2 * time.Second)
		if timedOut || got == nil {
			t.Fatal("the pod did not pass the message on")
		}
		if !bytes.Equal(got.Payload, payload) {
			t.Errorf("the pod read %d bytes, want %d", len(got.Payload), len(payload))
		}
	})

	t.Run("the pod writes a message", func(t *testing.T) {
		out := message.NewMessage(message.MessageTypePairing, []byte{0xff, 0xff, 0xff, 0xfe}, []byte{0, 0x2a, 0x1c, 0x6c})
		out.Payload = payload
		pod.WriteMessage(out)

		// No RTS: the packets arrive straight away.
		first := w.nextData(t)
		joiner, err := NewJoiner(first, layout)
		if err != nil {
			t.Fatalf("the pod's first packet: %v", err)
		}
		for joiner.More() {
			if err := joiner.Accumulate(w.nextData(t)); err != nil {
				t.Fatalf("the pod's packets: %v", err)
			}
		}
		body, err := joiner.Finalize()
		if err != nil {
			t.Fatalf("the pod's message: %v", err)
		}
		back, err := message.Unmarshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(back.Payload, payload) {
			t.Errorf("the pod wrote %d bytes, want %d", len(back.Payload), len(payload))
		}

		// The phone acknowledges, and the pod's write completes.
		pod.CmdWritten(CmdSuccess)
	})
}

// A DASH still opens every exchange with RTS and waits for CTS, which is
// what the pods and OmnipodKit have always done.
func TestDashLinkLayerStillHandshakes(t *testing.T) {
	w := newPhoneWire()
	pod, err := New(func(*Ble) (Radio, error) { return w, nil }, ProfileFor(ModeDash))
	if err != nil {
		t.Fatal(err)
	}
	pod.Connected()
	pod.StartMessageLoop()
	defer pod.StopMessageLoop()

	out := message.NewMessage(message.MessageTypePairing, []byte{0xff, 0xff, 0xff, 0xfe}, []byte{0, 0x2a, 0x1c, 0x6c})
	out.Payload = []byte("hello")
	pod.WriteMessage(out)

	if got := w.nextCmd(t); len(got) == 0 || got[0] != CmdRTS[0] {
		t.Fatalf("the pod sent %x first, want RTS %x", got, CmdRTS)
	}
	pod.CmdWritten(CmdCTS)
	if got := w.nextData(t); len(got) == 0 {
		t.Fatal("the pod sent no data after CTS")
	}
	pod.CmdWritten(CmdSuccess)
}

// An Omnipod 5 reports progress with 0x08 while it works through a pairing
// message; the pod must keep waiting for SUCCESS rather than treat that as
// a failure (OmnipodKit tolerates the same from a pod).
func TestO5PairStatusIsSkipped(t *testing.T) {
	w := newPhoneWire()
	pod, err := New(func(*Ble) (Radio, error) { return w, nil }, ProfileFor(ModeO5))
	if err != nil {
		t.Fatal(err)
	}
	pod.Connected()
	pod.StartMessageLoop()
	defer pod.StopMessageLoop()

	out := message.NewMessage(message.MessageTypePairing, []byte{0xff, 0xff, 0xff, 0xfe}, []byte{0, 0x2a, 0x1c, 0x6c})
	out.Payload = []byte("hello")
	pod.WriteMessage(out)
	w.nextData(t)

	pod.CmdWritten(CmdPairStatus)
	pod.CmdWritten(CmdSuccess)

	// The write finished, so the loop takes the next message.
	out2 := message.NewMessage(message.MessageTypePairing, []byte{0xff, 0xff, 0xff, 0xfe}, []byte{0, 0x2a, 0x1c, 0x6c})
	out2.Payload = []byte("again")
	pod.WriteMessage(out2)
	if got := w.nextData(t); len(got) == 0 {
		t.Fatal("the pod did not go on to the next message")
	}
	pod.CmdWritten(CmdSuccess)
}

// A message whose packets do not add up is refused with FAIL rather than
// passed on as a command.
func TestO5DamagedMessageIsRefused(t *testing.T) {
	w := newPhoneWire()
	pod, err := New(func(*Ble) (Radio, error) { return w, nil }, ProfileFor(ModeO5))
	if err != nil {
		t.Fatal(err)
	}
	layout := pod.Profile().Layout
	pod.Connected()
	pod.StartMessageLoop()
	defer pod.StopMessageLoop()

	out := message.NewMessage(message.MessageTypePairing, []byte{0, 0x2a, 0x1c, 0x6c}, []byte{0xff, 0xff, 0xff, 0xfe})
	out.Payload = make([]byte, 700)
	raw, err := out.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	packets := layout.Split(raw)
	damaged := append(Packet(nil), packets[1]...)
	damaged[10] ^= 0xff
	packets[1] = damaged

	for _, p := range packets {
		pod.DataWritten(p)
	}
	if got := w.nextCmd(t); len(got) == 0 || got[0] != CmdFail[0] {
		t.Fatalf("the pod answered %x, want FAIL %x", got, CmdFail)
	}
}
