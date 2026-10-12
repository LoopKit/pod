package pod

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/message"
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
