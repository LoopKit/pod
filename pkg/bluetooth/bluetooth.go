package bluetooth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/avereha/pod/pkg/message"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

type Packet []byte

var (
	CmdRTS     = Packet([]byte{0})
	CmdCTS     = Packet([]byte{1})
	CmdNACK    = Packet([]byte{2, 0})
	CmdAbort   = Packet([]byte{3})
	CmdSuccess = Packet([]byte{4})
	CmdFail    = Packet([]byte{5})
	CmdHello   = Packet([]byte{6})
	// An Omnipod 5 reports progress with this while it works through a
	// pairing message (OmnipodKit's PodCommand.PAIR_STATUS).
	CmdPairStatus = Packet([]byte{8})
)

// Radio carries the pod's command and data characteristics to the phone:
// a Bluetooth adapter, or the iOS Simulator through ImpossiBLE.
type Radio interface {
	NotifyCmd(Packet) error
	NotifyData(Packet) error
	Advertise(podId []byte, pdmId uint32) error
	AdvertiseState(state AdvertState) error
	Disconnect()
	// LinkMTU is the ATT MTU the phone negotiated, or 0 when the
	// transport has none to report.
	LinkMTU() int
}

const AdvertisedName = " :: Fake POD ::"

// AdvertState is what a paired pod advertises of its state: its fault
// code and its firing alert slots, 0 when there are none.
type AdvertState struct {
	Fault  uint8
	Alerts uint8
}

// status is the 2nd service UUID: real pods go C001 → C005 when an alert
// fires → C00A on a fault (captured in OmnipodKit). A fault is a new
// advertisement, which wakes a suspended app scanning for it.
func (s AdvertState) status() uint16 {
	switch {
	case s.Fault != 0:
		return 0xC00A
	case s.Alerts != 0:
		return 0xC005
	}
	return 0xC001
}

// ManufacturerData is the pod's iBeacon-shaped manufacturer data, with the
// status word OmnipodKit decodes 7 bytes from its end: 00, 02 (or the fault
// code), the fault code, the alert slots. A captured occlusion read 00141400.
func (s AdvertState) ManufacturerData() []byte {
	b1 := uint8(0x02)
	if s.Fault != 0 {
		b1 = s.Fault
	}
	data := []byte{0x4c, 0x00, 0x02, 0x15}
	data = append(data, make([]byte, 14)...)
	return append(data, 0x00, b1, s.Fault, s.Alerts, 0x00, 0x00, 0xc5)
}

// AdvertisedServices is the list of 16-bit service UUIDs a DASH pod
// advertises; the 4th and 5th carry its id, FFFF FFFE before pairing.
func AdvertisedServices(podId []byte, state AdvertState) []uint16 {
	idOne, idTwo, second := uint16(0xffff), uint16(0xfffe), uint16(0x2470)
	if podId != nil {
		idOne = binary.BigEndian.Uint16(podId[0:2])
		idTwo = binary.BigEndian.Uint16(podId[2:4])
		second = state.status()
	}
	return []uint16{
		0x4024,
		second,
		0x000a,
		idOne,
		idTwo,
		// these 4 are copied from lotNo and lotSeq from fixed string in versionresponse.go
		0x0814,
		0x6DB1,
		0x0006,
		0xE451,
	}
}

// input is one connection's writes from the phone. Each connection gets
// its own, so a reader left over from an earlier one never takes them.
type input struct {
	cmd    chan Packet
	data   chan Packet
	closed chan bool // a newer connection replaced this one
}

func newInput() *input {
	return &input{cmd: make(chan Packet, 5), data: make(chan Packet, 5), closed: make(chan bool)}
}

var errStopped = errors.New("the connection ended")

type Ble struct {
	in         *input // guarded by genMtx
	dataOutput chan Packet
	cmdOutput  chan Packet

	messageInput  chan *message.Message
	messageOutput chan *message.Message

	stopLoop    chan bool
	reconnected chan bool
	radio       Radio

	profile     Profile
	pdmId       uint32 // the controller the pod is paired to; guarded by genMtx
	podIdLocked []byte // the pod id last advertised; guarded by genMtx

	// connGen counts central connections; servingGen is the one the
	// message loop was started for. They differ only after a real reconnect.
	genMtx     sync.Mutex
	connGen    uint64
	servingGen uint64
	connected  bool
}

// New starts the pod's link layer on the radio that attach returns.
func New(attach func(*Ble) (Radio, error), profile Profile) (*Ble, error) {
	b := &Ble{
		profile:       profile,
		in:            newInput(),
		dataOutput:    make(chan Packet, 5),
		cmdOutput:     make(chan Packet, 5),
		messageInput:  make(chan *message.Message, 5),
		messageOutput: make(chan *message.Message, 2),
		reconnected:   make(chan bool, 1),
	}
	r, err := attach(b)
	if err != nil {
		return nil, err
	}
	b.radio = r

	go func() {
		for packet := range b.cmdOutput {
			if err := b.radio.NotifyCmd(packet); err != nil {
				log.Warnf("pkg bluetooth; CMD %s not sent: %s", packet, err)
			}
		}
	}()
	go func() {
		for packet := range b.dataOutput {
			if err := b.radio.NotifyData(packet); err != nil {
				log.Warnf("pkg bluetooth; DATA %s not sent: %s", packet, err)
			}
		}
	}()
	return b, nil
}

// Connected is the radio reporting a new connection from the phone.
func (b *Ble) Connected() {
	b.StopMessageLoop()
	for len(b.messageInput) > 0 {
		<-b.messageInput
	}
	b.genMtx.Lock()
	close(b.in.closed)
	b.in = newInput()
	b.connGen++
	b.connected = true
	b.genMtx.Unlock()
	// Wake any in-flight CommandLoop so it can tear down and
	// re-establish a session on this new connection.
	select {
	case b.reconnected <- true:
	default:
	}
}

func (b *Ble) Disconnected() {
	b.genMtx.Lock()
	b.connected = false
	b.genMtx.Unlock()
}

// IsConnected says whether the phone is connected.
func (b *Ble) IsConnected() bool {
	b.genMtx.Lock()
	defer b.genMtx.Unlock()
	return b.connected
}

// CmdWritten and DataWritten are the phone's writes to the two characteristics.
func (b *Ble) CmdWritten(data []byte) {
	b.input().cmd <- Packet(append([]byte(nil), data...))
}

func (b *Ble) DataWritten(data []byte) {
	b.input().data <- Packet(append([]byte(nil), data...))
}

func (b *Ble) input() *input {
	b.genMtx.Lock()
	defer b.genMtx.Unlock()
	return b.in
}

// read takes the next packet from a connection's channel, or reports that
// the message loop reading it was stopped.
func read(ch chan Packet, stop chan bool) (Packet, error) {
	select {
	case p := <-ch:
		return p, nil
	case <-stop:
		return nil, errStopped
	}
}

func (b *Ble) RefreshAdvertisingWithSpecifiedId(id []byte) error { // 4 bytes, first 2 usually empty
	log.Debugf("RefreshAdvertisingWithSpecifiedId %x", id)
	b.genMtx.Lock()
	b.podIdLocked = id
	pdmId := b.pdmId
	b.genMtx.Unlock()
	return b.radio.Advertise(id, pdmId)
}

// SetPdmId records the controller the pod is paired to. An Omnipod 5
// advertises it, so the phone can pick its own pod out while disconnected
// (BluetoothManager.podScanServiceUUID).
func (b *Ble) SetPdmId(pdmId uint32) {
	b.genMtx.Lock()
	changed := b.pdmId != pdmId
	b.pdmId = pdmId
	podId := b.podIdLocked
	b.genMtx.Unlock()
	if changed {
		b.radio.Advertise(podId, pdmId)
	}
}

// Profile is the BLE profile the pod is serving.
func (b *Ble) Profile() Profile { return b.profile }

// SetAdvertisedState advertises the pod's fault and firing alerts.
func (b *Ble) SetAdvertisedState(state AdvertState) error {
	return b.radio.AdvertiseState(state)
}

func (b *Ble) WriteCmd(packet Packet) error {

	b.cmdOutput <- packet
	return nil
}

func (b *Ble) WriteData(packet Packet) error {
	b.dataOutput <- packet
	return nil
}

func (b *Ble) writeDataBuffer(buf *bytes.Buffer) error {
	data := make([]byte, buf.Len())
	copy(data, buf.Bytes())
	buf.Reset()
	return b.WriteData(data)
}

// ReadCmd and ReadData read the current connection, following the phone
// to a new one.
func (b *Ble) ReadCmd() (Packet, error) {
	for {
		in := b.input()
		if p, err := read(in.cmd, in.closed); err == nil {
			return p, nil
		}
	}
}

func (b *Ble) ReadData() (Packet, error) {
	for {
		in := b.input()
		if p, err := read(in.data, in.closed); err == nil {
			return p, nil
		}
	}
}

func (p Packet) String() string {
	return hex.EncodeToString(p)
}

func (b *Ble) ReadMessage() (*message.Message, error) {
	message := <-b.messageInput
	return message, nil
}

func (b *Ble) ReadMessageWithTimeout(d time.Duration) (*message.Message, bool, bool) {
	deadline := time.After(d)
	for {
		select {
		case message := <-b.messageInput:
			return message, false, false
		case <-b.reconnected:
			if b.servingCurrentConnection() {
				// Latched while this very connection was being set up
				// (pairing retries connect several times). Not a reconnect.
				log.Tracef("pkg bluetooth; ignoring stale connect signal")
				continue
			}
			log.Debugf("ReadMessage interrupted by a new connection")
			return nil, false, true
		case <-deadline:
			log.Debugf("ReadMessage timeout")
			return nil, true, false
		}
	}
}

func (b *Ble) servingCurrentConnection() bool {
	b.genMtx.Lock()
	defer b.genMtx.Unlock()
	return b.connGen == b.servingGen
}

func (b *Ble) ShutdownConnection() {
	b.radio.Disconnect()
}

// MTUShortfall reports a link too small to carry a packet of this profile.
// The phone fragments a message into packets but does not fragment a packet,
// so a short link truncates every write silently, and pairing stalls on the
// first message that needs more than one packet. Returns nil when the link
// is big enough, and when the radio has no MTU to report.
func (b *Ble) MTUShortfall() error {
	mtu := b.radio.LinkMTU()
	if mtu == 0 {
		return nil
	}
	needed := b.profile.Layout.MaxPayloadSize + 3 // the 3-byte ATT write header
	if mtu >= needed {
		return nil
	}
	return fmt.Errorf("the phone negotiated an ATT MTU of %d, below the %d an %s packet needs, "+
		"so its writes would be truncated. A phone asks for more only of a Bluetooth 4.2 or "+
		"later radio: check this one with `hciconfig hci0 version`, and if it is older, plug "+
		"in a 4.2+ dongle and name it with -hci (it will not be hci0). On a 4.2+ radio, "+
		"`sudo hcitool -i hci0 cmd 0x08 0x0024 fb 00 48 03` is worth a try. Or run the app in "+
		"the iOS Simulator over -transport impossible, which has no MTU",
		mtu, needed, b.profile.Mode.Description())
}

func (b *Ble) WriteMessage(message *message.Message) {
	b.messageOutput <- message
}

func (b *Ble) loop(stop chan bool, in *input) {
	// A DASH pod is asked for every exchange with RTS on the command
	// characteristic; an Omnipod 5 has no such handshake, so an inbound
	// message simply begins with its first data packet. Leaving the data
	// channel nil for a DASH keeps this select out of the way of the
	// packet reads inside readMessage.
	var dataStart chan Packet
	if !b.profile.UsesRTS() {
		dataStart = in.data
	}
	for {
		select {
		case <-stop:
			return
		default:
		}
		select {
		case <-stop:
			return
		case msg := <-b.messageOutput:
			if err := b.writeMessage(msg, in, stop); err == errStopped {
				return
			} else if err != nil {
				// The phone gets no answer and asks again.
				log.Errorf("pkg bluetooth; error writing message: %s", err)
			}
		case cmd := <-in.cmd:
			if !b.profile.UsesRTS() {
				// The phone only acknowledges here; nothing it writes to
				// the command characteristic starts a message.
				log.Tracef("pkg bluetooth; command from the phone: %x", cmd)
				continue
			}
			msg, err := b.readMessage(cmd, in, stop)
			if err == errStopped {
				return
			}
			if err != nil {
				// The phone was told it failed and sends it again.
				log.Errorf("pkg bluetooth; error reading message: %s", err)
				continue
			}
			select {
			case b.messageInput <- msg:
			case <-stop:
				return
			}
		case first := <-dataStart:
			msg, err := b.readMessagePackets(first, in, stop)
			if err == errStopped {
				return
			}
			if err != nil {
				log.Errorf("pkg bluetooth; error reading message: %s", err)
				continue
			}
			select {
			case b.messageInput <- msg:
			case <-stop:
				return
			}
		}
	}
}

func (b *Ble) StartMessageLoop() {
	if b.stopLoop != nil {
		log.Fatalf("pkg bluetooth; Messaging loop is already running")
	}
	b.genMtx.Lock()
	b.servingGen = b.connGen
	b.genMtx.Unlock()
	select {
	case <-b.reconnected:
	default:
	}
	b.stopLoop = make(chan bool)
	go b.loop(b.stopLoop, b.input())
}

func (b *Ble) StopMessageLoop() {
	// race condition, but this is called only on device disconnect
	if b.stopLoop != nil {
		close(b.stopLoop)
		b.stopLoop = nil
	}
}

func (b *Ble) expectCommand(expected Packet, in *input, stop chan bool) error {
	for {
		cmd, err := read(in.cmd, stop)
		if err != nil {
			return err
		}
		if len(cmd) == 0 {
			return fmt.Errorf("expected command: %x. received an empty command", expected)
		}
		// A real Omnipod 5 reports progress with 0x08 while it works
		// through a pairing message; OmnipodKit skips those and keeps
		// waiting for what it asked for, so the pod tolerates them too.
		if cmd[0] == CmdPairStatus[0] {
			log.Tracef("pkg bluetooth; skipping pair status %x", cmd)
			continue
		}
		if cmd[0] != expected[0] {
			return fmt.Errorf("expected command: %x. received command: %x", expected, cmd)
		}
		return nil
	}
}

// writeMessage sends one pod message as a run of packets. A DASH asks to
// send first and an Omnipod 5 does not, but both wait to be told the
// message arrived (OmnipodKit's PeripheralManager.sendMessagePacket).
func (b *Ble) writeMessage(msg *message.Message, in *input, stop chan bool) error {
	raw, err := msg.Marshal()
	if err != nil {
		log.Fatalf("pkg bluetooth; could not marshal the message %s", err)
	}
	log.Tracef("pkg bluetooth; Sending message: %x", raw)

	if b.profile.UsesRTS() {
		b.WriteCmd(CmdRTS)
		if err := b.expectCommand(CmdCTS, in, stop); err != nil { // TODO figure out what to do if !CTS
			return err
		}
	}

	for _, packet := range b.profile.Layout.Split(raw) {
		if err := b.WriteData(packet); err != nil {
			return err
		}
	}
	return b.expectCommand(CmdSuccess, in, stop)
}

// readMessage reads a DASH message, which the phone opens with RTS.
func (b *Ble) readMessage(cmd Packet, in *input, stop chan bool) (*message.Message, error) {
	log.Trace("pkg bluetooth; Reading RTS")
	if len(cmd) == 0 || cmd[0] != CmdRTS[0] {
		return nil, fmt.Errorf("expected command: %x. received command: %x", CmdRTS, cmd)
	}
	log.Trace("pkg bluetooth; Sending CTS")
	b.WriteCmd(CmdCTS)

	first, err := read(in.data, stop)
	if err != nil {
		return nil, err
	}
	return b.readMessagePackets(first, in, stop)
}

// readMessagePackets reassembles a message that has begun with first, and
// tells the phone how it went.
func (b *Ble) readMessagePackets(first Packet, in *input, stop chan bool) (*message.Message, error) {
	joiner, err := NewJoiner(first, b.profile.Layout)
	if err != nil {
		log.Warnf("pkg bluetooth; sending FAIL: %s", err)
		b.WriteCmd(CmdFail)
		return nil, err
	}
	for joiner.More() {
		packet, err := read(in.data, stop)
		if err != nil {
			return nil, err
		}
		if err := joiner.Accumulate(packet); err != nil {
			log.Warnf("pkg bluetooth; sending FAIL: %s", err)
			b.WriteCmd(CmdFail)
			return nil, err
		}
	}
	body, err := joiner.Finalize()
	if err != nil {
		log.Warnf("pkg bluetooth; sending FAIL: %s", err)
		b.WriteCmd(CmdFail)
		return nil, err
	}

	b.WriteCmd(CmdSuccess)

	msg, err := message.Unmarshal(body)
	log.Tracef("pkg bluetooth; Received message: %s", spew.Sdump(msg))
	return msg, err
}
