package bluetooth

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/mode"
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
	// CmdHello is the phone's first write, 06 01 04 and its 4-byte id.
	CmdHello = Packet([]byte{6})
)

// Radio carries the pod's command and data characteristics to the phone:
// a Bluetooth adapter, or the iOS Simulator through ImpossiBLE.
type Radio interface {
	NotifyCmd(Packet) error
	NotifyData(Packet) error
	// Advertise sets the id in the advertisement: the pod's own id for a
	// DASH pod, the phone's (controller) id for a paired Omnipod 5; nil
	// before pairing.
	Advertise(id []byte) error
	AdvertiseState(state AdvertState) error
	Disconnect()
}

// UUID is a 16-bit or 128-bit service UUID in its printed byte order.
type UUID []byte

func UUID16(u uint16) UUID { return UUID{byte(u >> 8), byte(u)} }

// String is the form CoreBluetooth prints: "4024", or
// "CE1F923D-C539-48EA-7300-0AFFFFFFFE00".
func (u UUID) String() string {
	s := strings.ToUpper(hex.EncodeToString(u))
	if len(u) != 16 {
		return s
	}
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// AdvertisedName is the pod's local name. OmnipodKit finds a pod by its
// service UUIDs and never reads the name.
func AdvertisedName(m mode.Mode, id []byte) string {
	if !m.IsO5() {
		return " :: Fake POD ::"
	}
	// An Omnipod 5 names itself after its id and lot, as captured.
	return "AP " + strings.ToUpper(hex.EncodeToString(o5AdvertisedID(id))) + " 0A95B6110002761B"
}

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

// ManufacturerData is the pod's manufacturer data. A DASH pod's is iBeacon
// shaped, with the status word OmnipodKit decodes 7 bytes from its end: 00,
// 02 (or the fault code), the fault code, the alert slots. A captured
// occlusion read 00141400. An Omnipod 5 advertises 7 bytes OmnipodKit does
// not decode; these are from a capture.
func (s AdvertState) ManufacturerData() []byte {
	b1 := uint8(0x02)
	if s.Fault != 0 {
		b1 = s.Fault
	}
	data := []byte{0x4c, 0x00, 0x02, 0x15}
	data = append(data, make([]byte, 14)...)
	return append(data, 0x00, b1, s.Fault, s.Alerts, 0x00, 0x00, 0xc5)
}

// ManufacturerData is the manufacturer data for the pod in mode m.
func ManufacturerData(m mode.Mode, state AdvertState) []byte {
	if m.IsO5() {
		return []byte{0x60, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00}
	}
	return state.ManufacturerData()
}

// o5AdvertisedID is the controller id an Omnipod 5 embeds in its service
// UUID, FFFFFFFE until it has paired (OmnipodKit o5OmnipodServiceUUID).
func o5AdvertisedID(id []byte) []byte {
	if len(id) != 4 {
		return []byte{0xff, 0xff, 0xff, 0xfe}
	}
	return id
}

// AdvertisedServices is the list of service UUIDs the pod advertises.
//
// A DASH pod advertises nine 16-bit UUIDs; the 4th and 5th carry its id,
// FFFF FFFE before pairing, and the 2nd its status.
//
// An Omnipod 5 advertises exactly one 128-bit UUID,
// CE1F923D-C539-48EA-7300-0A<controller id>00, with FFFFFFFE before pairing;
// a fault flips the last byte to 02 (OmnipodKit BluetoothServices.swift,
// PodAdvertisement.swift). Any further UUID makes OmnipodKit reject the
// advertisement.
func AdvertisedServices(m mode.Mode, id []byte, state AdvertState) []UUID {
	if m.IsO5() {
		u := UUID{0xCE, 0x1F, 0x92, 0x3D, 0xC5, 0x39, 0x48, 0xEA, 0x73, 0x00, 0x0A}
		u = append(u, o5AdvertisedID(id)...)
		if state.Fault != 0 {
			return []UUID{append(u, 0x02)}
		}
		return []UUID{append(u, 0x00)}
	}
	idOne, idTwo, second := uint16(0xffff), uint16(0xfffe), uint16(0x2470)
	if id != nil {
		idOne = binary.BigEndian.Uint16(id[0:2])
		idTwo = binary.BigEndian.Uint16(id[2:4])
		second = state.status()
	}
	return []UUID{
		UUID16(0x4024),
		UUID16(second),
		UUID16(0x000a),
		UUID16(idOne),
		UUID16(idTwo),
		// these 4 are copied from lotNo and lotSeq from fixed string in versionresponse.go
		UUID16(0x0814),
		UUID16(0x6DB1),
		UUID16(0x0006),
		UUID16(0xE451),
	}
}

const (
	podServiceUUID = "1A7E4024-E3ED-4464-8B7E-751E03D0DC5F"
	cmdCharUUID    = "1A7E2441-E3ED-4464-8B7E-751E03D0DC5F"
	// DASH and Omnipod 5 pods differ in the data characteristic only
	// (OmnipodKit dashOmnipodCharacteristicUUID, o5OmnipodCharacteristicUUID).
	dashDataCharUUID = "1A7E2442-E3ED-4464-8B7E-751E03D0DC5F"
	o5DataCharUUID   = "1A7E2443-E3ED-4464-8B7E-751E03D0DC5F"
)

// DataCharUUID is the data characteristic of the pod in mode m.
func DataCharUUID(m mode.Mode) string {
	if m.IsO5() {
		return o5DataCharUUID
	}
	return dashDataCharUUID
}

// input is one connection's writes from the phone. Each connection gets
// its own, so a reader left over from an earlier one never takes them.
type input struct {
	cmd    chan Packet
	data   chan Packet
	closed chan bool // a newer connection replaced this one
}

// An Omnipod 5 message is up to five 244-byte packets, written without
// waiting for the pod.
func newInput() *input {
	return &input{cmd: make(chan Packet, 8), data: make(chan Packet, 16), closed: make(chan bool)}
}

var errStopped = errors.New("the connection ended")

type Ble struct {
	mode   mode.Mode
	layout Layout

	in         *input // guarded by genMtx
	dataOutput chan Packet
	cmdOutput  chan Packet

	messageInput  chan *message.Message
	messageOutput chan *message.Message

	stopLoop    chan bool
	reconnected chan bool
	radio       Radio

	// connGen counts central connections; servingGen is the one the
	// message loop was started for. They differ only after a real reconnect.
	genMtx     sync.Mutex
	connGen    uint64
	servingGen uint64
	connected  bool
}

// New starts the pod's link layer, for a DASH or Omnipod 5 pod, on the
// radio that attach returns.
func New(m mode.Mode, attach func(*Ble) (Radio, error)) (*Ble, error) {
	b := &Ble{
		mode:          m.Normalized(),
		layout:        DashLayout,
		in:            newInput(),
		dataOutput:    make(chan Packet, 5),
		cmdOutput:     make(chan Packet, 5),
		messageInput:  make(chan *message.Message, 5),
		messageOutput: make(chan *message.Message, 2),
		reconnected:   make(chan bool, 1),
	}
	if b.mode.IsO5() {
		b.layout = O5Layout
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

// Mode is the pod this link layer serves.
func (b *Ble) Mode() mode.Mode { return b.mode }

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

// RefreshAdvertisingWithSpecifiedId advertises with a new id: the pod's for
// a DASH pod, the phone's for an Omnipod 5.
func (b *Ble) RefreshAdvertisingWithSpecifiedId(id []byte) error {
	log.Debugf("RefreshAdvertisingWithSpecifiedId %x", id)
	return b.radio.Advertise(id)
}

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

func (b *Ble) WriteMessage(message *message.Message) {
	b.messageOutput <- message
}

// loop reads the phone's messages and writes the pod's. A DASH phone asks
// to send with RTS on the command characteristic and waits for CTS; an
// Omnipod 5 phone writes its data packets straight away, so for it the
// first data packet starts a message (OmnipodKit
// PeripheralManager+OmnipodKit.swift).
func (b *Ble) loop(stop chan bool, in *input) {
	var data chan Packet
	if b.mode.IsO5() {
		data = in.data
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
			if b.mode.IsO5() {
				// No RTS on an Omnipod 5; a HELLO sent again, or a
				// SUCCESS the pod was not waiting for, is nothing to act on.
				log.Debugf("pkg bluetooth; ignoring command %s outside a message", cmd)
				continue
			}
			if len(cmd) == 0 || cmd[0] != CmdRTS[0] {
				log.Errorf("pkg bluetooth; expected command: %x. received command: %x", CmdRTS, cmd)
				continue
			}
			log.Trace("pkg bluetooth; Reading RTS, sending CTS")
			b.WriteCmd(CmdCTS)
			first, err := read(in.data, stop)
			if err == errStopped {
				return
			}
			b.deliver(first, in, stop)
		case first := <-data:
			b.deliver(first, in, stop)
		}
	}
}

// deliver reads the message that first starts and hands it to the pod.
func (b *Ble) deliver(first Packet, in *input, stop chan bool) bool {
	msg, err := b.readMessage(first, in, stop)
	if err == errStopped {
		return false
	}
	if err != nil {
		// The phone was told it failed and sends it again.
		log.Errorf("pkg bluetooth; error reading message: %s", err)
		return true
	}
	select {
	case b.messageInput <- msg:
	case <-stop:
		return false
	}
	return true
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
	cmd, err := read(in.cmd, stop)
	if err != nil {
		return err
	}
	if len(cmd) == 0 || cmd[0] != expected[0] {
		return fmt.Errorf("expected command: %x. received command: %x", expected, cmd)
	}
	return nil
}

// writeMessage sends one message: RTS and CTS first on a DASH pod, then the
// packets, then the phone's SUCCESS.
func (b *Ble) writeMessage(msg *message.Message, in *input, stop chan bool) error {
	if !b.mode.IsO5() {
		b.WriteCmd(CmdRTS)
		if err := b.expectCommand(CmdCTS, in, stop); err != nil { // TODO figure out what to do if !CTS
			return err
		}
	}
	bytes, err := msg.Marshal()
	if err != nil {
		log.Fatalf("pkg bluetooth; could not marshal the message %s", err)
	}
	log.Tracef("pkg bluetooth; Sending message: %x", bytes)
	for _, p := range b.layout.Split(bytes) {
		b.WriteData(p)
	}
	return b.expectCommand(CmdSuccess, in, stop)
}

// readMessage reads the message that starts with first and acknowledges it
// with SUCCESS; a packet out of order gets a NACK with the expected index
// and a bad checksum FAIL, and the phone sends the message again.
func (b *Ble) readMessage(first Packet, in *input, stop chan bool) (*message.Message, error) {
	bytes, err := b.layout.Join(first, func() (Packet, error) { return read(in.data, stop) })
	var indexErr *IndexError
	switch {
	case err == errStopped:
		return nil, err
	case errors.As(err, &indexErr):
		log.Warnf("pkg bluetooth; sending NACK, packet index is wrong: %s", err)
		b.WriteCmd(Packet{CmdNACK[0], indexErr.Expected})
		return nil, err
	case err == ErrCRC:
		log.Warnf("pkg bluetooth; checksum missmatch; data: %s", hex.EncodeToString(bytes))
		b.WriteCmd(CmdFail)
		return nil, err
	case err != nil:
		log.Warnf("pkg bluetooth; bad packet: %s", err)
		b.WriteCmd(CmdFail)
		return nil, err
	}

	b.WriteCmd(CmdSuccess)

	msg, _err := message.Unmarshal(bytes)
	log.Tracef("pkg bluetooth; Received message: %s", spew.Sdump(msg))

	return msg, _err
}
