package bluetooth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
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
)

// Radio carries the pod's command and data characteristics to the phone:
// a Bluetooth adapter, or the iOS Simulator through ImpossiBLE.
type Radio interface {
	NotifyCmd(Packet) error
	NotifyData(Packet) error
	Advertise(podId []byte) error
	AdvertiseState(state AdvertState) error
	Disconnect()
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
	mode mode.Mode

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

func (b *Ble) RefreshAdvertisingWithSpecifiedId(id []byte) error { // 4 bytes, first 2 usually empty
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

func (b *Ble) WriteMessage(message *message.Message) {
	b.messageOutput <- message
}

func (b *Ble) loop(stop chan bool, in *input) {
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
	cmd, err := read(in.cmd, stop)
	if err != nil {
		return err
	}
	if len(cmd) == 0 || cmd[0] != expected[0] {
		return fmt.Errorf("expected command: %x. received command: %x", expected, cmd)
	}
	return nil
}

func (b *Ble) writeMessage(msg *message.Message, in *input, stop chan bool) error {
	var buf bytes.Buffer
	var index = 0

	b.WriteCmd(CmdRTS)
	if err := b.expectCommand(CmdCTS, in, stop); err != nil { // TODO figure out what to do if !CTS
		return err
	}
	bytes, err := msg.Marshal()
	if err != nil {
		log.Fatalf("pkg bluetooth; could not marshal the message %s", err)
	}
	log.Tracef("pkg bluetooth; Sending message: %x", bytes)
	sum := crc32.ChecksumIEEE(bytes)
	if len(bytes) <= 18 {
		buf.WriteByte(byte(index))
		buf.WriteByte(0)     // fragments

		buf.WriteByte(byte(sum >> 24))
		buf.WriteByte(byte(sum >> 16))
		buf.WriteByte(byte(sum >> 8))
		buf.WriteByte(byte(sum))
		buf.WriteByte((byte(len(bytes))))
		end := len(bytes)
		if len(bytes) > 14 {
			end = 14
		}
		buf.Write(bytes[:end])
		b.writeDataBuffer(&buf)

		if len(bytes) > 14 {
			buf.WriteByte(byte(index))
			buf.WriteByte(byte(len(bytes) - 14))
			buf.Write(bytes[14:])
			b.writeDataBuffer(&buf)
		}
		return nil
	}

	size := len(bytes)
	fullFragments := (size - 18) / 19
	rest := (size - (fullFragments * 19)) - 18
	buf.WriteByte(byte(index))
	buf.WriteByte(byte(fullFragments + 1))
	buf.Write(bytes[:18])

	b.writeDataBuffer(&buf)

	for index = 1; index <= fullFragments; index++ {
		buf.WriteByte(byte(index))
		if index == 1 {
			buf.Write(bytes[18:37])
		} else {
			buf.Write(bytes[(index-1)*19+18 : (index-1)*19+18+19])
		}
		b.writeDataBuffer(&buf)
	}

	buf.WriteByte(byte(index))
	buf.WriteByte(byte(rest))
	buf.WriteByte(byte(sum >> 24))
	buf.WriteByte(byte(sum >> 16))
	buf.WriteByte(byte(sum >> 8))
	buf.WriteByte(byte(sum))
	end := rest
	if rest > 14 {
		end = 14
	}
	buf.Write(bytes[(fullFragments*19)+18 : (fullFragments*19)+18+end])
	b.writeDataBuffer(&buf)
	if rest > 14 {
		index++
		buf.WriteByte(byte(index))
		buf.WriteByte(byte(rest - 14))
		buf.Write(bytes[fullFragments*19+18+14:])
		for buf.Len() < 20 {
			buf.WriteByte(0)
		}
		b.writeDataBuffer(&buf)
	}
	return b.expectCommand(CmdSuccess, in, stop)
}

func (b *Ble) readMessage(cmd Packet, in *input, stop chan bool) (*message.Message, error) {
	var buf bytes.Buffer
	var checksum []byte

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
	fragments := int(first[1])
	expectedIndex := 1
	oneExtra := false
	if fragments == 0 {
		checksum = first[2:6]
		len := first[6]
		end := len + 7
		if len > 13 {
			oneExtra = true
			end = 20
		}
		buf.Write(first[7:end])
	} else {
		buf.Write(first[2:20])
	}
	for i := 1; i < fragments; i++ {
		data, err := read(in.data, stop)
		if err != nil {
			return nil, err
		}
		if i == expectedIndex {
			buf.Write(data[1:20])
		} else {
			log.Warnf("pkg bluetooth; sending NACK, packet index is wrong")
			buf.Write(data[:])
			CmdNACK[1] = byte(expectedIndex)
			b.WriteCmd(CmdNACK)
		}
		expectedIndex++
	}
	if fragments != 0 {
		data, err := read(in.data, stop)
		if err != nil {
			return nil, err
		}
		len := data[1]
		if len > 14 {
			oneExtra = true
			len = 14
		}
		checksum = data[2:6]
		buf.Write(data[6 : len+6])
	}
	log.Tracef("pkg bluetooth; One extra: %t", oneExtra)
	if oneExtra {
		data, err := read(in.data, stop)
		if err != nil {
			return nil, err
		}
		buf.Write(data[2 : data[1]+2])
	}
	bytes := buf.Bytes()
	sum := crc32.ChecksumIEEE(bytes)
	if binary.BigEndian.Uint32(checksum) != sum {
		log.Warnf("pkg bluetooth; checksum missmatch. checksum is: %x. want: %x", sum, checksum)
		log.Warnf("pkg bluetooth; data: %s", hex.EncodeToString(bytes))

		b.WriteCmd(CmdFail)
		return nil, errors.New("checksum missmatch")
	}

	b.WriteCmd(CmdSuccess)

	msg, _err := message.Unmarshal(bytes)
	log.Tracef("pkg bluetooth; Received message: %s", spew.Sdump(msg))

	return msg, _err
}
