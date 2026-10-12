package bluetooth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
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
)

// Radio carries the pod's command and data characteristics to the phone:
// a Bluetooth adapter, or the iOS Simulator through ImpossiBLE.
type Radio interface {
	NotifyCmd(Packet) error
	NotifyData(Packet) error
	Advertise(podId []byte) error
	Disconnect()
}

const AdvertisedName = " :: Fake POD ::"

// AdvertisedServices is the list of 16-bit service UUIDs a DASH pod
// advertises; the 4th and 5th carry its id, FFFF FFFE before pairing.
func AdvertisedServices(podId []byte) []uint16 {
	idOne, idTwo := uint16(0xffff), uint16(0xfffe)
	if podId != nil {
		idOne = binary.BigEndian.Uint16(podId[0:2])
		idTwo = binary.BigEndian.Uint16(podId[2:4])
	}
	return []uint16{
		0x4024,
		0x2470,
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

type Ble struct {
	dataInput  chan Packet
	cmdInput   chan Packet
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

// New starts the pod's link layer on the radio that attach returns.
func New(attach func(*Ble) (Radio, error)) (*Ble, error) {
	b := &Ble{
		dataInput:     make(chan Packet, 5),
		cmdInput:      make(chan Packet, 5),
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
	// What the previous connection left unread is no part of the new one.
	for _, ch := range []chan Packet{b.cmdInput, b.dataInput} {
		for len(ch) > 0 {
			<-ch
		}
	}
	for len(b.messageInput) > 0 {
		<-b.messageInput
	}
	b.genMtx.Lock()
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
	b.cmdInput <- Packet(append([]byte(nil), data...))
}

func (b *Ble) DataWritten(data []byte) {
	b.dataInput <- Packet(append([]byte(nil), data...))
}

func (b *Ble) RefreshAdvertisingWithSpecifiedId(id []byte) error { // 4 bytes, first 2 usually empty
	log.Debugf("RefreshAdvertisingWithSpecifiedId %x", id)
	return b.radio.Advertise(id)
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

func (b *Ble) ReadCmd() (Packet, error) {
	packet := <-b.cmdInput
	return packet, nil
}

func (b *Ble) ReadData() (Packet, error) {
	packet := <-b.dataInput
	return packet, nil
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

func (b *Ble) loop(stop chan bool) {
	for {
		select {
		case <-stop:
			return
		case msg := <-b.messageOutput:
			b.writeMessage(msg)
		case cmd := <-b.cmdInput:
			msg, err := b.readMessage(cmd)
			if err != nil {
				// The phone was told it failed and sends it again.
				log.Errorf("pkg bluetooth; error reading message: %s", err)
				continue
			}
			b.messageInput <- msg
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
	go b.loop(b.stopLoop)
}

func (b *Ble) StopMessageLoop() {
	// race condition, but this is called only on device disconnect
	if b.stopLoop != nil {
		close(b.stopLoop)
		b.stopLoop = nil
	}
}

func (b *Ble) expectCommand(expected Packet) {
	cmd, _ := b.ReadCmd()
	if !bytes.Equal(expected[:1], cmd[:1]) {
		log.Fatalf("pkg bluetooth; expected command: %s. received command: %s", expected, cmd)
	}
}

func (b *Ble) writeMessage(msg *message.Message) {
	var buf bytes.Buffer
	var index = 0

	b.WriteCmd(CmdRTS)
	b.expectCommand(CmdCTS) // TODO figure out what to do if !CTS
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
		return
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
	b.expectCommand(CmdSuccess)
}

func (b *Ble) readMessage(cmd Packet) (*message.Message, error) {
	var buf bytes.Buffer
	var checksum []byte

	log.Trace("pkg bluetooth; Reading RTS")
	if !bytes.Equal(CmdRTS[:1], cmd[:1]) {
		log.Fatalf("pkg bluetooth; expected command: %x. received command: %x", CmdRTS, cmd)
	}
	log.Trace("pkg bluetooth; Sending CTS")

	b.WriteCmd(CmdCTS)

	first, _ := b.ReadData()
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
		data, _ := b.ReadData()
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
		data, _ := b.ReadData()
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
		data, _ := b.ReadData()
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
