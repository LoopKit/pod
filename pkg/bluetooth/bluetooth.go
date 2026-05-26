package bluetooth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"sync"
	"time"

	"github.com/avereha/pod/pkg/bluetooth/packet"
	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/pair"
	"github.com/davecgh/go-spew/spew"
	"github.com/paypal/gatt"
	"github.com/paypal/gatt/linux/cmd"
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

type Ble struct {
	// mode selects which BLE profile (Dash or Omnipod 5) the simulator
	// exposes: advertisement bytes, GATT service shape, transport framing,
	// and command-channel routing all differ between the two.
	mode pair.Mode

	dataInput chan Packet
	cmdInput  chan Packet
	// cmdActivation receives pairing-state command bytes (HELLO 0x06,
	// PAIR_STATUS 0x08, INCORRECT 0x09 — anything that isn't the RTS/CTS/
	// SUCCESS/NACK fragmentation control set). ReadCmd() drains this so
	// StartActivation gets first crack at the HELLO byte without racing
	// the message loop's cmdInput consumer.
	cmdActivation chan Packet
	dataOutput    chan Packet
	cmdOutput     chan Packet

	messageInput  chan *message.Message
	messageOutput chan *message.Message

	stopLoop chan bool
	device   *gatt.Device
	central  *gatt.Central

	cmdNotifier    gatt.Notifier
	cmdNotifierMtx sync.Mutex

	dataNotifier    gatt.Notifier
	dataNotifierMtx sync.Mutex

	heartbeatNotifier    gatt.Notifier
	heartbeatNotifierMtx sync.Mutex
}

// IsO5 reports whether this BLE instance is exposing the Omnipod 5 profile.
// Used internally to gate advertisement, GATT shape, transport framing, and
// command-channel routing decisions. Dash profile is the default and must
// match origin/main bit-for-bit.
func (b *Ble) IsO5() bool { return b.mode == pair.ModeO5 }

var DefaultServerOptions = []gatt.Option{
	gatt.LnxMaxConnections(1),
	gatt.LnxDeviceID(-1, true),
	gatt.LnxSetAdvertisingParameters(&cmd.LESetAdvertisingParameters{
		AdvertisingIntervalMin: 0x00f4,
		AdvertisingIntervalMax: 0x00f4,
		AdvertisingChannelMap:  0x7,
	}),
}

// advertiser is the narrow subset of gatt.Device the advertise/refresh
// helpers need. Pulling these two calls behind an interface lets the
// regression tests in profile_test.go capture the exact name/UUID/mfg-data
// arguments each mode produces without having to stand up a real gatt.Device.
// gatt.Device satisfies this interface implicitly, so the production call
// sites pass the device unchanged.
type advertiser interface {
	AdvertiseNameAndServices(name string, ss []gatt.UUID) error
	AdvertiseNameServicesMfgData(name string, ss []gatt.UUID, mfg []byte) error
}

// dashAdvertiseName is the device name the Dash simulator advertises. It is
// the literal string origin/main has shipped with since the project's first
// commit; OmnipodKit's Dash scanner does not rely on the name (it matches by
// the 0x4024 service UUID), but the byte-for-byte form is preserved so
// btmon captures continue to compare cleanly with main.
const dashAdvertiseName = " :: Fake POD ::"

// o5MfgData is the 7-byte manufacturer-data payload that real Omnipod 5 pods
// co-advertise. Source: OmnipodKit BLE advertisement bytes captured from
// production pod scans; the OmnipodKit scanner inspects this field during
// discovery, so we emit the exact same sequence for O5 advertisements.
var o5MfgData = []byte{0x60, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00}

// advertiseDash advertises the Dash profile: the " :: Fake POD ::" name and
// the 9-element UUID16 list from origin/main. This must remain byte-for-byte
// identical to main so existing Dash users (and the test fixtures captured
// against main) keep working. podId is the 4-byte pod address; when nil the
// default {ff,ff,ff,fe} mapping from main is used.
func (b *Ble) advertiseDash(d advertiser, podId []byte) error {
	podIdServiceOne := gatt.UUID16(0xffff)
	podIdServiceTwo := gatt.UUID16(0xfffe)
	if podId != nil {
		podIdServiceOne = gatt.UUID16(binary.BigEndian.Uint16(podId[0:2]))
		podIdServiceTwo = gatt.UUID16(binary.BigEndian.Uint16(podId[2:4]))
	}

	// Advertise device name and service's UUIDs.
	return d.AdvertiseNameAndServices(dashAdvertiseName, []gatt.UUID{
		gatt.UUID16(0x4024),

		gatt.UUID16(0x2470),
		gatt.UUID16(0x000a),

		podIdServiceOne,
		podIdServiceTwo,

		// these 4 are copied from lotNo and lotSeq from fixed string in versionresponse.go
		gatt.UUID16(0x0814),
		gatt.UUID16(0x6DB1),
		gatt.UUID16(0x0006),
		gatt.UUID16(0xE451),
	})
}

// advertiseO5 advertises the Omnipod 5 profile: an "AP <hex> 0A95B6110002761B"
// name, two 128-bit UUIDs (CE1F923D-...0A<podId>00 plus the ECF301E2...
// scanner identifier), and the 7-byte manufacturer-data payload that real
// Omnipod 5 pods co-advertise. When podId is nil the default {ff,ff,ff,fe}
// mapping is used. The mfg-data bytes (60 03 00 01 00 00 00) come straight
// from OmnipodKit's observed BLE advertisement frames — OmnipodKit's scanner
// keys off this field, so the vendored paypal/gatt fork now exposes
// AdvertiseNameServicesMfgData to let us emit it.
func (b *Ble) advertiseO5(d advertiser, podId []byte) error {
	podIdArray, err := hex.DecodeString("fffffffe")
	if err != nil {
		return fmt.Errorf("could not parse default address: %w", err)
	}
	if podId != nil {
		podIdArray = podId
	}

	// CE1F923D-C539-48EA-7300-0AFFFFFFFE00 unpaired, or
	// CE1F923D-C539-48EA-7300-0A<pdmId>00 once paired. The
	// ECF301E2... UUID is OmnipodKit's "advertisement" identifier
	// for the O5 heartbeat service and is co-advertised so the
	// scanner can find it during discovery (BluetoothServices.swift).
	return d.AdvertiseNameServicesMfgData(
		"AP "+strings.ToUpper(hex.EncodeToString(podIdArray))+" 0A95B6110002761B",
		[]gatt.UUID{
			gatt.MustParseUUID("CE1F923D-C539-48EA-7300-0A" + hex.EncodeToString(podIdArray) + "00"),
			gatt.MustParseUUID("ECF301E2-674B-4474-94D0-364F3AA653E6"),
		},
		o5MfgData,
	)
}

// refreshDash is the Dash-profile re-advertise path used after SetUniqueID
// updates the pod address. Verbatim form from origin/main (same UUID list as
// advertiseDash but constructed inline so the trace logging matches main's
// shape too). The advertiser parameter is the same gatt.Device the live
// caller uses in production; tests pass a mock to capture the exact call.
func (b *Ble) refreshDash(d advertiser, id []byte) error {
	log.Tracef("podIdServiceOne %v", gatt.UUID16(binary.BigEndian.Uint16(id[0:2])))
	log.Tracef("podIdServiceTwo %v", gatt.UUID16(binary.BigEndian.Uint16(id[2:4])))
	return d.AdvertiseNameAndServices(dashAdvertiseName, []gatt.UUID{
		gatt.UUID16(0x4024),

		gatt.UUID16(0x2470),
		gatt.UUID16(0x000a),

		gatt.UUID16(binary.BigEndian.Uint16(id[0:2])),
		gatt.UUID16(binary.BigEndian.Uint16(id[2:4])),

		// these 4 are copied from lotNo and lotSeq from fixed string in versionresponse.go
		gatt.UUID16(0x0814),
		gatt.UUID16(0x6DB1),
		gatt.UUID16(0x0006),
		gatt.UUID16(0xE451),
	})
}

// refreshO5 is the Omnipod 5 re-advertise path used after SetUniqueID. Same
// shape as advertiseO5, including the OmnipodKit-observed manufacturer-data
// payload so post-pair re-advertise frames still match real-pod BLE captures.
// The advertiser parameter is the same gatt.Device the live caller uses in
// production; tests pass a mock to capture the exact call.
func (b *Ble) refreshO5(d advertiser, id []byte) error {
	return d.AdvertiseNameServicesMfgData(
		"AP "+strings.ToUpper(hex.EncodeToString(id))+" 0A95B6110002761B",
		[]gatt.UUID{
			gatt.MustParseUUID("CE1F923D-C539-48EA-7300-0A" + hex.EncodeToString(id) + "00"),
			gatt.MustParseUUID("ECF301E2-674B-4474-94D0-364F3AA653E6"),
		},
		o5MfgData,
	)
}

func New(adapterID string, podId []byte, mode pair.Mode) (*Ble, error) {
	d, err := gatt.NewDevice(DefaultServerOptions...)
	if err != nil {
		log.Fatalf("pkg bluetooth; failed to open device, err: %s", err)
	}

	b := &Ble{
		mode:          mode,
		dataInput:     make(chan Packet, 5),
		cmdInput:      make(chan Packet, 5),
		cmdActivation: make(chan Packet, 5),
		dataOutput:    make(chan Packet, 5),
		cmdOutput:     make(chan Packet, 5),
		messageInput:  make(chan *message.Message, 5),
		messageOutput: make(chan *message.Message, 2),
		device:        &d,
	}

	log.Infof("pkg bluetooth; profile=%s adapter=%s podId=%x", mode, adapterID, podId)

	d.Handle(
		gatt.CentralConnected(func(c gatt.Central) {
			fmt.Println("pkg bluetooth; ** New connection from: ", c.ID())
			b.StopMessageLoop()
			b.central = &c
		}),
		gatt.CentralDisconnected(func(c gatt.Central) {
			log.Tracef("pkg bluetooth; ** disconnect: %s", c.ID())
		}),
	)

	// Start cmd writing goroutine
	go func() {
		for {
			packet := <-b.cmdOutput
			b.cmdNotifierMtx.Lock()
			if b.cmdNotifier.Done() {
				log.Fatalf("pkg bluetooth; CMD closed")
			}
			ret, err := b.cmdNotifier.Write(packet)
			b.cmdNotifierMtx.Unlock()
			log.Tracef("pkg bluetooth; CMD notification return: %d/%s", ret, hex.EncodeToString(packet))
			if err != nil {
				log.Fatalf("pkg bluetooth; error writing CMD: %s", err)
			}
		}
	}()

	// Start data writing goroutine
	go func() {
		for {
			packet := <-b.dataOutput
			b.dataNotifierMtx.Lock()
			if b.dataNotifier.Done() {
				log.Fatalf("pkg bluetooth; DATA closed")
			}
			ret, err := b.dataNotifier.Write(packet)
			b.dataNotifierMtx.Unlock()
			log.Tracef("pkg bluetooth; DATA notification return: %d/%s", ret, hex.EncodeToString(packet))
			if err != nil {
				log.Fatalf("pkg bluetooth; error writing DATA: %s ", err)
			}
		}
	}()

	// Heartbeat emitter: once a phone subscribes to the heartbeat
	// characteristic, push a one-byte notification every 10s. Real O5 pods
	// use this as a connection keep-alive. The ticker spawns unconditionally
	// for both modes — in Dash mode the heartbeat service is never
	// registered (see onStateChanged below) so b.heartbeatNotifier stays
	// nil and the nil-check below makes the ticker a no-op. No Notify call
	// is ever fired for Dash.
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			b.heartbeatNotifierMtx.Lock()
			n := b.heartbeatNotifier
			b.heartbeatNotifierMtx.Unlock()
			if n == nil || n.Done() {
				continue
			}
			if _, err := n.Write([]byte{0x00}); err != nil {
				log.Tracef("pkg bluetooth; heartbeat write error: %s", err)
			}
		}
	}()

	// A mandatory handler for monitoring device state.
	onStateChanged := func(d gatt.Device, s gatt.State) {
		fmt.Printf("state: %s\n", s)
		switch s {
		case gatt.StatePoweredOn:
			// Main pod GATT service (same primary UUID for Dash and Omnipod 5).
			// Source: OmnipodKit BluetoothServices.swift / BlePodProfile.swift.
			// Dash and O5 share the service + cmd char UUIDs; only the data
			// char UUID differs (Dash uses 2442 verbatim from origin/main, O5
			// uses 2443 per OmnipodKit). The O5-only heartbeat service is
			// registered alongside the main service for O5 mode.
			var serviceUUID = gatt.MustParseUUID("1A7E4024-E3ED-4464-8B7E-751E03D0DC5F")
			var cmdCharUUID = gatt.MustParseUUID("1A7E2441-E3ED-4464-8B7E-751E03D0DC5F")
			var dashDataCharUUID = gatt.MustParseUUID("1A7E2442-E3ED-4464-8B7E-751E03D0DC5F")
			var o5DataCharUUID = gatt.MustParseUUID("1A7E2443-E3ED-4464-8B7E-751E03D0DC5F")

			// Omnipod 5 heartbeat service used for keep-alive.
			// The pod GATT service UUID is 7DED7A6C... and its single
			// characteristic is 7DED7A6D... (notify). The ECF301E2... UUID
			// below is what OmnipodKit scans for in the advertisement, not a
			// GATT service exposed on the pod.
			var heartbeatServiceUUID = gatt.MustParseUUID("7DED7A6C-CA72-46A7-A3A2-6061F6FDCAEB")
			var heartbeatCharUUID = gatt.MustParseUUID("7DED7A6D-CA72-46A7-A3A2-6061F6FDCAEB")

			s := gatt.NewService(serviceUUID)

			cmdCharacteristic := s.AddCharacteristic(cmdCharUUID)
			cmdCharacteristic.HandleWriteFunc(
				func(r gatt.Request, data []byte) (status byte) {
					log.Tracef("received CMD,  %x", data)
					ret := make([]byte, len(data))
					copy(ret, data)
					if b.IsO5() {
						// O5: Multi-byte writes (e.g. HELLO = 06 01 04 +
						// 4-byte controller ID) and any non-RTS/SUCCESS
						// single-byte signal (HELLO, PAIR_STATUS,
						// INCORRECT, …) belong on the activation queue.
						// RTS / SUCCESS / NACK / FAIL stay on cmdInput
						// where the message loop drains them for
						// fragmentation handshake and ack handling.
						if len(ret) > 1 || (ret[0] != CmdRTS[0] && ret[0] != CmdSuccess[0] &&
							ret[0] != CmdNACK[0] && ret[0] != CmdFail[0]) {
							b.cmdActivation <- Packet(ret)
						} else {
							b.cmdInput <- Packet(ret)
						}
					} else {
						// Dash: origin/main routes every CMD write to
						// cmdInput unconditionally. The message loop's
						// readMessage path consumes RTS bytes there, and
						// StartAcceptingCommands' ReadCmd() also reads
						// from cmdInput on Dash.
						b.cmdInput <- Packet(ret)
					}
					return 0
				})

			cmdCharacteristic.HandleNotifyFunc(
				func(r gatt.Request, n gatt.Notifier) {
					b.cmdNotifierMtx.Lock()
					b.cmdNotifier = n
					b.cmdNotifierMtx.Unlock()
					log.Infof("pkg bluetooth; handling CMD notifications on new connection from:  %s", r.Central.ID())
				})

			// Mode-branch the data characteristic UUID: Dash keeps the 2442
			// value from origin/main, O5 uses 2443 per OmnipodKit. The
			// notify/write callbacks are identical for both modes — the
			// transport (Commit D) and command dispatcher (Commit E) will
			// branch on b.IsO5() where they need to.
			dataCharUUID := dashDataCharUUID
			if b.IsO5() {
				dataCharUUID = o5DataCharUUID
			}
			dataCharacteristic := s.AddCharacteristic(dataCharUUID)
			dataCharacteristic.HandleNotifyFunc(
				func(r gatt.Request, n gatt.Notifier) {
					b.dataNotifierMtx.Lock()
					b.dataNotifier = n
					b.dataNotifierMtx.Unlock()
					log.Infof("pkg bluetooth; handling DATA notifications on new connection from: %s", r.Central.ID())
					log.Infof("     *** OK to send commands from the phone app ***")
				})

			dataCharacteristic.HandleWriteFunc(
				func(r gatt.Request, data []byte) (status byte) {
					log.Tracef("pkg bluetooth; received DATA,%x, -- %d", data, len(data))
					ret := make([]byte, len(data))
					copy(ret, data)
					b.dataInput <- Packet(ret)
					return 0
				})

			// Mode-branch the GATT registration call. Dash uses the singular
			// AddService form from origin/main and does NOT expose the
			// heartbeat service. O5 builds the heartbeat service and
			// registers both via SetServices, matching the OmnipodKit shape.
			if b.IsO5() {
				h := gatt.NewService(heartbeatServiceUUID)
				hbCharacteristic := h.AddCharacteristic(heartbeatCharUUID)
				hbCharacteristic.HandleNotifyFunc(
					func(r gatt.Request, n gatt.Notifier) {
						b.heartbeatNotifierMtx.Lock()
						b.heartbeatNotifier = n
						b.heartbeatNotifierMtx.Unlock()
						log.Infof("pkg bluetooth; handling heartbeat notifications on new connection from: %s", r.Central.ID())
					})

				err = d.SetServices([]*gatt.Service{s, h})
				if err != nil {
					log.Fatalf("pkg bluetooth; could not add service: %s", err)
				}
			} else {
				err = d.AddService(s)
				if err != nil {
					log.Fatalf("pkg bluetooth; could not add service: %s", err)
				}
			}

			// Mode-branch the advertisement so DASH stays byte-for-byte
			// identical to origin/main (which is what existing Dash scanners
			// match against) while O5 keeps the OmnipodKit-shaped name,
			// 128-bit UUID list, and the manufacturer-data payload that real
			// pods co-advertise.
			var advertiseErr error
			var advertisedName string
			var advertisedUUIDCount int
			var advertisedMfg []byte
			if b.IsO5() {
				advertiseErr = b.advertiseO5(d, podId)
				// Mirror the name/uuid-count computation from advertiseO5 so
				// the startup log matches what was actually advertised.
				idHex := "FFFFFFFE"
				if podId != nil {
					idHex = strings.ToUpper(hex.EncodeToString(podId))
				}
				advertisedName = "AP " + idHex + " 0A95B6110002761B"
				advertisedUUIDCount = 2
				advertisedMfg = o5MfgData
			} else {
				advertiseErr = b.advertiseDash(d, podId)
				advertisedName = dashAdvertiseName
				advertisedUUIDCount = 9
				advertisedMfg = nil
			}
			if advertiseErr != nil {
				log.Fatalf("pkg bluetooth; advertise: %s", advertiseErr)
			}
			// mfg_data is logged hex-encoded so a Pi btmon capture can be
			// correlated against the bytes we asked paypal/gatt to emit.
			// Dash leaves it empty; O5 prints the 7-byte payload.
			log.Infof("pkg bluetooth; advertising name=%q uuid_count=%d mfg_data=%s", advertisedName, advertisedUUIDCount, hex.EncodeToString(advertisedMfg))
		default:
		}
	}
	err = d.Init(onStateChanged)
	if err != nil {
		log.Fatalf("pkg bluetooth; could not init bluetooth: %s", err)
	}
	return b, nil
}

func (b *Ble) RefreshAdvertisingWithSpecifiedId(id []byte) error { // 4 bytes, first 2 usually empty
	log.Debugf("RefreshAdvertisingWithSpecifiedId %x", id)
	// Looking at the paypal/gatt source code, we don't need to call
	// StopAdvertising, but just call AdvertiseNameAndServices and it should
	// update. Mode-branch the actual payload so DASH refreshes match
	// origin/main byte-for-byte while O5 keeps the OmnipodKit-shaped form.
	var err error
	if b.IsO5() {
		err = b.refreshO5(*b.device, id)
	} else {
		err = b.refreshDash(*b.device, id)
	}
	if err != nil {
		log.Infof("pkg bluetooth; could not re-advertise: %s", err)
	}
	return err
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

// ReadCmd blocks until the next pairing-state command byte arrives on the
// CMD characteristic. On Dash this is origin/main's behavior: every CMD
// write is funnelled through cmdInput, including the single-byte RTS that
// StartAcceptingCommands waits for. On O5 the dispatcher splits multi-byte
// activation frames (HELLO = 06 01 04 + 4-byte controller ID, PAIR_STATUS,
// INCORRECT, …) onto cmdActivation while RTS/CTS/SUCCESS/NACK/FAIL stay on
// cmdInput for the message loop's fragmentation handshake.
func (b *Ble) ReadCmd() (Packet, error) {
	if b.IsO5() {
		packet := <-b.cmdActivation
		return packet, nil
	}
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

func (b *Ble) ReadMessageWithTimeout(d time.Duration) (*message.Message, bool) {
	select {
	case message := <-b.messageInput:
		return message, false
	case <-time.After(d):
		log.Debugf("ReadMessage timeout")
		return nil, true
	}
}

// ShutdownConnection drops the BLE link to the current central and stops
// the message loop so a subsequent StartAcceptingCommands can re-init the
// pipeline cleanly. Without the StopMessageLoop call here, restarting the
// loop later would fatal with "Messaging loop is already running".
func (b *Ble) ShutdownConnection() {
	if b.central != nil {
		(*b.central).Close()
	}
	b.StopMessageLoop()
}

func (b *Ble) WriteMessage(message *message.Message) {
	b.messageOutput <- message
}

// loop dispatches to a mode-specific transport reader/writer.
//
// Dash and Omnipod 5 use fundamentally different fragmentation framings on
// the wire, so the message loop has to be branched at the top: Dash uses the
// legacy hand-rolled 20-byte RTS/CTS/SUCCESS handshake from origin/main,
// while O5 uses the packet.Split/Join framing aligned with OmnipodKit.
// Branching once here keeps each transport's select self-contained and
// avoids a hot-path b.IsO5() check per case.
func (b *Ble) loop(stop chan bool) {
	if b.IsO5() {
		b.loopO5(stop)
	} else {
		b.loopDash(stop)
	}
}

// loopDash is the legacy origin/main message loop: outgoing messages go
// through writeMessage (20-byte RTS/CTS fragments) and incoming messages are
// reassembled by readMessage (which consumes data fragments from b.dataInput
// inline via b.ReadData() during the RTS handshake). There is intentionally
// NO `case data := <-b.dataInput` here — on Dash, the data characteristic's
// fragments are pulled by readMessage, not by the loop's select.
func (b *Ble) loopDash(stop chan bool) {
	for {
		select {
		case <-stop:
			return
		case msg := <-b.messageOutput:
			b.writeMessage(msg)
		case cmd := <-b.cmdInput:
			msg, err := b.readMessage(cmd)
			if err != nil {
				log.Fatalf("pkg bluetooth; error reading message: %s", err)
			}
			if msg != nil {
				b.messageInput <- msg
			}
		}
	}
}

// loopO5 is the Omnipod 5 message loop: outgoing messages go through
// writeMessageData (packet.Split, up to 244-byte fragments) and incoming
// data fragments arrive on b.dataInput where readMessageData / packet.Join
// reassembles them. The cmdInput case is kept as a fallback for any RTS-like
// signal byte that slips through; readMessage warns and returns nil for
// non-RTS bytes (added in Commit 9), so this never fatals on stray cmd
// bytes — and on O5 the phone is not expected to send RTS at all.
func (b *Ble) loopO5(stop chan bool) {
	for {
		select {
		case <-stop:
			return
		case msg := <-b.messageOutput:
			b.writeMessageData(msg)
		case data := <-b.dataInput:
			msg, err := b.readMessageData(data)
			if err != nil {
				log.Fatalf("pkg bluetooth; error reading message: %s", err)
			}
			b.messageInput <- msg
		case cmd := <-b.cmdInput:
			msg, err := b.readMessage(cmd)
			if err != nil {
				log.Fatalf("pkg bluetooth; error reading message: %s", err)
			}
			if msg != nil {
				b.messageInput <- msg
			}
		}
	}
}

func (b *Ble) StartMessageLoop() {
	if b.stopLoop != nil {
		log.Fatalf("pkg bluetooth; Messaging loop is already running")
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

// writeMessageData fragments msg through pkg/bluetooth/packet (OmnipodKit's
// authoritative split format) and pushes each fragment to the DATA
// characteristic. This is the path used by the live loop for all message
// writes — including the large get-status-type-1/3/5 responses preserved
// from main commit 79be48c. The packet subpackage's Split tests cover
// SPS2.1- and SPS2-sized payloads, so the large-message handling that
// 79be48c added to the old hand-rolled byte fragmentation in writeMessage
// is supplied here by the tested Split implementation.
func (b *Ble) writeMessageData(msg *message.Message) {
	payload, err := msg.Marshal()
	if err != nil {
		log.Fatalf("pkg bluetooth; could not marshal the message %s", err)
	}
	log.Debugf("pkg bluetooth; sending message (%d bytes): %x", len(payload), payload)

	packets := packet.Split(payload)
	log.Debugf("pkg bluetooth; split into %d BLE fragment(s)", len(packets))

	for i, pkt := range packets {
		log.Tracef("pkg bluetooth; writing fragment %d/%d (%d bytes)", i+1, len(packets), len(pkt))
		var buf bytes.Buffer
		buf.Write(pkt)
		b.writeDataBuffer(&buf)
	}
}

// writeMessage is the legacy Dash-shaped fragmenter retained from origin/main.
// It is no longer invoked by the message loop (writeMessageData is used
// instead), but is kept here for any future caller that wants the old
// RTS/CTS/SUCCESS handshake. The byte→int index conversion from commit
// 79be48c is preserved verbatim so the type 1/3/5 / large-message overflow
// fix still applies if anything calls this.
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
		buf.WriteByte(0) // fragments

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

// readMessageData reassembles fragments arriving on the DATA characteristic
// using pkg/bluetooth/packet.Join. This replaces the old hand-rolled
// fragmentation reader; the OmnipodKit-aligned reassembler bounds each
// fragment read to its own declared length so smaller-than-244 MTUs still
// work, which subsumes the large-message read robustness work in 79be48c.
func (b *Ble) readMessageData(data Packet) (*message.Message, error) {
	return b.parsePackets(data)
}

func (b *Ble) parsePackets(first Packet) (*message.Message, error) {
	log.Debugf("pkg bluetooth; reassembling, first fragment %d bytes: %x", len(first), first)
	bytesOut, err := packet.Join(first, func() ([]byte, error) {
		pkt, e := b.ReadData()
		if e == nil {
			log.Tracef("pkg bluetooth; got next fragment %d bytes: %x", len(pkt), []byte(pkt))
		}
		return pkt, e
	})
	if err != nil {
		log.Warnf("pkg bluetooth; reassembly failed: %s", err)
		b.WriteCmd(CmdFail)
		return nil, err
	}
	log.Debugf("pkg bluetooth; reassembled %d-byte message", len(bytesOut))

	b.WriteCmd(CmdSuccess)

	msg, mErr := message.Unmarshal(bytesOut)
	log.Tracef("pkg bluetooth; received message: %s", spew.Sdump(msg))
	return msg, mErr
}

// readMessage is the legacy RTS-driven read path retained from origin/main.
// With the new loop wiring (dataInput is consumed directly by
// readMessageData) this function only runs when an RTS arrives on the CMD
// characteristic. HELLO / PAIR_STATUS / INCORRECT and other multi-byte
// activation bytes are routed to cmdActivation by the CMD-char write
// handler, so they should never reach here; if one does (e.g. a
// misclassified future OmnipodKit signal), warn and ignore rather than
// fatal so the loop survives.
func (b *Ble) readMessage(cmd Packet) (*message.Message, error) {
	var buf bytes.Buffer
	var checksum []byte

	if !bytes.Equal(CmdRTS[:1], cmd[:1]) {
		// HELLO / PAIR_STATUS / etc. are routed to cmdActivation by the
		// CMD char write handler, so seeing one here means it slipped
		// through the dispatcher (e.g. a multi-byte signal misclassified).
		// Log and ignore rather than fatal — the activation-path consumer
		// (StartActivation's ReadCmd) will pick it up if relevant.
		log.Warnf("pkg bluetooth; readMessage saw unexpected cmd byte 0x%02x; ignoring", cmd[0])
		return nil, nil
	}
	log.Trace("pkg bluetooth; Reading RTS, sending CTS")

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
