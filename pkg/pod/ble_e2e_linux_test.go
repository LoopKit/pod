//go:build ble_e2e
// +build ble_e2e

package pod

// TestOverTheAir runs the phone model against a pod binary on another
// Bluetooth adapter, over a real ATT connection, the way an iPhone talks to
// the pod on a Raspberry Pi. It needs Linux with two adapters, such as two
// virtual controllers from BlueZ's btvirt, the pod (-transport ble) on
// POD_ADDR and no bluetoothd; scripts/ble-e2e sets that up and runs it (see
// docs/BLE_E2E_TEST.md):
//
//	POD_ADDR=00:AA:01:00:00:00 POD_MODE=o5 PHONE_MTU=185 PHONE_SERVER_MTU=527 \
//	    ./pod_e2e.test -test.run TestOverTheAir -test.v
//
// PHONE_MTU is the MTU the phone offers as it connects ("none" to offer
// none); PHONE_SERVER_MTU is how it answers an exchange the pod starts: an
// MTU, "error" or "ignore"; PHONE_HCI is the phone's adapter (default 1).
// Like iOS, the phone cuts a write without response to MTU-3 bytes.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/mode"
	"golang.org/x/sys/unix"
)

const (
	attError      = 0x01
	attMTUReq     = 0x02
	attMTURsp     = 0x03
	attFindInfo   = 0x04
	attReadByType = 0x08
	attReadGroup  = 0x10
	attWriteReq   = 0x12
	attWriteRsp   = 0x13
	attNotify     = 0x1b
	attWriteCmd   = 0x52
)

// attLink is the phone's end of the ATT connection, and the radio of the
// phone's bluetooth.Ble.
type attLink struct {
	t  *testing.T
	fd int

	reqMu     sync.Mutex // one request at a time
	mu        sync.Mutex
	mtu       int
	pending   bool
	truncated int
	podErrors int // error PDUs the pod sent unasked

	rsp       chan []byte
	podAsked  chan int
	serverMTU string

	cmd, data         uint16 // value handles
	cmdCCCD, dataCCCD uint16
	writeType         byte
	phone             *bluetooth.Ble
	ready             chan bool // closed once phone is set
}

func le16(b []byte) int { return int(binary.LittleEndian.Uint16(b)) }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// powerOnLE turns on LE and power on the phone's adapter through the
// kernel's management socket, as btmgmt would: the kernel refuses an LE
// connection from an adapter without LE.
func powerOnLE(t *testing.T, index uint16) {
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.BTPROTO_HCI)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrHCI{Dev: 0xffff, Channel: unix.HCI_CHANNEL_CONTROL}); err != nil {
		t.Fatalf("binding the management socket: %v", err)
	}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5})
	for _, op := range []int{0x000d, 0x0005} { // Set Low Energy, Set Powered
		if _, err := unix.Write(fd, []byte{byte(op), byte(op >> 8), byte(index), byte(index >> 8), 1, 0, 1}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				t.Fatalf("management command %#04x: %v", op, err)
			}
			// Command Complete (1) or Status (2): opcode, status.
			if ev := le16(buf); n >= 9 && (ev == 1 || ev == 2) && le16(buf[6:]) == op {
				if buf[8] != 0 {
					t.Fatalf("management command %#04x on hci%d: status %#02x", op, index, buf[8])
				}
				break
			}
		}
	}
}

func dial(t *testing.T, addr string) *attLink {
	index, _ := strconv.Atoi(env("PHONE_HCI", "1"))
	powerOnLE(t, uint16(index))
	hw, err := net.ParseMAC(addr)
	if err != nil {
		t.Fatalf("POD_ADDR %q: %v", addr, err)
	}
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_SEQPACKET, unix.BTPROTO_L2CAP)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrL2{CID: 4, AddrType: unix.BDADDR_LE_PUBLIC}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	sa := &unix.SockaddrL2{CID: 4, AddrType: unix.BDADDR_LE_PUBLIC}
	copy(sa.Addr[:], hw)
	if err := unix.Connect(fd, sa); err != nil {
		t.Fatalf("connecting to %s: %v", addr, err)
	}
	l := &attLink{t: t, fd: fd, mtu: 23, rsp: make(chan []byte, 1), podAsked: make(chan int, 4),
		serverMTU: env("PHONE_SERVER_MTU", "527"), ready: make(chan bool)}
	t.Cleanup(func() { unix.Close(fd) })
	go l.read()
	return l
}

func (l *attLink) send(pdu []byte) {
	if _, err := unix.Write(l.fd, pdu); err != nil {
		l.t.Errorf("writing % x: %v", pdu, err)
	}
}

func (l *attLink) read() {
	buf := make([]byte, 1024)
	for {
		n, err := unix.Read(l.fd, buf)
		if err != nil || n == 0 {
			return
		}
		pdu := append([]byte{}, buf[:n]...)
		switch pdu[0] {
		case attNotify:
			<-l.ready
			h, v := uint16(le16(pdu[1:3])), bluetooth.Packet(pdu[3:])
			switch h {
			case l.cmd:
				l.phone.CmdWritten(v)
			case l.data:
				l.phone.DataWritten(v)
			}
		case attMTUReq:
			offer := le16(pdu[1:3])
			l.podAsked <- offer
			switch l.serverMTU {
			case "ignore":
			case "error":
				l.send([]byte{attError, attMTUReq, 0, 0, 0x06}) // request not supported
			default:
				rx, _ := strconv.Atoi(l.serverMTU)
				l.send([]byte{attMTURsp, byte(rx), byte(rx >> 8)})
				l.mu.Lock()
				if rx < offer {
					offer = rx
				}
				l.mtu = offer
				l.mu.Unlock()
			}
		default:
			l.mu.Lock()
			pending := l.pending
			if !pending && pdu[0] == attError {
				l.podErrors++
			}
			l.mu.Unlock()
			if pending {
				l.rsp <- pdu
			} else {
				l.t.Logf("unasked PDU from the pod: % x", pdu)
			}
		}
	}
}

// request sends a request and returns the pod's response. ATT allows one
// request at a time, so a request waits for the one before it, as iOS
// queues them.
func (l *attLink) request(pdu []byte) []byte {
	l.reqMu.Lock()
	defer l.reqMu.Unlock()
	l.mu.Lock()
	l.pending = true
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.pending = false
		l.mu.Unlock()
	}()
	l.send(pdu)
	select {
	case r := <-l.rsp:
		return r
	case <-time.After(3 * time.Second):
		l.t.Fatalf("no response to % x", pdu)
		return nil
	}
}

func (l *attLink) MTU() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.mtu
}

// write writes a value as OmnipodKit does: without response on an Omnipod
// 5, cut to MTU-3 bytes as iOS does; with response on DASH.
func (l *attLink) write(h uint16, v []byte) error {
	if max := l.MTU() - 3; len(v) > max {
		l.mu.Lock()
		l.truncated++
		l.mu.Unlock()
		v = v[:max]
	}
	pdu := append([]byte{l.writeType, byte(h), byte(h >> 8)}, v...)
	if l.writeType == attWriteCmd {
		l.send(pdu)
		return nil
	}
	if r := l.request(pdu); r[0] != attWriteRsp {
		return fmt.Errorf("write to %#04x answered % x", h, r)
	}
	return nil
}

func (l *attLink) NotifyCmd(p bluetooth.Packet) error         { return l.write(l.cmd, p) }
func (l *attLink) NotifyData(p bluetooth.Packet) error        { return l.write(l.data, p) }
func (l *attLink) Advertise([]byte) error                     { return nil }
func (l *attLink) AdvertiseState(bluetooth.AdvertState) error { return nil }
func (l *attLink) Disconnect()                                {}

// uuid128 is a 128-bit UUID as ATT carries it, little endian.
func uuid128(s string) []byte {
	b := unhex(stripDashes(s))
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func stripDashes(s string) string {
	return string(bytes.ReplaceAll([]byte(s), []byte("-"), nil))
}

// discover finds the pod service's command and data characteristics and
// their CCCDs, as CoreBluetooth's discovery would.
func (l *attLink) discover(m mode.Mode) {
	t := l.t
	service := uuid128("1A7E4024-E3ED-4464-8B7E-751E03D0DC5F")
	var start, end uint16
	for h := uint16(1); h != 0; {
		r := l.request([]byte{attReadGroup, byte(h), byte(h >> 8), 0xff, 0xff, 0x00, 0x28})
		if r[0] != attReadGroup+1 {
			break
		}
		size := int(r[1])
		for i := 2; i+size <= len(r); i += size {
			s, e := uint16(le16(r[i:])), uint16(le16(r[i+2:]))
			if bytes.Equal(r[i+4:i+size], service) {
				start, end = s, e
			}
			h = e + 1
		}
	}
	if start == 0 {
		t.Fatal("the pod service is not there")
	}
	data := "1A7E2442-E3ED-4464-8B7E-751E03D0DC5F"
	if m.IsO5() {
		data = "1A7E2443-E3ED-4464-8B7E-751E03D0DC5F"
	}
	cmdUUID, dataUUID := uuid128("1A7E2441-E3ED-4464-8B7E-751E03D0DC5F"), uuid128(data)
	for h := start; h <= end; {
		r := l.request([]byte{attReadByType, byte(h), byte(h >> 8), byte(end), byte(end >> 8), 0x03, 0x28})
		if r[0] != attReadByType+1 {
			break
		}
		size := int(r[1])
		for i := 2; i+size <= len(r); i += size {
			decl, value := uint16(le16(r[i:])), uint16(le16(r[i+3:]))
			switch {
			case bytes.Equal(r[i+5:i+size], cmdUUID):
				l.cmd = value
			case bytes.Equal(r[i+5:i+size], dataUUID):
				l.data = value
			}
			h = decl + 1
		}
	}
	if l.cmd == 0 || l.data == 0 {
		t.Fatalf("command %#04x, data %#04x: a characteristic is missing", l.cmd, l.data)
	}
	l.cmdCCCD, l.dataCCCD = l.cccd(l.cmd, end), l.cccd(l.data, end)
	t.Logf("service %#04x-%#04x; command %#04x (CCCD %#04x), data %#04x (CCCD %#04x)",
		start, end, l.cmd, l.cmdCCCD, l.data, l.dataCCCD)
}

func (l *attLink) cccd(value, end uint16) uint16 {
	h := value + 1
	r := l.request([]byte{attFindInfo, byte(h), byte(h >> 8), byte(end), byte(end >> 8)})
	if r[0] == attFindInfo+1 && r[1] == 1 {
		for i := 2; i+4 <= len(r); i += 4 {
			if le16(r[i+2:]) == 0x2902 {
				return uint16(le16(r[i:]))
			}
		}
	}
	l.t.Fatalf("no CCCD after %#04x", value)
	return 0
}

func (l *attLink) subscribe(cccd uint16) {
	if r := l.request([]byte{attWriteReq, byte(cccd), byte(cccd >> 8), 1, 0}); r[0] != attWriteRsp {
		l.t.Fatalf("subscribing at %#04x: % x", cccd, r)
	}
}

func podStatus(t *testing.T) Status {
	t.Helper()
	resp, err := http.Get(env("POD_API", "http://127.0.0.1:8080") + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var s Status
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func waitPodStatus(t *testing.T, ready func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := podStatus(t)
		if ready(s) || time.Now().After(deadline) {
			return s
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestOverTheAir(t *testing.T) {
	m, err := mode.Parse(env("POD_MODE", "o5"))
	if err != nil {
		t.Fatal(err)
	}
	l := dial(t, env("POD_ADDR", ""))
	l.writeType = attWriteReq
	if m.IsO5() {
		l.writeType = attWriteCmd
	}

	// iOS starts its own MTU exchange as it connects.
	if offer := env("PHONE_MTU", "185"); offer != "none" {
		mtu, _ := strconv.Atoi(offer)
		r := l.request([]byte{attMTUReq, byte(mtu), byte(mtu >> 8)})
		if r[0] != attMTURsp {
			t.Fatalf("MTU exchange answered % x", r)
		}
		if rx := le16(r[1:]); rx < mtu {
			mtu = rx
		}
		l.mu.Lock()
		l.mtu = mtu
		l.mu.Unlock()
		t.Logf("the phone offered %s; the pod answered %d; MTU %d", offer, le16(r[1:]), mtu)
	}
	select {
	case offer := <-l.podAsked:
		t.Logf("the pod asked for an MTU of %d; the phone answered %q", offer, l.serverMTU)
	case <-time.After(2 * time.Second):
		t.Logf("the pod did not start an MTU exchange")
	}
	time.Sleep(300 * time.Millisecond)
	if l.podErrors != 0 {
		t.Errorf("the pod sent %d unasked error PDU(s)", l.podErrors)
	}
	t.Logf("ATT MTU %d: the phone writes at most %d bytes", l.MTU(), l.MTU()-3)

	l.discover(m)
	phoneBle, err := bluetooth.New(m, func(*bluetooth.Ble) (bluetooth.Radio, error) { return l, nil })
	if err != nil {
		t.Fatal(err)
	}
	l.phone = phoneBle
	close(l.ready)
	phoneBle.Connected()
	// OmnipodKit says HELLO, then enables notifications.
	if err := l.write(l.cmd, append([]byte{6, 1, 4}, testController...)); err != nil {
		t.Fatal(err)
	}
	l.subscribe(l.cmdCCCD)
	l.subscribe(l.dataCCCD)
	phoneBle.StartMessageLoop()

	ph := &phone{t: t, m: m, ble: phoneBle, controllerID: testController, podID: testPodID, msgSeq: 1}
	ph.signingKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	defer func() { t.Logf("writes cut short: %d", l.truncated) }()

	ph.pair()
	t.Logf("paired")
	ph.session(2)
	t.Logf("session established")

	ph.msgSeq = 10
	blocks := ph.command(unhex("ffffffff"), 0, unhex("0704ffffffff"), false)
	if blocks[0] != 0x01 || blocks[1] != 0x15 || blocks[8] != m.ProductID() {
		t.Fatalf("AssignAddress answered %x", blocks)
	}
	if m.IsO5() {
		for _, tc := range []struct{ send, want string }{
			{"53453235352e323d31373830323134373932", "45533235352e323d30"},
			{"53332e323d0003000e002c47332e32", "332e323d0003000e00"},
			{"53332e393d382c47332e39", "332e393d38"},
			{"53332e373d333637303031352c47332e37", "332e373d33363730303135"},
		} {
			if got := ph.exchange(unhex(tc.send), false); !bytes.Equal(got, unhex(tc.want)) {
				t.Fatalf("AID %x answered %q", tc.send, got)
			}
		}
		history := append(unhex("5345322e313d00a8"), make([]byte, 168)...)
		if got := ph.exchange(history, false); string(got) != "ES2.1=0" {
			t.Fatalf("insulin history answered %q", got)
		}
	}
	setup := append(unhex("0313"), ph.podID...)
	setup = append(setup, make([]byte, 15)...)
	blocks = ph.command(unhex("ffffffff"), 1, setup, false)
	if blocks[0] != 0x01 || blocks[1] != 0x1b || !bytes.Equal(blocks[25:29], ph.podID) {
		t.Fatalf("SetupPod answered %x", blocks)
	}
	blocks = ph.command(ph.podID, 2, unhex("0e0100"), false)
	if blocks[0] != 0x1d {
		t.Fatalf("GetStatus answered %x", blocks)
	}
	if m.IsO5() {
		blocks = ph.command(ph.podID, 3, ph.bolusBlocks(), false)
		if !bytes.Equal(blocks, []byte{0x06, 0x03, 0x2a, 0x00, 0x03}) {
			t.Fatalf("an unsigned bolus answered %x", blocks)
		}
	}
	blocks = ph.command(ph.podID, 4, ph.bolusBlocks(), m.IsO5())
	if blocks[0] != 0x1d || blocks[1]>>4&0x4 == 0 {
		t.Fatalf("the bolus answered %x", blocks)
	}
	s := waitPodStatus(t, func(s Status) bool { return s.BolusActive })
	if !s.BolusActive || s.Mode != string(m) || (m.IsO5() && s.BadSignatures != 1) {
		t.Fatalf("status %+v", s)
	}
	t.Logf("ran: %s, bolus active, %d signed command(s) rejected", s.ModeName, s.BadSignatures)
}
