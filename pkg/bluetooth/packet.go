package bluetooth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// Layout is how a message is cut into BLE packets, a port of OmnipodKit's
// BlePacketLayout / PayloadSplitter / PayloadJoiner. The first packet has
// the fragment count, the last one the payload size and CRC32, and a
// payload that does not fit the last packet spills into one more; only the
// packet size differs between a DASH pod (20 bytes) and an Omnipod 5 (244).
type Layout struct {
	MaxPayloadSize int
	MaxFragments   int

	firstHeaderWithoutMiddle int // index, fragments=0, crc32, size
	firstHeaderWithMiddle    int // index, fragments
	lastHeader               int // index, size, crc32
}

const extraHeader = 2 // index, size

var (
	DashLayout = Layout{MaxPayloadSize: 20, MaxFragments: 15, firstHeaderWithoutMiddle: 7, firstHeaderWithMiddle: 2, lastHeader: 6}
	O5Layout   = Layout{MaxPayloadSize: 244, MaxFragments: 15, firstHeaderWithoutMiddle: 7, firstHeaderWithMiddle: 2, lastHeader: 6}
)

func (l Layout) firstCapacityWithoutMiddle() int {
	return l.MaxPayloadSize - l.firstHeaderWithoutMiddle
}
func (l Layout) firstCapacityWithMiddle() int { return l.MaxPayloadSize - l.firstHeaderWithMiddle }
func (l Layout) middleCapacity() int          { return l.MaxPayloadSize - 1 }
func (l Layout) lastCapacity() int            { return l.MaxPayloadSize - l.lastHeader }

func crc32Bytes(payload []byte) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], crc32.ChecksumIEEE(payload))
	return b[:]
}

func padTo(b []byte, n int) []byte {
	for len(b) < n {
		b = append(b, 0)
	}
	return b
}

// Split cuts a marshalled message into the packets to write, in order.
func (l Layout) Split(payload []byte) []Packet {
	if len(payload) <= l.firstCapacityWithMiddle() {
		return l.splitInOnePacket(payload)
	}
	crc := crc32Bytes(payload)
	first := l.firstCapacityWithMiddle()
	middle := l.middleCapacity()
	middleFragments := (len(payload) - first) / middle
	rest := len(payload) - middleFragments*middle - first

	var packets []Packet
	packets = append(packets, append(Packet{0, byte(middleFragments + 1)}, payload[:first]...))
	for i := 1; i <= middleFragments; i++ {
		start := first + (i-1)*middle
		packets = append(packets, append(Packet{byte(i)}, payload[start:start+middle]...))
	}
	lastStart := first + middleFragments*middle
	end := rest
	if end > l.lastCapacity() {
		end = l.lastCapacity()
	}
	last := append(Packet{byte(middleFragments + 1), byte(rest)}, crc...)
	last = append(last, payload[lastStart:lastStart+end]...)
	packets = append(packets, padTo(last, l.MaxPayloadSize))
	if rest > l.lastCapacity() {
		extra := append(Packet{byte(middleFragments + 2), byte(rest - l.lastCapacity())}, payload[lastStart+l.lastCapacity():]...)
		packets = append(packets, padTo(extra, l.MaxPayloadSize))
	}
	return packets
}

func (l Layout) splitInOnePacket(payload []byte) []Packet {
	end := len(payload)
	if end > l.firstCapacityWithoutMiddle() {
		end = l.firstCapacityWithoutMiddle()
	}
	first := append(Packet{0, 0}, crc32Bytes(payload)...)
	first = append(first, byte(len(payload)))
	first = append(first, payload[:end]...)
	packets := []Packet{first}
	if len(payload) > end {
		extra := append(Packet{1, byte(len(payload) - end)}, payload[end:]...)
		packets = append(packets, padTo(extra, l.MaxPayloadSize))
	}
	return packets
}

// IndexError is a packet out of sequence; the pod answers it with a NACK
// naming the index it expected.
type IndexError struct {
	Expected byte
	Got      byte
}

func (e *IndexError) Error() string {
	return fmt.Sprintf("packet index %d, expected %d", e.Got, e.Expected)
}

var ErrCRC = errors.New("CRC32 mismatch")

// Join reads a message that starts with first, taking the rest of its
// packets from next, and checks the CRC32.
func (l Layout) Join(first Packet, next func() (Packet, error)) ([]byte, error) {
	if len(first) < l.firstHeaderWithMiddle {
		return nil, fmt.Errorf("first packet %x too short", first)
	}
	if first[0] != 0 {
		return nil, &IndexError{Expected: 0, Got: first[0]}
	}
	fullFragments := int(first[1])
	if fullFragments > l.MaxFragments {
		return nil, fmt.Errorf("received more than %d fragments", l.MaxFragments)
	}
	if len(first) < l.firstHeaderWithoutMiddle {
		return nil, fmt.Errorf("first packet %x too short", first)
	}

	var payload, crc []byte
	oneExtra := false
	if fullFragments == 0 {
		size := int(first[6])
		end := size + l.firstHeaderWithoutMiddle
		if end > len(first) {
			end = len(first)
		}
		payload = append(payload, first[l.firstHeaderWithoutMiddle:end]...)
		crc = first[2:6]
		oneExtra = size+l.firstHeaderWithoutMiddle > end
	} else {
		if len(first) < l.MaxPayloadSize {
			return nil, fmt.Errorf("first packet of %d is %d bytes, not %d", fullFragments+1, len(first), l.MaxPayloadSize)
		}
		payload = append(payload, first[l.firstHeaderWithMiddle:l.MaxPayloadSize]...)
	}

	for index := 1; index <= fullFragments; index++ {
		p, err := next()
		if err != nil {
			return nil, err
		}
		if len(p) < 3 {
			return nil, fmt.Errorf("packet %x too short", p)
		}
		if int(p[0]) != index {
			return nil, &IndexError{Expected: byte(index), Got: p[0]}
		}
		if index < fullFragments {
			if len(p) < l.MaxPayloadSize {
				return nil, fmt.Errorf("packet %d is %d bytes, not %d", index, len(p), l.MaxPayloadSize)
			}
			payload = append(payload, p[1:l.MaxPayloadSize]...)
			continue
		}
		if len(p) < l.lastHeader {
			return nil, fmt.Errorf("last packet %x too short", p)
		}
		size := int(p[1])
		end := size + l.lastHeader
		if end > len(p) {
			end = len(p)
		}
		payload = append(payload, p[l.lastHeader:end]...)
		crc = p[2:6]
		oneExtra = size+l.lastHeader > end
	}

	if oneExtra {
		p, err := next()
		if err != nil {
			return nil, err
		}
		if len(p) < 3 {
			return nil, fmt.Errorf("packet %x too short", p)
		}
		if int(p[0]) != fullFragments+1 {
			return nil, &IndexError{Expected: byte(fullFragments + 1), Got: p[0]}
		}
		size := int(p[1])
		if len(p) < extraHeader+size {
			return nil, fmt.Errorf("extra packet %x is shorter than its %d bytes", p, size)
		}
		payload = append(payload, p[extraHeader:extraHeader+size]...)
	}

	if binary.BigEndian.Uint32(crc) != crc32.ChecksumIEEE(payload) {
		return payload, ErrCRC
	}
	return payload, nil
}
