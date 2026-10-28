package bluetooth

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// A pod message is carried over BLE as a run of fixed-size packets. Both
// sides build and read them the same way; OmnipodKit's PayloadSplitter,
// PayloadJoiner and BLEPacket are the reference, and its BlePacketLayout
// is what differs between a DASH pod and an Omnipod 5 (20-byte packets
// against 244-byte ones).
type PacketLayout struct {
	MaxPayloadSize int
	MaxFragments   int

	FirstHeaderWithoutMiddle int
	FirstHeaderWithMiddle    int
	LastHeader               int
}

// The capacities each kind of packet leaves for message bytes.
func (l PacketLayout) firstCapWithoutMiddle() int {
	return l.MaxPayloadSize - l.FirstHeaderWithoutMiddle
}
func (l PacketLayout) firstCapWithMiddle() int { return l.MaxPayloadSize - l.FirstHeaderWithMiddle }
func (l PacketLayout) middleCap() int          { return l.MaxPayloadSize - 1 }
func (l PacketLayout) lastCap() int            { return l.MaxPayloadSize - l.LastHeader }

// Split cuts a message into the packets to write, in order.
func (l PacketLayout) Split(payload []byte) []Packet {
	sum := make([]byte, 4)
	binary.BigEndian.PutUint32(sum, crc32.ChecksumIEEE(payload))

	// Short enough for one packet, plus at most one carrying the remainder.
	if len(payload) <= l.firstCapWithMiddle() {
		end := min(l.firstCapWithoutMiddle(), len(payload))
		first := make([]byte, 0, l.FirstHeaderWithoutMiddle+end)
		first = append(first, 0, 0) // index, no full fragments
		first = append(first, sum...)
		first = append(first, byte(len(payload)))
		first = append(first, payload[:end]...)
		packets := []Packet{first}
		if len(payload) > end {
			packets = append(packets, l.plusOne(1, payload[end:]))
		}
		return packets
	}

	middles := (len(payload) - l.firstCapWithMiddle()) / l.middleCap()
	rest := len(payload) - middles*l.middleCap() - l.firstCapWithMiddle()

	first := make([]byte, 0, l.MaxPayloadSize)
	first = append(first, 0, byte(middles+1))
	first = append(first, payload[:l.firstCapWithMiddle()]...)
	packets := []Packet{first}

	for i := 1; i <= middles; i++ {
		from := l.firstCapWithMiddle() + (i-1)*l.middleCap()
		mid := make([]byte, 0, l.MaxPayloadSize)
		mid = append(mid, byte(i))
		mid = append(mid, payload[from:from+l.middleCap()]...)
		packets = append(packets, mid)
	}

	tail := l.firstCapWithMiddle() + middles*l.middleCap()
	end := min(l.lastCap(), rest)
	last := make([]byte, 0, l.MaxPayloadSize)
	last = append(last, byte(middles+1), byte(rest))
	last = append(last, sum...)
	last = append(last, payload[tail:tail+end]...)
	last = append(last, make([]byte, l.MaxPayloadSize-end-l.LastHeader)...)
	packets = append(packets, last)

	if rest > l.lastCap() {
		packets = append(packets, l.plusOne(byte(middles+2), payload[tail+l.lastCap():]))
	}
	return packets
}

// plusOne is the optional extra packet that carries what would not fit in
// a first or last packet (OmnipodKit's LastOptionalPlusOneBlePacket).
func (l PacketLayout) plusOne(index byte, payload []byte) Packet {
	p := make([]byte, 0, l.MaxPayloadSize)
	p = append(p, index, byte(len(payload)))
	p = append(p, payload...)
	return append(p, make([]byte, l.MaxPayloadSize-len(payload)-2)...)
}

// Joiner reassembles a message from the packets the phone writes.
type Joiner struct {
	layout        PacketLayout
	body          []byte
	sum           []byte
	fullFragments int
	plusOne       bool
	seen          int
}

// NewJoiner starts on the first packet of a message.
func NewJoiner(first Packet, layout PacketLayout) (*Joiner, error) {
	if len(first) < layout.FirstHeaderWithMiddle {
		return nil, fmt.Errorf("first packet is %d bytes, too short to read", len(first))
	}
	if first[0] != 0 {
		return nil, fmt.Errorf("first packet has index %d, want 0", first[0])
	}
	fragments := int(first[1])
	if fragments > layout.MaxFragments {
		return nil, fmt.Errorf("first packet claims %d fragments, more than %d", fragments, layout.MaxFragments)
	}
	if len(first) < layout.FirstHeaderWithoutMiddle {
		return nil, fmt.Errorf("first packet is %d bytes, too short to read", len(first))
	}

	j := &Joiner{layout: layout, fullFragments: fragments}
	if fragments == 0 {
		size := int(first[6])
		end := min(size+layout.FirstHeaderWithoutMiddle, len(first))
		j.sum = append([]byte(nil), first[2:6]...)
		j.body = append(j.body, first[layout.FirstHeaderWithoutMiddle:end]...)
		j.plusOne = size+layout.FirstHeaderWithoutMiddle > end
		return j, nil
	}
	if len(first) < layout.MaxPayloadSize {
		return nil, fmt.Errorf("first packet of a run is %d bytes, want %d", len(first), layout.MaxPayloadSize)
	}
	j.body = append(j.body, first[layout.FirstHeaderWithMiddle:layout.MaxPayloadSize]...)
	return j, nil
}

// More says whether the message needs another packet.
func (j *Joiner) More() bool {
	return j.seen < j.fullFragments || (j.plusOne && j.seen < j.fullFragments+1)
}

// Accumulate takes the next packet of the message.
func (j *Joiner) Accumulate(p Packet) error {
	if len(p) < 3 {
		return fmt.Errorf("packet is %d bytes, too short to read", len(p))
	}
	index := int(p[0])
	if index != j.seen+1 {
		return fmt.Errorf("packet has index %d, want %d", index, j.seen+1)
	}
	j.seen = index

	switch {
	case index < j.fullFragments:
		if len(p) < j.layout.MaxPayloadSize {
			return fmt.Errorf("middle packet is %d bytes, want %d", len(p), j.layout.MaxPayloadSize)
		}
		j.body = append(j.body, p[1:j.layout.MaxPayloadSize]...)
	case index == j.fullFragments:
		if len(p) < j.layout.LastHeader {
			return fmt.Errorf("last packet is %d bytes, too short to read", len(p))
		}
		size := int(p[1])
		end := min(size+j.layout.LastHeader, len(p))
		j.sum = append([]byte(nil), p[2:6]...)
		j.body = append(j.body, p[j.layout.LastHeader:end]...)
		j.plusOne = size+j.layout.LastHeader > end
	case index == j.fullFragments+1 && j.plusOne:
		size := int(p[1])
		if len(p) < 2+size {
			return fmt.Errorf("extra packet holds %d bytes, less than the %d it claims", len(p)-2, size)
		}
		j.body = append(j.body, p[2:2+size]...)
	default:
		return fmt.Errorf("packet has index %d, past the %d fragments of this message", index, j.fullFragments)
	}
	return nil
}

// Finalize returns the message once every packet has arrived.
func (j *Joiner) Finalize() ([]byte, error) {
	if j.sum == nil {
		return nil, fmt.Errorf("the message never carried a checksum")
	}
	if want, got := binary.BigEndian.Uint32(j.sum), crc32.ChecksumIEEE(j.body); want != got {
		return nil, fmt.Errorf("message checksum is %08x, want %08x", got, want)
	}
	return j.body, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
