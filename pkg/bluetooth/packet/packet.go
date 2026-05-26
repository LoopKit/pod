// Package packet implements the BLE packet split/join used by the Omnipod 5
// (and Dash) BLE protocol. Sources of truth:
//   - OmnipodKit/Bluetooth/Packet/PayloadSplitter.swift
//   - OmnipodKit/Bluetooth/Packet/PayloadJoiner.swift
//   - OmnipodKit/Bluetooth/Packet/BLEPacket.swift
//   - OmnipodKit/Bluetooth/BlePodProfile.swift
//
// Lives in its own subpackage so the pure split/join logic can be unit-tested
// on any host (the parent bluetooth package imports paypal/gatt which is
// Linux-only).
package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"

	log "github.com/sirupsen/logrus"
)

// BLE packet layout used by Omnipod 5 (and Dash, with a different MTU).
// Header sizes are identical between Dash and O5; only MaxPayloadSize differs
// (20 for Dash, 244 for O5).
const (
	MaxPayloadSize                  = 244
	FirstPacketHeaderWithoutMiddle  = 7 // idx(1) + fullFragments(1) + crc32(4) + size(1)
	FirstPacketHeaderWithMiddle     = 2 // idx(1) + fullFragments(1)
	MiddlePacketHeader              = 1 // idx(1)
	LastPacketHeader                = 6 // idx(1) + size(1) + crc32(4)
	LastOptionalPlusOnePacketHeader = 2 // idx(1) + size(1)
)

func firstPacketCapacityWithoutMiddle() int { return MaxPayloadSize - FirstPacketHeaderWithoutMiddle }
func firstPacketCapacityWithMiddle() int    { return MaxPayloadSize - FirstPacketHeaderWithMiddle }
func middlePacketCapacity() int             { return MaxPayloadSize - MiddlePacketHeader }
func lastPacketCapacity() int               { return MaxPayloadSize - LastPacketHeader }

// Split fragments a Marshal'd TWi message into the BLE packets the O5
// protocol expects. The wire layout matches OmnipodKit's PayloadSplitter.
func Split(payload []byte) [][]byte {
	first := firstPacketCapacityWithMiddle()
	if len(payload) <= firstPacketCapacityWithoutMiddle() {
		return splitOne(payload)
	}
	mid := middlePacketCapacity()
	last := lastPacketCapacity()

	middleFragments := (len(payload) - first) / mid
	rest := byte(len(payload) - middleFragments*mid - first)

	sum := crc32.ChecksumIEEE(payload)

	out := make([][]byte, 0, middleFragments+3)

	// First fragment: [0][fullFragments][payload[0..242]]
	{
		buf := make([]byte, 0, MaxPayloadSize)
		buf = append(buf, 0)
		buf = append(buf, byte(middleFragments+1))
		buf = append(buf, payload[:first]...)
		out = append(out, buf)
	}

	// Middle fragments: [idx][payload[..243]]
	for i := 1; i <= middleFragments; i++ {
		start := first + (i-1)*mid
		end := start + mid
		buf := make([]byte, 0, MaxPayloadSize)
		buf = append(buf, byte(i))
		buf = append(buf, payload[start:end]...)
		out = append(out, buf)
	}

	// Last fragment: [idx][size][crc32(4)][payload (up to 238B)] [zero pad to MTU]
	lastIdx := byte(middleFragments + 1)
	lastStart := first + middleFragments*mid
	endInLast := int(rest)
	if endInLast > last {
		endInLast = last
	}
	{
		buf := make([]byte, 0, MaxPayloadSize)
		buf = append(buf, lastIdx)
		buf = append(buf, rest)
		var crcBytes [4]byte
		binary.BigEndian.PutUint32(crcBytes[:], sum)
		buf = append(buf, crcBytes[:]...)
		buf = append(buf, payload[lastStart:lastStart+endInLast]...)
		// Zero-pad to MaxPayloadSize so the wire write matches MTU exactly,
		// matching OmnipodKit's LastBlePacket.toData (it pads the difference).
		if pad := MaxPayloadSize - len(buf); pad > 0 {
			buf = append(buf, make([]byte, pad)...)
		}
		out = append(out, buf)
	}

	// Optional last+1: [idx+1][size][payload tail] [zero pad]
	if int(rest) > last {
		extraSize := byte(int(rest) - last)
		buf := make([]byte, 0, MaxPayloadSize)
		buf = append(buf, lastIdx+1)
		buf = append(buf, extraSize)
		extraStart := lastStart + last
		buf = append(buf, payload[extraStart:]...)
		if pad := MaxPayloadSize - len(buf); pad > 0 {
			buf = append(buf, make([]byte, pad)...)
		}
		out = append(out, buf)
	}

	return out
}

// splitPayloadOne builds the single-packet wire form (and an optional
// extra-packet continuation when the payload is small but doesn't fit in
// the first packet's capacity). Mirrors PayloadSplitter.splitInOnePacket.
func splitOne(payload []byte) [][]byte {
	cap := firstPacketCapacityWithoutMiddle()
	end := len(payload)
	if end > cap {
		end = cap
	}
	sum := crc32.ChecksumIEEE(payload)

	// First packet: [0][0][crc32(4)][size(1)][payload[0..end]] [zero pad]
	first := make([]byte, 0, MaxPayloadSize)
	first = append(first, 0)
	first = append(first, 0) // fullFragments == 0 means single-packet
	var crcBytes [4]byte
	binary.BigEndian.PutUint32(crcBytes[:], sum)
	first = append(first, crcBytes[:]...)
	first = append(first, byte(len(payload)))
	first = append(first, payload[:end]...)
	if pad := MaxPayloadSize - len(first); pad > 0 {
		first = append(first, make([]byte, pad)...)
	}

	out := [][]byte{first}

	if len(payload) > cap {
		// LastOptionalPlusOne: [1][size of tail][payload tail] [zero pad]
		extraSize := byte(len(payload) - cap)
		buf := make([]byte, 0, MaxPayloadSize)
		buf = append(buf, 1)
		buf = append(buf, extraSize)
		buf = append(buf, payload[cap:]...)
		if pad := MaxPayloadSize - len(buf); pad > 0 {
			buf = append(buf, make([]byte, pad)...)
		}
		out = append(out, buf)
	}

	return out
}

// joinPackets reassembles a complete TWi message from BLE fragments using
// the OmnipodKit on-wire format. `first` is the initial fragment already
// pulled off the data channel; `nextFragment` is called to read each
// subsequent fragment.
func Join(first []byte, nextFragment func() ([]byte, error)) ([]byte, error) {
	if len(first) < FirstPacketHeaderWithMiddle {
		return nil, fmt.Errorf("first fragment too short: %d bytes", len(first))
	}
	if first[0] != 0 {
		return nil, fmt.Errorf("first fragment idx %d, want 0", first[0])
	}
	fullFragments := int(first[1])

	var buf bytes.Buffer
	var crc []byte
	var oneExtraBytes int

	if fullFragments == 0 {
		// Single-packet form
		if len(first) < FirstPacketHeaderWithoutMiddle {
			return nil, fmt.Errorf("single-packet first fragment too short: %d", len(first))
		}
		crc = append(crc, first[2:6]...)
		size := int(first[6])
		cap := firstPacketCapacityWithoutMiddle()
		take := size
		if take > cap {
			take = cap
			oneExtraBytes = size - cap
		}
		end := FirstPacketHeaderWithoutMiddle + take
		if end > len(first) {
			return nil, fmt.Errorf("single-packet first fragment truncated: need %d, have %d", end, len(first))
		}
		buf.Write(first[FirstPacketHeaderWithoutMiddle:end])
	} else {
		// Multi-packet first: copy from offset 2 up to MTU.
		end := MaxPayloadSize
		if end > len(first) {
			end = len(first)
		}
		buf.Write(first[FirstPacketHeaderWithMiddle:end])
	}

	expectedIdx := 1
	for i := 1; i <= fullFragments; i++ {
		pkt, err := nextFragment()
		if err != nil {
			return nil, fmt.Errorf("fragment %d read: %w", i, err)
		}
		if len(pkt) < 1 {
			return nil, fmt.Errorf("fragment %d empty", i)
		}
		if int(pkt[0]) != expectedIdx {
			log.Warnf("pkg bluetooth; fragment idx mismatch: got %d, want %d", pkt[0], expectedIdx)
			return nil, fmt.Errorf("fragment idx mismatch")
		}
		if i == fullFragments {
			// Last packet
			if len(pkt) < LastPacketHeader {
				return nil, fmt.Errorf("last fragment too short: %d", len(pkt))
			}
			size := int(pkt[1])
			crc = append(crc[:0], pkt[2:6]...)
			cap := lastPacketCapacity()
			take := size
			if take > cap {
				take = cap
				oneExtraBytes = size - cap
			}
			end := LastPacketHeader + take
			if end > len(pkt) {
				return nil, fmt.Errorf("last fragment truncated: need %d, have %d", end, len(pkt))
			}
			buf.Write(pkt[LastPacketHeader:end])
		} else {
			// Middle packet
			end := MaxPayloadSize
			if end > len(pkt) {
				end = len(pkt)
			}
			buf.Write(pkt[MiddlePacketHeader:end])
		}
		expectedIdx++
	}

	if oneExtraBytes > 0 {
		pkt, err := nextFragment()
		if err != nil {
			return nil, fmt.Errorf("optional extra fragment read: %w", err)
		}
		if len(pkt) < LastOptionalPlusOnePacketHeader {
			return nil, fmt.Errorf("extra fragment too short: %d", len(pkt))
		}
		if int(pkt[0]) != expectedIdx {
			return nil, fmt.Errorf("extra fragment idx mismatch: got %d want %d", pkt[0], expectedIdx)
		}
		size := int(pkt[1])
		if size != oneExtraBytes {
			log.Warnf("pkg bluetooth; extra fragment size %d != expected %d", size, oneExtraBytes)
		}
		end := LastOptionalPlusOnePacketHeader + size
		if end > len(pkt) {
			return nil, fmt.Errorf("extra fragment truncated: need %d, have %d", end, len(pkt))
		}
		buf.Write(pkt[LastOptionalPlusOnePacketHeader:end])
	}

	out := buf.Bytes()
	sum := crc32.ChecksumIEEE(out)
	if crc == nil {
		return nil, errors.New("no CRC found in packets")
	}
	if got := binary.BigEndian.Uint32(crc); got != sum {
		log.Warnf("pkg bluetooth; CRC mismatch: header=%x computed=%x reassembled=%d bytes", got, sum, len(out))
		return nil, errors.New("crc mismatch")
	}
	return out, nil
}
