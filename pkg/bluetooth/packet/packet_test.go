package packet

import (
	"bytes"
	"testing"
)

// TestPacketRoundTrip exercises split→join across the size regimes that
// exercise different code paths: a tiny payload (single packet), a payload
// that just barely overflows a single packet (single + LastOptionalPlusOne),
// a multi-fragment payload that fits cleanly in last, and a large payload
// that needs the LastOptionalPlusOne tail.
func TestPacketRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"tiny", 16},
		{"single-cap", firstPacketCapacityWithoutMiddle()},
		{"single+extra", firstPacketCapacityWithoutMiddle() + 5},
		{"two-frag", firstPacketCapacityWithMiddle() + 50},
		{"three-frag-clean", firstPacketCapacityWithMiddle() + middlePacketCapacity() + 50},
		{"three-frag-extra", firstPacketCapacityWithMiddle() + middlePacketCapacity() + lastPacketCapacity() + 17},
		{"sps2.1-sized", 666},
		{"sps2-sized", 920},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.size)
			for i := range payload {
				payload[i] = byte(i)
			}
			packets := Split(payload)
			if len(packets) == 0 {
				t.Fatal("splitPayload returned no packets")
			}
			for _, p := range packets {
				if len(p) > MaxPayloadSize {
					t.Errorf("packet larger than MTU: %d", len(p))
				}
			}

			i := 0
			out, err := Join(packets[0], func() ([]byte, error) {
				i++
				if i >= len(packets) {
					t.Fatalf("joiner asked for fragment %d but only %d available", i, len(packets))
				}
				return packets[i], nil
			})
			if err != nil {
				t.Fatalf("joinPackets: %v", err)
			}
			if !bytes.Equal(out, payload) {
				t.Errorf("round-trip mismatch: got %d bytes, want %d", len(out), len(payload))
			}
		})
	}
}

// TestPacketCRCDetectsTamper confirms the joiner rejects a flipped byte.
func TestPacketCRCDetectsTamper(t *testing.T) {
	payload := make([]byte, 500)
	for i := range payload {
		payload[i] = byte(i)
	}
	packets := Split(payload)
	// Flip a byte in the middle of fragment 0's payload area (after the
	// 2-byte header, before any structural byte the joiner reads).
	packets[0][50] ^= 0xff

	i := 0
	_, err := Join(packets[0], func() ([]byte, error) {
		i++
		return packets[i], nil
	})
	if err == nil {
		t.Fatal("expected CRC mismatch error after tamper")
	}
}

// TestJoinIndexMismatch flips a fragment's index byte and asserts the joiner
// rejects the reassembly rather than silently producing corrupt output.
func TestJoinIndexMismatch(t *testing.T) {
	payload := make([]byte, 500) // forces 3 fragments
	for i := range payload {
		payload[i] = byte(i)
	}
	packets := Split(payload)
	if len(packets) < 2 {
		t.Fatalf("expected ≥2 packets, got %d", len(packets))
	}
	// Corrupt the first non-first fragment's idx (was 1, claim 99).
	packets[1][0] = 99

	i := 0
	_, err := Join(packets[0], func() ([]byte, error) {
		i++
		return packets[i], nil
	})
	if err == nil {
		t.Fatal("expected error from out-of-order fragment idx")
	}
}

// TestSplitBoundaryLastFitsExactly: payload size that lands the rest exactly
// at lastPacketCapacity. Confirms no LastOptionalPlusOnePacket is emitted
// at the boundary (off-by-one risk).
func TestSplitBoundaryLastFitsExactly(t *testing.T) {
	// firstCap (242) + middleCap*1 (243) + lastCap (238) = 723.
	size := firstPacketCapacityWithMiddle() + middlePacketCapacity() + lastPacketCapacity()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	packets := Split(payload)
	if len(packets) != 3 {
		t.Fatalf("expected exactly 3 packets at boundary, got %d", len(packets))
	}
	// rest byte in the last packet should equal lastPacketCapacity exactly,
	// not size - lastPacketCapacity (which would be 0 and trigger oneExtra).
	if int(packets[2][1]) != lastPacketCapacity() {
		t.Errorf("last packet size byte = %d, want %d", packets[2][1], lastPacketCapacity())
	}

	i := 0
	out, err := Join(packets[0], func() ([]byte, error) {
		i++
		return packets[i], nil
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Errorf("round-trip mismatch at boundary")
	}
}

// TestJoinAcceptsShorterFragments: the joiner bounds reads by len(pkt), not
// by MaxPayloadSize, so a smaller-than-244 negotiated MTU still reassembles
// correctly. Hand-built fragments at a 30-byte fragment size simulate that.
func TestJoinAcceptsShorterFragments(t *testing.T) {
	// Build a 100-byte payload split into 30-byte fragments by hand.
	// Layout chosen to mirror what a sender at MTU=30 would emit:
	//   first capacity (with middle) = 28
	//   middle capacity              = 29
	//   last capacity                = 24
	//   middleFragments = (100-28)/29 = 2, rest = 100 - 28 - 2*29 = 14.
	// 14 ≤ lastCapacity, so no LastOptionalPlusOnePacket.
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i + 1)
	}

	first := []byte{0, 3}             // idx=0, fullFragments=3
	first = append(first, payload[0:28]...)

	mid1 := []byte{1}
	mid1 = append(mid1, payload[28:57]...)

	mid2 := []byte{2}
	mid2 = append(mid2, payload[57:86]...)

	// crc of full payload, big-endian
	last := []byte{3, 14}
	crc := crc32IEEE(payload)
	last = append(last, byte(crc>>24), byte(crc>>16), byte(crc>>8), byte(crc))
	last = append(last, payload[86:100]...)

	frags := [][]byte{first, mid1, mid2, last}
	for i, f := range frags {
		if len(f) > 30 {
			t.Fatalf("fragment %d %d bytes — too big for simulated MTU", i, len(f))
		}
	}

	i := 0
	out, err := Join(frags[0], func() ([]byte, error) {
		i++
		return frags[i], nil
	})
	if err != nil {
		t.Fatalf("Join with short fragments: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Errorf("round-trip mismatch: got %d bytes %x, want %d bytes %x", len(out), out[:8], len(payload), payload[:8])
	}
}

// crc32IEEE — local helper so the test doesn't reach into the production
// crc32 import already used by packet.go (keeps test imports minimal).
func crc32IEEE(b []byte) uint32 {
	// Direct standard-lib polynomial 0xedb88320, big-endian Init=0xffffffff,
	// XorOut=0xffffffff. Identical to hash/crc32.ChecksumIEEE.
	const poly = 0xedb88320
	c := ^uint32(0)
	for _, x := range b {
		c ^= uint32(x)
		for i := 0; i < 8; i++ {
			if c&1 != 0 {
				c = (c >> 1) ^ poly
			} else {
				c >>= 1
			}
		}
	}
	return ^c
}
