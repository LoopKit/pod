package bluetooth

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"testing"
)

func generated(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(int(seed) + i)
	}
	return b
}

func roundTrip(t *testing.T, l Layout, payload []byte) []Packet {
	t.Helper()
	packets := l.Split(payload)
	if len(packets) == 0 {
		t.Fatal("no packets")
	}
	for i, p := range packets {
		if len(p) > l.MaxPayloadSize {
			t.Fatalf("%d bytes: packet %d is %d bytes", len(payload), i, len(p))
		}
	}
	rest := packets[1:]
	got, err := l.Join(packets[0], func() (Packet, error) {
		if len(rest) == 0 {
			return nil, errors.New("ran out of packets")
		}
		p := rest[0]
		rest = rest[1:]
		return p, nil
	})
	if err != nil {
		t.Fatalf("%d bytes: %v", len(payload), err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("%d bytes: joined % x", len(payload), got)
	}
	if len(rest) != 0 {
		t.Fatalf("%d bytes: %d packets left over", len(payload), len(rest))
	}
	return packets
}

// The Omnipod 5 layout, with the cases from OmnipodKit's O5BleFramingTests.
func TestO5LayoutMatchesOmnipodKit(t *testing.T) {
	l := O5Layout
	if l.firstCapacityWithoutMiddle() != 237 || l.firstCapacityWithMiddle() != 242 || l.middleCapacity() != 243 || l.lastCapacity() != 238 {
		t.Fatal("capacities differ from BlePodProfile.omnipod5")
	}
	for _, tc := range []struct{ n, packets int }{
		{0, 1}, {100, 1}, {242, 2}, {243, 2}, {300, 2}, {500, 3}, {641, 3}, {642, 3}, {893, 4}, {953, 4},
	} {
		if got := len(roundTrip(t, l, generated(tc.n, 0xa5))); got != tc.packets {
			t.Errorf("%d bytes: %d packets, want %d", tc.n, got, tc.packets)
		}
	}
	first := l.Split(generated(953, 2))[0]
	if first[1] != 3 {
		t.Errorf("953 bytes: first packet announces %d full fragments, want 3", first[1])
	}
	for n := 1; n <= 1200; n++ {
		roundTrip(t, l, generated(n, byte(n)))
	}
}

// legacyDashSplit is the simulator's hand-written DASH fragmenter before the
// layouts, for messages of more than 18 bytes (the only ones a pod sends).
func legacyDashSplit(b []byte) []Packet {
	var out []Packet
	sum := crc32.ChecksumIEEE(b)
	crc := []byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}
	size := len(b)
	fullFragments := (size - 18) / 19
	rest := (size - (fullFragments * 19)) - 18
	out = append(out, append(Packet{0, byte(fullFragments + 1)}, b[:18]...))
	index := 1
	for ; index <= fullFragments; index++ {
		out = append(out, append(Packet{byte(index)}, b[(index-1)*19+18:(index-1)*19+18+19]...))
	}
	end := rest
	if rest > 14 {
		end = 14
	}
	last := append(Packet{byte(index), byte(rest)}, crc...)
	last = append(last, b[fullFragments*19+18:fullFragments*19+18+end]...)
	out = append(out, last)
	if rest > 14 {
		index++
		extra := append(Packet{byte(index), byte(rest - 14)}, b[fullFragments*19+18+14:]...)
		for len(extra) < 20 {
			extra = append(extra, 0)
		}
		out = append(out, extra)
	}
	return out
}

// The DASH layout writes what the simulator always wrote, apart from zero
// padding the last packet to 20 bytes as a real pod (and OmnipodKit) does.
// 302 bytes is the longest message 15 fragments carry.
func TestDashLayoutKeepsTheOldFraming(t *testing.T) {
	l := DashLayout
	for n := 19; n <= 302; n++ {
		payload := generated(n, byte(n))
		got := roundTrip(t, l, payload)
		want := legacyDashSplit(payload)
		if len(got) != len(want) {
			t.Fatalf("%d bytes: %d packets, legacy %d", n, len(got), len(want))
		}
		for i := range want {
			w := want[i]
			for len(w) < 20 {
				w = append(w, 0)
			}
			if !bytes.Equal(got[i], w) {
				t.Fatalf("%d bytes, packet %d:\n got  % x\n want % x", n, i, got[i], w)
			}
		}
	}
	// Short messages take the first packet's 13 bytes and spill the rest.
	for n := 1; n <= 18; n++ {
		roundTrip(t, l, generated(n, 1))
	}
}

// OmnipodKit's joiner takes at most 15 fragments, so a longer message is
// refused rather than read wrong.
func TestJoinRejectsTooManyFragments(t *testing.T) {
	packets := DashLayout.Split(generated(303, 5))
	if packets[0][1] != 16 {
		t.Fatalf("303 bytes announce %d fragments", packets[0][1])
	}
	if _, err := DashLayout.Join(packets[0], func() (Packet, error) { return packets[1], nil }); err == nil {
		t.Fatal("16 fragments were accepted")
	}
}

func TestJoinRejectsAnOutOfOrderPacket(t *testing.T) {
	packets := O5Layout.Split(generated(500, 3))
	_, err := O5Layout.Join(packets[0], func() (Packet, error) { return packets[2], nil })
	var ie *IndexError
	if !errors.As(err, &ie) || ie.Expected != 1 || ie.Got != 2 {
		t.Fatalf("got %v", err)
	}
}

func TestJoinRejectsABadCRC(t *testing.T) {
	packets := DashLayout.Split(generated(30, 4))
	last := append(Packet{}, packets[1]...)
	binary.BigEndian.PutUint32(last[2:6], 0xdeadbeef)
	_, err := DashLayout.Join(packets[0], func() (Packet, error) { return last, nil })
	if !errors.Is(err, ErrCRC) {
		t.Fatalf("got %v", err)
	}
}

func ExampleLayout_Split() {
	packets := O5Layout.Split(generated(18, 0x54))
	fmt.Println(len(packets), len(packets[0]))
	// Output: 1 25
}

// A packet goes in one ATT write or notification, which holds MTU-3 bytes.
func TestMinMTUFitsAWholePacket(t *testing.T) {
	for _, tt := range []struct {
		name   string
		layout Layout
		want   int
	}{
		{"DASH", DashLayout, 23},
		{"Omnipod 5", O5Layout, 247},
	} {
		if got := tt.layout.MinMTU(); got != tt.want {
			t.Errorf("%s: MinMTU() = %d, want %d", tt.name, got, tt.want)
		}
		if packets := tt.layout.Split(generated(600, 1)); len(packets[0]) > tt.layout.MinMTU()-3 {
			t.Errorf("%s: a %d-byte packet does not fit MinMTU %d", tt.name, len(packets[0]), tt.layout.MinMTU())
		}
	}
}
