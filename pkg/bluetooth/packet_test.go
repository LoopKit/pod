package bluetooth

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
)

// Whatever the pod writes, the phone has to be able to put back together,
// at both packet sizes and at every length that changes which packets are
// used: one packet, one plus the extra, a run of middle packets, and a run
// whose last packet overflows into the extra one.
func TestSplitAndJoinRoundTrip(t *testing.T) {
	for _, mode := range []Mode{ModeDash, ModeO5} {
		layout := ProfileFor(mode).Layout
		t.Run(string(mode), func(t *testing.T) {
			sizes := []int{1, 2,
				layout.firstCapWithoutMiddle() - 1,
				layout.firstCapWithoutMiddle(),
				layout.firstCapWithoutMiddle() + 1,
				layout.firstCapWithMiddle(),
				layout.firstCapWithMiddle() + 1,
				layout.firstCapWithMiddle() + layout.lastCap(),
				layout.firstCapWithMiddle() + layout.lastCap() + 1,
				layout.firstCapWithMiddle() + layout.middleCap() + 1,
				layout.firstCapWithMiddle() + 3*layout.middleCap() + 7,
			}
			// The pairing messages are what makes the Omnipod 5 packet
			// size necessary, so cover their sizes too.
			if mode == ModeO5 {
				sizes = append(sizes, 16+80, 16+642, 16+1089, 16+1100)
			}
			for _, size := range sizes {
				body := make([]byte, size)
				rand.New(rand.NewSource(int64(size))).Read(body)

				packets := layout.Split(body)
				if len(packets) == 0 {
					t.Fatalf("%d bytes split into no packets", size)
				}
				for i, p := range packets {
					if len(p) > layout.MaxPayloadSize {
						t.Fatalf("%d bytes: packet %d is %d bytes, over the %d limit", size, i, len(p), layout.MaxPayloadSize)
					}
				}

				joiner, err := NewJoiner(packets[0], layout)
				if err != nil {
					t.Fatalf("%d bytes: first packet: %v", size, err)
				}
				for i := 1; i < len(packets); i++ {
					if !joiner.More() {
						t.Fatalf("%d bytes: packet %d was not expected", size, i)
					}
					if err := joiner.Accumulate(packets[i]); err != nil {
						t.Fatalf("%d bytes: packet %d: %v", size, i, err)
					}
				}
				if joiner.More() {
					t.Fatalf("%d bytes: still waiting for a packet after all %d", size, len(packets))
				}
				got, err := joiner.Finalize()
				if err != nil {
					t.Fatalf("%d bytes: %v", size, err)
				}
				if !bytes.Equal(got, body) {
					t.Fatalf("%d bytes: came back as %d bytes and differs", size, len(got))
				}
			}
		})
	}
}

// A DASH pod has 20-byte packets and an Omnipod 5 244-byte ones, which is
// what lets its ~1 KB pairing messages fit in the 15 fragments the phone
// allows (OmnipodKit's BlePodProfile).
func TestLayoutsMatchOmnipodKit(t *testing.T) {
	dash := ProfileFor(ModeDash).Layout
	if dash.MaxPayloadSize != 20 {
		t.Errorf("DASH packets are %d bytes, want 20", dash.MaxPayloadSize)
	}
	o5 := ProfileFor(ModeO5).Layout
	if o5.MaxPayloadSize != 244 {
		t.Errorf("Omnipod 5 packets are %d bytes, want 244", o5.MaxPayloadSize)
	}

	// The largest pairing message is SPS2, about 1.1 KB with its wrapper.
	if _, err := NewJoiner(o5.Split(make([]byte, 1200))[0], o5); err != nil {
		t.Errorf("a 1200-byte message does not fit the Omnipod 5 layout: %v", err)
	}
	if n := len(o5.Split(make([]byte, 1200))); n > o5.MaxFragments+2 {
		t.Errorf("a 1200-byte message takes %d packets, more than the phone reads", n)
	}
}

// A damaged message has to be refused rather than passed on.
func TestJoinerRefusesDamagedMessages(t *testing.T) {
	layout := ProfileFor(ModeO5).Layout
	body := make([]byte, 600)
	rand.New(rand.NewSource(1)).Read(body)
	packets := layout.Split(body)

	t.Run("a flipped bit fails the checksum", func(t *testing.T) {
		broken := append([]Packet(nil), packets...)
		damaged := append(Packet(nil), broken[1]...)
		damaged[5] ^= 0xff
		broken[1] = damaged

		joiner, err := NewJoiner(broken[0], layout)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(broken); i++ {
			if err := joiner.Accumulate(broken[i]); err != nil {
				return // refused on the way in, which is fine
			}
		}
		if _, err := joiner.Finalize(); err == nil {
			t.Error("a flipped bit was accepted")
		}
	})

	t.Run("a packet out of order is refused", func(t *testing.T) {
		joiner, err := NewJoiner(packets[0], layout)
		if err != nil {
			t.Fatal(err)
		}
		if err := joiner.Accumulate(packets[len(packets)-1]); err == nil {
			t.Error("a packet arriving out of order was accepted")
		}
	})

	t.Run("a message that does not start at zero is refused", func(t *testing.T) {
		if _, err := NewJoiner(packets[1], layout); err == nil {
			t.Error("a message starting partway through was accepted")
		}
	})

	t.Run("a truncated first packet is refused", func(t *testing.T) {
		if _, err := NewJoiner(packets[0][:1], layout); err == nil {
			t.Error("a one-byte first packet was accepted")
		}
	})
}

// An Omnipod 5 advertises one 128-bit service UUID holding its
// controller's id, and flips the last byte to 02 when it wants attention
// (OmnipodKit's o5ServiceAdvertisementUUID and o5FaultAdvertisementUUID).
func TestO5Advertisement(t *testing.T) {
	o5 := ProfileFor(ModeO5)

	unpaired := o5.AdvertisedServiceUUIDs(nil, 0, AdvertState{})
	if len(unpaired) != 1 || unpaired[0] != "CE1F923D-C539-48EA-7300-0AFFFFFFFE00" {
		t.Errorf("an unpaired pod advertises %v, want the FFFFFFFE UUID", unpaired)
	}

	paired := o5.AdvertisedServiceUUIDs([]byte{0, 0x2a, 0x1c, 0x6d}, 0x002A1C6C, AdvertState{})
	if len(paired) != 1 || paired[0] != "CE1F923D-C539-48EA-7300-0A002A1C6C00" {
		t.Errorf("a paired pod advertises %v, want its controller's UUID", paired)
	}

	faulted := o5.AdvertisedServiceUUIDs(nil, 0x002A1C6C, AdvertState{Fault: 0x14})
	if len(faulted) != 1 || faulted[0] != "CE1F923D-C539-48EA-7300-0A002A1C6C02" {
		t.Errorf("a faulted pod advertises %v, want the …02 UUID", faulted)
	}

	// A DASH still advertises its nine 16-bit UUIDs.
	dash := ProfileFor(ModeDash).AdvertisedServiceUUIDs([]byte{0, 0x2a, 0x1c, 0x6d}, 0, AdvertState{})
	if len(dash) != 9 || dash[0] != "4024" {
		t.Errorf("a DASH advertises %v, want nine UUIDs starting 4024", dash)
	}
}

// The controller id comes from the HELLO the phone writes before anything
// else (OmnipodKit's PeripheralManager.sendHello).
func TestPdmIdFromHello(t *testing.T) {
	hello, _ := hex.DecodeString("0601" + "04" + "002a1c6c")
	got, ok := O5PdmIdFromHello(hello)
	if !ok || got != 0x002A1C6C {
		t.Errorf("O5PdmIdFromHello = %08x, %v; want 002a1c6c, true", got, ok)
	}
	for _, short := range []string{"", "06", "060104002a1c"} {
		b, _ := hex.DecodeString(short)
		if _, ok := O5PdmIdFromHello(b); ok {
			t.Errorf("O5PdmIdFromHello(%q) should not have read an id", short)
		}
	}
	if _, ok := O5PdmIdFromHello([]byte{0x04}); ok {
		t.Error("a SUCCESS byte should not read as a HELLO")
	}
}

func ExampleMode_Description() {
	fmt.Println(ModeDash.Description(), "/", ModeO5.Description())
	// Output: Omnipod DASH / Omnipod 5
}
