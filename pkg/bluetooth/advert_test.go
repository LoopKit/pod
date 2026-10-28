package bluetooth

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/paypal/gatt"
)

// advFields splits an advertising packet into its (type, value) fields.
// advBytes is the packet's used portion; AdvPacket.Bytes returns a
// fixed-size array that cannot be sliced directly.
func advBytes(a *gatt.AdvPacket) []byte {
	full := a.Bytes()
	return append([]byte(nil), full[:a.Len()]...)
}

func advFields(t *testing.T, b []byte) map[byte][]byte {
	t.Helper()
	out := map[byte][]byte{}
	for i := 0; i < len(b); {
		l := int(b[i])
		if l == 0 || i+1+l > len(b) {
			break
		}
		out[b[i+1]] = b[i+2 : i+1+l]
		i += 1 + l
	}
	return out
}

const (
	fieldAllUUID16  = 0x03
	fieldAllUUID128 = 0x07
)

// An Omnipod 5 advertises one 128-bit service UUID. The vendored gatt wrote
// every UUID into a 16-bit list whatever its length, so the phone saw a run
// of nonsense 16-bit UUIDs and never matched its pod.
func TestAdvertisingPacksA128BitUUID(t *testing.T) {
	u, err := gatt.ParseUUID(o5AdvertisementUUID(0x002A1C6C, false))
	if err != nil {
		t.Fatal(err)
	}

	a := &gatt.AdvPacket{}
	a.AppendFlags(0x06)
	a.AppendUUIDFit([]gatt.UUID{u})

	fields := advFields(t, advBytes(a))
	got, ok := fields[fieldAllUUID128]
	if !ok {
		t.Fatalf("no 128-bit UUID list in %x (fields %v)", advBytes(a), keys(fields))
	}
	if len(got) != 16 {
		t.Fatalf("the 128-bit list holds %d bytes, want 16", len(got))
	}
	if _, wrong := fields[fieldAllUUID16]; wrong {
		t.Error("a 128-bit UUID was also written into the 16-bit list")
	}

	// gatt keeps UUIDs little-endian on the wire, so the advertised bytes are
	// the UUID reversed.
	want := strings.ToUpper(hex.EncodeToString(reverseBytes(got)))
	if want != strings.ToUpper(strings.ReplaceAll(o5AdvertisementUUID(0x002A1C6C, false), "-", "")) {
		t.Errorf("advertised UUID is %s, want %s", want, o5AdvertisementUUID(0x002A1C6C, false))
	}
}

// A DASH advertises nine 16-bit UUIDs, which must still go out as a 16-bit
// list and must still fit the 31-byte packet.
func TestAdvertisingStillPacksDash(t *testing.T) {
	var uu []gatt.UUID
	for _, u := range AdvertisedServices([]byte{0x00, 0x2a, 0x1c, 0x6d}, AdvertState{}) {
		uu = append(uu, gatt.UUID16(u))
	}

	a := &gatt.AdvPacket{}
	a.AppendFlags(0x06)
	a.AppendUUIDFit(uu)

	fields := advFields(t, advBytes(a))
	got, ok := fields[fieldAllUUID16]
	if !ok {
		t.Fatalf("no 16-bit UUID list in %x (fields %v)", advBytes(a), keys(fields))
	}
	if len(got) != 2*len(uu) {
		t.Errorf("the 16-bit list holds %d bytes, want %d", len(got), 2*len(uu))
	}
	if a.Len() > 31 {
		t.Errorf("the advertisement is %d bytes, over the 31 a packet allows", a.Len())
	}
}

// An advertisement carrying a 128-bit UUID has no room left for the pod's
// name, so the name belongs in the scan response and the packet must still
// fit.
func TestO5AdvertisementFitsWithoutTheName(t *testing.T) {
	u, _ := gatt.ParseUUID(o5AdvertisementUUID(0x002A1C6C, false))
	a := &gatt.AdvPacket{}
	a.AppendFlags(0x06)
	a.AppendUUIDFit([]gatt.UUID{u})

	if n := a.Len(); n > 31 {
		t.Fatalf("the advertisement is %d bytes, over the 31 a packet allows", n)
	}
	if a.Len()+len(AdvertisedName)+2 < 31 {
		t.Errorf("the name would fit after all (%d + %d), so the scan-response path is untested",
			a.Len(), len(AdvertisedName))
	}
}

func keys(m map[byte][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, hex.EncodeToString([]byte{k}))
	}
	return out
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// A real Omnipod 5 names itself "AP <controller id> <lot><tid>", captured from
// a pod as "AP FFFFFFFE 0E977731000A3AB7" while it was still unpaired. The
// simulator mirrors that shape so a pod looks like one in a scan.
func TestO5AdvertisedName(t *testing.T) {
	o5 := ProfileFor(ModeO5)

	unpaired := o5.AdvertisedName(0)
	if unpaired != "AP FFFFFFFE 0E146DB10006E451" {
		t.Errorf("an unpaired pod is named %q", unpaired)
	}
	paired := o5.AdvertisedName(0x002A1C6C)
	if paired != "AP 002A1C6C 0E146DB10006E451" {
		t.Errorf("a paired pod is named %q", paired)
	}

	// The name goes in the scan response, which is also 31 bytes: two of
	// header plus the name itself.
	if n := 2 + len(paired); n > 31 {
		t.Errorf("the name needs %d bytes of the scan response, over 31", n)
	}

	// The lot in the name has to decode as an Omnipod 5, as the real pod's
	// 0E977731 does: bits 25-30 are the product, 7 for a U100 Omnipod 5.
	if got := (0x0E146DB1 >> 25) & 0x3f; got != 7 {
		t.Errorf("the advertised lot decodes as product %d, want 7", got)
	}

	// A DASH keeps the name this simulator has always used.
	if got := ProfileFor(ModeDash).AdvertisedName(0); got != AdvertisedName {
		t.Errorf("a DASH is named %q, want %q", got, AdvertisedName)
	}
}
