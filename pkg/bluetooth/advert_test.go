package bluetooth

import (
	"bytes"
	"testing"

	"github.com/avereha/pod/pkg/mode"
)

func uuidStrings(us []UUID) []string {
	var out []string
	for _, u := range us {
		out = append(out, u.String())
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A DASH pod's advertisement is what it always was.
func TestDashAdvertisement(t *testing.T) {
	got := uuidStrings(AdvertisedServices(mode.Dash, nil, AdvertState{}))
	want := []string{"4024", "2470", "000A", "FFFF", "FFFE", "0814", "6DB1", "0006", "E451"}
	if !equalStrings(got, want) {
		t.Fatalf("unpaired: %v", got)
	}
	got = uuidStrings(AdvertisedServices(mode.Dash, []byte{0x17, 0x0d, 0x2a, 0x40}, AdvertState{Alerts: 0x08}))
	want = []string{"4024", "C005", "000A", "170D", "2A40", "0814", "6DB1", "0006", "E451"}
	if !equalStrings(got, want) {
		t.Fatalf("paired with an alert: %v", got)
	}
	if AdvertisedName(mode.Dash, nil) != " :: Fake POD ::" {
		t.Fatal("name changed")
	}
	mfg := ManufacturerData(mode.Dash, AdvertState{Fault: 0x14})
	if !bytes.Equal(mfg[len(mfg)-7:len(mfg)-3], []byte{0x00, 0x14, 0x14, 0x00}) {
		t.Fatalf("manufacturer data %x", mfg)
	}
}

// An Omnipod 5 advertises one 128-bit UUID that carries the controller id,
// FFFFFFFE before pairing, and ends in 02 on a fault (OmnipodKit
// PodAdvertisement, o5ServiceAdvertisementUUID, o5FaultAdvertisementUUID).
func TestO5Advertisement(t *testing.T) {
	got := uuidStrings(AdvertisedServices(mode.O5, nil, AdvertState{}))
	if !equalStrings(got, []string{"CE1F923D-C539-48EA-7300-0AFFFFFFFE00"}) {
		t.Fatalf("unpaired: %v", got)
	}
	controller := []byte{0x00, 0x2a, 0x1c, 0x6c}
	got = uuidStrings(AdvertisedServices(mode.O5, controller, AdvertState{Alerts: 0x08}))
	if !equalStrings(got, []string{"CE1F923D-C539-48EA-7300-0A002A1C6C00"}) {
		t.Fatalf("paired: %v", got)
	}
	got = uuidStrings(AdvertisedServices(mode.O5, controller, AdvertState{Fault: 0x14}))
	if !equalStrings(got, []string{"CE1F923D-C539-48EA-7300-0A002A1C6C02"}) {
		t.Fatalf("faulted: %v", got)
	}
	if AdvertisedName(mode.O5, controller) != "AP 002A1C6C 0A95B6110002761B" {
		t.Fatalf("name %q", AdvertisedName(mode.O5, controller))
	}
	if DataCharUUID(mode.O5) != "1A7E2443-E3ED-4464-8B7E-751E03D0DC5F" || DataCharUUID(mode.Dash) != "1A7E2442-E3ED-4464-8B7E-751E03D0DC5F" {
		t.Fatal("data characteristic UUIDs")
	}
}
