package bluetooth

// profile_test.go is the Commit H regression guard for the Dash vs Omnipod 5
// advertisement payloads. The four helpers (advertiseDash, advertiseO5,
// refreshDash, refreshO5) take a narrow `advertiser` interface (defined in
// bluetooth.go) so these tests can capture the exact name / UUID list /
// manufacturer-data each mode emits without instantiating a real
// paypal/gatt device. A future change to the O5 advertisement shape that
// inadvertently mutates the Dash form will trip the byte-for-byte checks
// here and fail CI before silently breaking existing Dash users.

import (
	"bytes"
	"testing"

	"github.com/avereha/pod/pkg/pair"
	"github.com/paypal/gatt"
)

// advCall records a single AdvertiseNameAndServices call.
type advCall struct {
	name  string
	uuids []gatt.UUID
}

// mfgCall records a single AdvertiseNameServicesMfgData call.
type mfgCall struct {
	name  string
	uuids []gatt.UUID
	mfg   []byte
}

// fakeAdvertiser implements the advertiser interface and records every call.
// Only the two advertise variants are exercised; the rest of gatt.Device is
// not used by the helpers under test, so no further surface is mocked.
type fakeAdvertiser struct {
	adv []advCall
	mfg []mfgCall
}

func (f *fakeAdvertiser) AdvertiseNameAndServices(name string, ss []gatt.UUID) error {
	// Defensive copy so test mutations of the underlying slice can't poison
	// what the test asserts against.
	cp := make([]gatt.UUID, len(ss))
	copy(cp, ss)
	f.adv = append(f.adv, advCall{name: name, uuids: cp})
	return nil
}

func (f *fakeAdvertiser) AdvertiseNameServicesMfgData(name string, ss []gatt.UUID, mfg []byte) error {
	cp := make([]gatt.UUID, len(ss))
	copy(cp, ss)
	mfgCp := make([]byte, len(mfg))
	copy(mfgCp, mfg)
	f.mfg = append(f.mfg, mfgCall{name: name, uuids: cp, mfg: mfgCp})
	return nil
}

// uuidEqual is shorthand for asserting a UUID matches one constructed inline.
func uuidEqual(t *testing.T, idx int, got, want gatt.UUID) {
	t.Helper()
	if !got.Equal(want) {
		t.Errorf("uuid[%d] = %s, want %s", idx, got.String(), want.String())
	}
}

func TestAdvertiseDashBytes(t *testing.T) {
	b := &Ble{mode: pair.ModeDash}
	fa := &fakeAdvertiser{}

	if err := b.advertiseDash(fa, []byte{0xaa, 0xbb, 0xcc, 0xdd}); err != nil {
		t.Fatalf("advertiseDash returned error: %v", err)
	}

	if len(fa.adv) != 1 {
		t.Fatalf("expected exactly one AdvertiseNameAndServices call, got %d", len(fa.adv))
	}
	if len(fa.mfg) != 0 {
		t.Fatalf("Dash advertisement must NOT use mfg-data form; got %d mfg calls", len(fa.mfg))
	}

	got := fa.adv[0]
	if got.name != " :: Fake POD ::" {
		t.Errorf("name = %q, want %q", got.name, " :: Fake POD ::")
	}
	if len(got.uuids) != 9 {
		t.Fatalf("expected 9 UUIDs, got %d", len(got.uuids))
	}
	// Verbatim from origin/main: 0x4024, 0x2470, 0x000a, podIdOne, podIdTwo,
	// 0x0814, 0x6DB1, 0x0006, 0xE451.
	want := []gatt.UUID{
		gatt.UUID16(0x4024),
		gatt.UUID16(0x2470),
		gatt.UUID16(0x000a),
		gatt.UUID16(0xaabb),
		gatt.UUID16(0xccdd),
		gatt.UUID16(0x0814),
		gatt.UUID16(0x6DB1),
		gatt.UUID16(0x0006),
		gatt.UUID16(0xE451),
	}
	for i := range want {
		uuidEqual(t, i, got.uuids[i], want[i])
	}
}

func TestAdvertiseDashDefaultPodId(t *testing.T) {
	b := &Ble{mode: pair.ModeDash}
	fa := &fakeAdvertiser{}

	if err := b.advertiseDash(fa, nil); err != nil {
		t.Fatalf("advertiseDash returned error: %v", err)
	}
	if len(fa.adv) != 1 {
		t.Fatalf("expected one adv call, got %d", len(fa.adv))
	}
	// Default mapping from origin/main: 0xffff / 0xfffe.
	uuidEqual(t, 3, fa.adv[0].uuids[3], gatt.UUID16(0xffff))
	uuidEqual(t, 4, fa.adv[0].uuids[4], gatt.UUID16(0xfffe))
}

func TestAdvertiseO5Bytes(t *testing.T) {
	b := &Ble{mode: pair.ModeO5}
	fa := &fakeAdvertiser{}

	if err := b.advertiseO5(fa, []byte{0xaa, 0xbb, 0xcc, 0xdd}); err != nil {
		t.Fatalf("advertiseO5 returned error: %v", err)
	}

	if len(fa.mfg) != 1 {
		t.Fatalf("expected exactly one AdvertiseNameServicesMfgData call, got %d", len(fa.mfg))
	}
	if len(fa.adv) != 0 {
		t.Fatalf("O5 advertisement must NOT use plain form; got %d plain adv calls", len(fa.adv))
	}

	got := fa.mfg[0]
	wantName := "AP AABBCCDD 0A95B6110002761B"
	if got.name != wantName {
		t.Errorf("name = %q, want %q", got.name, wantName)
	}
	if len(got.uuids) != 2 {
		t.Fatalf("expected 2 UUIDs, got %d", len(got.uuids))
	}
	uuidEqual(t, 0, got.uuids[0], gatt.MustParseUUID("CE1F923D-C539-48EA-7300-0AAABBCCDD00"))
	uuidEqual(t, 1, got.uuids[1], gatt.MustParseUUID("ECF301E2-674B-4474-94D0-364F3AA653E6"))

	// Manufacturer data is the OmnipodKit-observed 7-byte payload.
	wantMfg := []byte{0x60, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00}
	if !bytes.Equal(got.mfg, wantMfg) {
		t.Errorf("mfg = %x, want %x", got.mfg, wantMfg)
	}
}

func TestAdvertiseO5DefaultPodId(t *testing.T) {
	b := &Ble{mode: pair.ModeO5}
	fa := &fakeAdvertiser{}

	if err := b.advertiseO5(fa, nil); err != nil {
		t.Fatalf("advertiseO5 returned error: %v", err)
	}
	if len(fa.mfg) != 1 {
		t.Fatalf("expected one mfg call, got %d", len(fa.mfg))
	}
	got := fa.mfg[0]
	wantName := "AP FFFFFFFE 0A95B6110002761B"
	if got.name != wantName {
		t.Errorf("default-id name = %q, want %q", got.name, wantName)
	}
	uuidEqual(t, 0, got.uuids[0], gatt.MustParseUUID("CE1F923D-C539-48EA-7300-0AFFFFFFFE00"))
}

func TestRefreshDashBytes(t *testing.T) {
	b := &Ble{mode: pair.ModeDash}
	fa := &fakeAdvertiser{}

	if err := b.refreshDash(fa, []byte{0xaa, 0xbb, 0xcc, 0xdd}); err != nil {
		t.Fatalf("refreshDash returned error: %v", err)
	}

	if len(fa.adv) != 1 {
		t.Fatalf("expected exactly one AdvertiseNameAndServices call, got %d", len(fa.adv))
	}
	if len(fa.mfg) != 0 {
		t.Fatalf("Dash refresh must NOT use mfg-data form; got %d mfg calls", len(fa.mfg))
	}

	got := fa.adv[0]
	if got.name != " :: Fake POD ::" {
		t.Errorf("name = %q, want %q", got.name, " :: Fake POD ::")
	}
	if len(got.uuids) != 9 {
		t.Fatalf("expected 9 UUIDs, got %d", len(got.uuids))
	}
	want := []gatt.UUID{
		gatt.UUID16(0x4024),
		gatt.UUID16(0x2470),
		gatt.UUID16(0x000a),
		gatt.UUID16(0xaabb),
		gatt.UUID16(0xccdd),
		gatt.UUID16(0x0814),
		gatt.UUID16(0x6DB1),
		gatt.UUID16(0x0006),
		gatt.UUID16(0xE451),
	}
	for i := range want {
		uuidEqual(t, i, got.uuids[i], want[i])
	}
}

func TestRefreshO5Bytes(t *testing.T) {
	b := &Ble{mode: pair.ModeO5}
	fa := &fakeAdvertiser{}

	if err := b.refreshO5(fa, []byte{0xaa, 0xbb, 0xcc, 0xdd}); err != nil {
		t.Fatalf("refreshO5 returned error: %v", err)
	}

	if len(fa.mfg) != 1 {
		t.Fatalf("expected exactly one AdvertiseNameServicesMfgData call, got %d", len(fa.mfg))
	}
	if len(fa.adv) != 0 {
		t.Fatalf("O5 refresh must NOT use plain form; got %d plain adv calls", len(fa.adv))
	}

	got := fa.mfg[0]
	wantName := "AP AABBCCDD 0A95B6110002761B"
	if got.name != wantName {
		t.Errorf("name = %q, want %q", got.name, wantName)
	}
	if len(got.uuids) != 2 {
		t.Fatalf("expected 2 UUIDs, got %d", len(got.uuids))
	}
	uuidEqual(t, 0, got.uuids[0], gatt.MustParseUUID("CE1F923D-C539-48EA-7300-0AAABBCCDD00"))
	uuidEqual(t, 1, got.uuids[1], gatt.MustParseUUID("ECF301E2-674B-4474-94D0-364F3AA653E6"))

	wantMfg := []byte{0x60, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00}
	if !bytes.Equal(got.mfg, wantMfg) {
		t.Errorf("mfg = %x, want %x", got.mfg, wantMfg)
	}
}
