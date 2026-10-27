package aid

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// OmnipodKit's O5CommLogFixtures: what the phone sent and the pod answered.
var fixtures = []struct {
	name   string
	send   []byte
	prefix string
	key    string
	kind   Kind
	data   []byte
	recv   []byte // the body after the prefix
}{
	{"utc", unhex("53453235352e323d31373830323134373932"), "ES255.2=", UTC, KindExtendedSet, []byte("1780214792"), []byte("0")},
	{"tdi", unhex("53332e323d0003000e002c47332e32"), "3.2=", TDI, KindSetGet, unhex("0003000e00"), unhex("0003000e00")},
	{"dia", unhex("53332e393d382c47332e39"), "3.9=", DIA, KindSetGet, []byte("8"), []byte("8")},
	{"egv", unhex("53332e373d333637303031352c47332e37"), "3.7=", EGV, KindSetGet, []byte("3670015"), []byte("3670015")},
}

func targetProfile() ([]byte, []byte) {
	body := unhex("00c0")
	for i := 0; i < 48; i++ {
		var t [4]byte
		binary.BigEndian.PutUint32(t[:], 0x6e)
		body = append(body, t[:]...)
	}
	send := append(append(unhex("53332e313d"), body...), unhex("2c47332e31")...)
	return send, body
}

func TestOmnipodKitFixtures(t *testing.T) {
	profileSend, profileBody := targetProfile()
	history := append(unhex("5345322e313d00a8"), make([]byte, 168)...)
	cases := append(fixtures,
		struct {
			name   string
			send   []byte
			prefix string
			key    string
			kind   Kind
			data   []byte
			recv   []byte
		}{"target profile", profileSend, "3.1=", TargetGlucoseProfile, KindSetGet, profileBody, profileBody},
		struct {
			name   string
			send   []byte
			prefix string
			key    string
			kind   Kind
			data   []byte
			recv   []byte
		}{"insulin history", history, "ES2.1=", AlgorithmInsulinHistory, KindExtendedSet, history[len("SE2.1="):], []byte("0")},
	)
	settings := Settings{}
	for _, tc := range cases {
		if !IsCommand(tc.send) {
			t.Errorf("%s: not seen as an AID command", tc.name)
		}
		c, err := Parse(tc.send)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if c.Kind != tc.kind || c.Key() != tc.key || !bytes.Equal(c.Data, tc.data) {
			t.Errorf("%s: parsed %s %s data %x", tc.name, c.Kind, c.Key(), c.Data)
		}
		if c.ResponsePrefix() != tc.prefix {
			t.Errorf("%s: prefix %q, want %q", tc.name, c.ResponsePrefix(), tc.prefix)
		}
		if !bytes.Equal(c.Encode(), tc.send) {
			t.Errorf("%s: re-encoded as %x", tc.name, c.Encode())
		}
		got := settings.Respond(c)
		if !bytes.Equal(got, append([]byte(tc.prefix), tc.recv...)) {
			t.Errorf("%s: answered %x", tc.name, got)
		}
	}
	if len(profileSend) != 204 || len(history) != 176 {
		t.Errorf("payload sizes %d and %d", len(profileSend), len(history))
	}
	// A later get returns what was set.
	c, _ := Parse([]byte("G3.9"))
	if got := settings.Respond(c); string(got) != "3.9=8" {
		t.Errorf("get after set: %q", got)
	}
}

func TestStatusQueries(t *testing.T) {
	settings := Settings{}
	for _, tc := range []struct {
		send string
		size int
	}{{"G3.11", len("3.11=") + 30}, {"G3.12", len("3.12=") + 29}} {
		c, err := Parse([]byte(tc.send))
		if err != nil {
			t.Fatal(err)
		}
		if c.Kind != KindGet || len(settings.Respond(c)) != tc.size {
			t.Errorf("%s: %s, %d bytes", tc.send, c.Kind, len(settings.Respond(c)))
		}
	}
}

func TestOmnipodCommandsAreNotAIDCommands(t *testing.T) {
	for _, p := range [][]byte{
		unhex("53302e303d000b" + "ffffffff08030e0100008a" + "2c47302e30"), // S0.0=<GetStatus>,G0.0
		[]byte("S0.0="), []byte("G0"), []byte(""), unhex("1d1800a02800000463ff"),
	} {
		if IsCommand(p) {
			t.Errorf("%x taken for an AID command", p)
		}
	}
	for _, p := range []string{"S3.2", "SE3=1", "G3.", "Sx.1=2,Gx.1", "S3.1=12,G3.2"} {
		if _, err := Parse([]byte(p)); err == nil {
			t.Errorf("%q parsed", p)
		}
	}
}
