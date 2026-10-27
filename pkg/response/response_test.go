package response

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/avereha/pod/pkg/mode"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// The DASH version responses are the bytes the simulator has always sent.
func TestDashVersionResponsesAreUnchanged(t *testing.T) {
	got, _ := AssignAddressResponse(mode.Dash).Marshal()
	if want := unhex("0115040A00010300040208146DB10006E45100FFFFFFFF"); !bytes.Equal(got, want) {
		t.Fatalf("assign address: %X", got)
	}
	got, _ = SetupPodResponse(mode.Dash, []byte{0x00, 0x00, 0x10, 0x91}).Marshal()
	if want := unhex("011B13881008340A50040A00010300040308146DB10006E45100001091"); !bytes.Equal(got, want) {
		t.Fatalf("setup pod: %X", got)
	}
}

// The Omnipod 5 version responses have the shape of OmnipodKit's
// O5CommLogFixtures: product id 5, firmware 9.0.3, BLE 6.0.2, its lot and tid.
func TestO5VersionResponses(t *testing.T) {
	got, _ := AssignAddressResponse(mode.O5).Marshal()
	want := unhex("011509000306000205020e986131000818a305ffffffff")
	if !bytes.Equal(got, want) {
		t.Fatalf("assign address:\n got  %X\n want %X", got, want)
	}
	got, _ = SetupPodResponse(mode.O5, []byte{0x00, 0x2a, 0x1c, 0x6e}).Marshal()
	want = unhex("011b13881008340a5009000306000205030e986131000818a3002a1c6e")
	if !bytes.Equal(got, want) {
		t.Fatalf("setup pod:\n got  %X\n want %X", got, want)
	}
}

func TestErrorResponse(t *testing.T) {
	got, _ := (&ErrorResponse{Code: ErrorO5InvalidCommand, PodProgress: PodProgressRunningAbove50U}).Marshal()
	if !bytes.Equal(got, []byte{0x06, 0x03, 0x2a, 0x00, 0x08}) {
		t.Fatalf("%x", got)
	}
}

// An Omnipod 5 response ends in the Omnipod CRC16; a DASH response in zeros.
func TestResponseCRCByMode(t *testing.T) {
	rsp := &GeneralStatusResponse{PodProgress: PodProgressRunningAbove50U, Reservoir: 1000}
	meta := &ResponseMetadata{Src: []byte{1, 2, 3, 4}, Dst: []byte{5, 6, 7, 8}, RequestID: []byte{0xff, 0xff, 0xff, 0xff}}
	msg, err := Marshal(rsp, meta)
	if err != nil {
		t.Fatal(err)
	}
	body := msg.Payload[len("0.0=")+2:]
	if !bytes.Equal(body[len(body)-2:], []byte{0, 0}) {
		t.Fatalf("DASH CRC %x", body[len(body)-2:])
	}
	meta.Mode = mode.O5
	msg, _ = Marshal(rsp, meta)
	body = msg.Payload[len("0.0=")+2:]
	// The CRC of OmnipodKit's vector, computed by the same function.
	if bytes.Equal(body[len(body)-2:], []byte{0, 0}) {
		t.Fatal("an Omnipod 5 response without a CRC")
	}
}
