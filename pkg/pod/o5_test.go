package pod

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/avereha/pod/pkg/aid"
	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/command"
	"github.com/avereha/pod/pkg/crc"
	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/response"
)

// silentRadio is a pod radio that goes nowhere; these tests exercise what
// the pod decides, not what it writes.
type silentRadio struct{}

func (silentRadio) NotifyCmd(bluetooth.Packet) error           { return nil }
func (silentRadio) NotifyData(bluetooth.Packet) error          { return nil }
func (silentRadio) Advertise([]byte, uint32) error             { return nil }
func (silentRadio) AdvertiseState(bluetooth.AdvertState) error { return nil }
func (silentRadio) Disconnect()                                {}
func (silentRadio) LinkMTU() int                               { return 0 }

func testPod(t *testing.T, mode bluetooth.Mode) *Pod {
	t.Helper()
	ble, err := bluetooth.New(func(*bluetooth.Ble) (bluetooth.Radio, error) { return silentRadio{}, nil },
		bluetooth.ProfileFor(mode))
	if err != nil {
		t.Fatal(err)
	}
	return &Pod{
		ble:   ble,
		state: NewFreshState(t.TempDir()+"/state.toml", mode),
		aid:   aid.NewStore(),
	}
}

// omnipodCommand builds the command block the phone sends inside an
// encrypted message: the S0.0= wrapper around an addressed, length-and-
// sequence prefixed body with its CRC16.
func omnipodCommand(t *testing.T, address []byte, seq uint8, body []byte) []byte {
	t.Helper()
	inner := append([]byte(nil), address...)
	lsf := uint16(seq&0x0f)<<10 | uint16(len(body))
	inner = append(inner, byte(lsf>>8), byte(lsf))
	inner = append(inner, body...)
	inner = append(inner, crc.CRC16(inner)...)

	out := append([]byte("S0.0="), byte(len(inner)>>8), byte(len(inner)))
	out = append(out, inner...)
	return append(out, []byte(",G0.0")...)
}

func parseCommand(t *testing.T, body []byte) command.Command {
	t.Helper()
	cmd, err := command.Unmarshal(omnipodCommand(t, []byte{0x00, 0x2a, 0x1c, 0x6d}, 3, body))
	if err != nil {
		t.Fatalf("building a command: %v", err)
	}
	return cmd
}

// An Omnipod 5 refuses to deliver or stop insulin unless the command came
// signed by the controller it paired with, and answers error 0x2A when it
// does not — which is what OmnipodKit's ErrorResponseCode.o5InvalidCommand
// names. Anything else it takes as before.
func TestO5SignatureEnforcement(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic := make([]byte, 64)
	key.PublicKey.X.FillBytes(controllerPublic[:32])
	key.PublicKey.Y.FillBytes(controllerPublic[32:])

	signingInput := []byte("the header and the encrypted payload")
	sign := func(k *ecdsa.PrivateKey, data []byte) []byte {
		digest := sha256.Sum256(data)
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}

	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 0x1c deactivate and 0x1f stop delivery must be signed; 0x0e get
	// status need not be.
	deactivate := []byte{0x1c, 0x00}
	getStatus := []byte{0x0e, 0x00, 0x00}

	for _, tc := range []struct {
		name    string
		body    []byte
		msgType message.MessageType
		sig     []byte
		refused bool
	}{
		{"a signed deactivate is carried out", deactivate, message.MessageTypeEncryptedSigned, sign(key, signingInput), false},
		{"an unsigned deactivate is refused", deactivate, message.MessageTypeEncrypted, nil, true},
		{"a deactivate signed by a stranger is refused", deactivate, message.MessageTypeEncryptedSigned, sign(stranger, signingInput), true},
		{"a deactivate with a damaged signature is refused", deactivate, message.MessageTypeEncryptedSigned, make([]byte, 64), true},
		{"an unsigned get status is carried out", getStatus, message.MessageTypeEncrypted, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPod(t, bluetooth.ModeO5)
			p.state.ControllerPublic = controllerPublic

			got := p.checkO5Signature(parseCommand(t, tc.body), tc.msgType, tc.sig, signingInput)
			if tc.refused {
				if got == nil {
					t.Fatal("the command was carried out and should have been refused")
				}
				refusal, ok := got.(*response.ErrorResponse)
				if !ok {
					t.Fatalf("the pod answered with %T, want an error response", got)
				}
				if refusal.Code != response.ErrorInvalidCommand {
					t.Errorf("the error code is 0x%02x, want 0x%02x", refusal.Code, response.ErrorInvalidCommand)
				}
				if p.state.SignedRejected != 1 {
					t.Errorf("the pod counted %d refusals, want 1", p.state.SignedRejected)
				}
				// The refusal is a valid message block: type 06 and a length.
				raw, err := refusal.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				if len(raw) != 5 || raw[0] != 0x06 || raw[1] != 0x03 {
					t.Errorf("the error response is %x, want 06 03 then three bytes", raw)
				}
				return
			}
			if got != nil {
				t.Fatalf("the command was refused with %T and should have been carried out", got)
			}
			if p.state.SignedRejected != 0 {
				t.Errorf("the pod counted %d refusals, want 0", p.state.SignedRejected)
			}
		})
	}
}

// A DASH pod has no signatures at all, so the same unsigned commands must
// go through untouched.
func TestDashIgnoresSignatures(t *testing.T) {
	p := testPod(t, bluetooth.ModeDash)
	for _, body := range [][]byte{{0x1c, 0x00}, {0x1f, 0x05, 0x49, 0x4e, 0x53, 0x2e, 0x07}, {0x0e, 0x00, 0x00}} {
		if got := p.checkO5Signature(parseCommand(t, body), message.MessageTypeEncrypted, nil, nil); got != nil {
			t.Errorf("a DASH refused command 0x%02x", body[0])
		}
	}
	if p.state.SignedRejected != 0 {
		t.Error("a DASH counted a signature refusal")
	}
}

// The commands that must be signed are the ones OmnipodKit signs
// (requiresType4Signing): everything that starts or stops insulin.
func TestWhichCommandsMustBeSigned(t *testing.T) {
	mustSign := map[command.Type]bool{
		command.PROGRAM_INSULIN: true, // 0x1a, before basal, temp basal or bolus
		command.DEACTIVATE:      true, // 0x1c
		command.STOP_DELIVERY:   true, // 0x1f
	}
	for _, t2 := range []command.Type{
		command.SET_UNIQUE_ID, command.GET_VERSION, command.GET_STATUS,
		command.SILENCE_ALERTS, command.PROGRAM_ALERTS, command.PROGRAM_INSULIN,
		command.DEACTIVATE, command.PROGRAM_BEEPS, command.STOP_DELIVERY,
		command.CNFG_DELIV_FLAG,
	} {
		if got := o5RequiresSignature(t2); got != mustSign[t2] {
			t.Errorf("command 0x%02x (%s) requires a signature: %v, want %v", t2, command.CommandName[t2], got, mustSign[t2])
		}
	}
}

// The pod reports the product the phone expects for its mode; a mismatch
// makes OmnipodKit refuse the pod during setup.
func TestProductFollowsMode(t *testing.T) {
	if got := testPod(t, bluetooth.ModeO5).product().ID; got != response.ProductIDOmnipod5 {
		t.Errorf("an Omnipod 5 reports product 0x%02x, want 0x%02x", got, response.ProductIDOmnipod5)
	}
	if got := testPod(t, bluetooth.ModeDash).product().ID; got != response.ProductIDDash {
		t.Errorf("a DASH reports product 0x%02x, want 0x%02x", got, response.ProductIDDash)
	}
}

// A state file written before the simulator could be an Omnipod 5 holds no
// mode, and that pod is a DASH.
func TestStateRemembersItsMode(t *testing.T) {
	for _, tc := range []struct {
		saved string
		want  bluetooth.Mode
	}{
		{"", bluetooth.ModeDash},
		{"dash", bluetooth.ModeDash},
		{"o5", bluetooth.ModeO5},
	} {
		s := &PODState{Mode: tc.saved}
		if got := s.PodMode(); got != tc.want {
			t.Errorf("a state holding %q is a %s pod, want %s", tc.saved, got, tc.want)
		}
	}
}

// The controller id ends up where the status page and the advertisement
// read it from.
func TestPdmIdKept(t *testing.T) {
	p := testPod(t, bluetooth.ModeO5)
	p.state.PdmId = 0x002A1C6C
	p.takeSnapshot()
	if got := p.Status().Controller; got != "002A1C6C" {
		t.Errorf("the status shows controller %q, want 002A1C6C", got)
	}
	if got := p.Status().PodType; got != "Omnipod 5" {
		t.Errorf("the status shows pod type %q, want Omnipod 5", got)
	}
}

// A sanity check on the command builder these tests rely on: the sequence
// number and the body have to survive the round trip.
func TestCommandBuilderRoundTrip(t *testing.T) {
	cmd := parseCommand(t, []byte{0x0e, 0x00, 0x00})
	if cmd.GetType() != command.GET_STATUS {
		t.Errorf("the command came back as 0x%02x, want 0x0e", cmd.GetType())
	}
	seq, id, err := cmd.GetHeaderData()
	if err != nil {
		t.Fatal(err)
	}
	if seq != 3 {
		t.Errorf("the sequence is %d, want 3", seq)
	}
	if binary.BigEndian.Uint32(id) != 0x002A1C6D {
		t.Errorf("the address is %x, want 002a1c6d", id)
	}
}
