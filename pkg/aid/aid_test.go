package aid

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// The nine setup commands OmnipodKit sends during an Omnipod 5 activation,
// built as O5AidCommands builds them, with the response prefix it then
// insists on (sendO5AidCommand throws if the answer does not start with it).
func TestRespondToActivationCommands(t *testing.T) {
	targets := make([]byte, 0, 2+48*4)
	targets = append(targets, 0x00, 0xc0)
	for i := 0; i < 48; i++ {
		targets = binary.BigEndian.AppendUint32(targets, 110)
	}
	history := append([]byte{0x00, 0xa8}, make([]byte, 168)...)

	for _, tc := range []struct {
		name       string
		payload    []byte
		wantPrefix string
		wantEcho   []byte // what must follow the prefix, when the phone can tell
	}{
		{
			name:       "UTC time",
			payload:    []byte("SE255.2=1761600000"),
			wantPrefix: "ES255.2=",
		},
		{
			name:       "therapy delivery information",
			payload:    append(append([]byte("S3.2="), 0x00, 0x03, 0x00, 0x0e, 0x00), []byte(",G3.2")...),
			wantPrefix: "3.2=",
			wantEcho:   []byte{0x00, 0x03, 0x00, 0x0e, 0x00},
		},
		{
			name:       "target BG profile",
			payload:    append(append([]byte("S3.1="), targets...), []byte(",G3.1")...),
			wantPrefix: "3.1=",
			wantEcho:   targets,
		},
		{
			name:       "duration of insulin action",
			payload:    []byte("S3.9=8,G3.9"),
			wantPrefix: "3.9=",
			wantEcho:   []byte("8"),
		},
		{
			name:       "glucose configuration",
			payload:    []byte("S3.7=3670015,G3.7"),
			wantPrefix: "3.7=",
			wantEcho:   []byte("3670015"),
		},
		{
			name:       "algorithm insulin history",
			payload:    append([]byte("SE2.1="), history...),
			wantPrefix: "ES2.1=",
		},
		{
			name:       "unified pod status",
			payload:    []byte("G3.12"),
			wantPrefix: "3.12=",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !Looks(tc.payload) {
				t.Fatalf("%q was not recognised as an AID command", tc.payload[:8])
			}
			cmd, err := Parse(tc.payload)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := NewStore().Respond(cmd)
			if !bytes.HasPrefix(got, []byte(tc.wantPrefix)) {
				t.Fatalf("answer %q does not start with %q", got, tc.wantPrefix)
			}
			if tc.wantEcho != nil {
				if echo := got[len(tc.wantPrefix):]; !bytes.Equal(echo, tc.wantEcho) {
					t.Errorf("answer echoed %x, want %x", echo, tc.wantEcho)
				}
			}
		})
	}
}

// A set is read back by a later read of the same attribute.
func TestStoreReadsBackWhatWasSet(t *testing.T) {
	store := NewStore()
	set, err := Parse([]byte("S3.9=8,G3.9"))
	if err != nil {
		t.Fatal(err)
	}
	store.Respond(set)

	get, err := Parse([]byte("G3.9"))
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Respond(get); string(got) != "3.9=8" {
		t.Errorf("read back %q, want %q", got, "3.9=8")
	}
}

// An Omnipod command block must not be mistaken for an AID command: both
// arrive on the same encrypted transport and only the payload tells them
// apart.
func TestOmnipodCommandIsNotAnAIDCommand(t *testing.T) {
	block := append([]byte("S0.0="), []byte{0x00, 0x0b, 0x00, 0x2a, 0x1c, 0x6d, 0x00, 0x03, 0x0e, 0x01, 0x00, 0x00, 0x00}...)
	block = append(block, []byte(",G0.0")...)
	if Looks(block) {
		t.Error("an S0.0= command block was taken for an AID command")
	}
}

// Binary data can hold the bytes that end a set command, so the parser has
// to split on the suffix rather than search for a comma.
func TestSetWithBinaryDataHoldingItsOwnSuffix(t *testing.T) {
	data := append([]byte(",G3.2"), 0x00, 0x01)
	payload := append(append([]byte("S3.2="), data...), []byte(",G3.2")...)
	cmd, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(cmd.Data, data) {
		t.Errorf("data is %x, want %x", cmd.Data, data)
	}
}

func TestParseRejectsRubbish(t *testing.T) {
	for _, payload := range []string{"", "S", "S3=1", "G", "G3", "S3.2=novalue"} {
		if _, err := Parse([]byte(payload)); err == nil {
			t.Errorf("Parse(%q) should have failed", payload)
		}
	}
}

func ExampleCommand_String() {
	cmd, _ := Parse([]byte("S3.9=8,G3.9"))
	fmt.Println(cmd)
	// Output: set 3.9 = 38 (1 bytes)
}

// An AID answer is acknowledged by the phone exactly as any other
// response is (OmnipodKit's sendO5AidCommand ends by sending an ACK), so
// an exchange is: command in, answer out, acknowledgement in. A pod that
// expects only the first two reads the acknowledgement as a command, and
// an acknowledgement carries no payload, so it does not parse as one.
func TestAcknowledgementIsNotAnAIDCommand(t *testing.T) {
	if Looks(nil) {
		t.Error("an empty acknowledgement was taken for an AID command")
	}
	if Looks([]byte{}) {
		t.Error("an empty acknowledgement was taken for an AID command")
	}
}
