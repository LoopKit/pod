package eap

import (
	"encoding/hex"
	"github.com/wmnsk/milenage"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestEapAka_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		eap  *EapAka
	}{
		{
			name: "emtpy",
			eap:  &EapAka{},
		},
		{
			name: "success",
			eap: &EapAka{
				Code: CodeSuccess,
			},
		},
		{
			name: "challenge",
			eap: &EapAka{
				Code:    CodeRequest,
				SubType: SubTypeAkaChallenge,
				Attributes: map[AttributeType]*Attribute{
					AT_RAND: {
						Data: make([]byte, 16),
					},
					AT_CUSTOM_IV: {
						Data: make([]byte, 4),
					},
					AT_AUTN: {
						Data: make([]byte, 16),
					},
				},
			},
		},
		{
			name: "response",
			eap: &EapAka{
				Code:    CodeResponse,
				SubType: SubTypeAkaChallenge,
				Attributes: map[AttributeType]*Attribute{
					AT_RES: {
						Data: make([]byte, 8),
					},
					AT_CUSTOM_IV: {
						Data: make([]byte, 4),
					},
				},
			},
		},
		{
			name: "synchronization failure",
			eap: &EapAka{
				Code:    CodeResponse,
				SubType: SubTypeAkaSynchronizationFailure,
				Attributes: map[AttributeType]*Attribute{
					AT_AUTS: {
						Data: make([]byte, 14),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.eap.Marshal()
			if err != nil {
				t.Errorf("EapAka.Marshal() error = %v", err)
				return
			}

			back, err := Unmarshal(got)
			if err != nil {
				t.Error(err)
			}
			if diff := cmp.Diff(tt.eap, back); diff != "" {
				t.Errorf("EapAka.Unmarshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// challengeAutn builds the AUTN a controller sends for a given sequence
// number, the way OmnipodKit's SessionEstablisher does: SQN^AK, the AMF, then
// MAC-A over the lot.
func challengeAutn(t *testing.T, k, rand []byte, sqn uint64, amf uint16) []byte {
	t.Helper()
	op, _ := hex.DecodeString("cdc202d5123e20f62b6d676ac72cb318")
	_, _, _, ak, err := milenage.New(k, op, rand, 0, 0).F2345()
	if err != nil {
		t.Fatal(err)
	}
	mac, err := milenage.New(k, op, rand, sqn, amf).F1()
	if err != nil {
		t.Fatal(err)
	}
	autn := make([]byte, 16)
	for i := 0; i < 6; i++ {
		autn[i] = byte(sqn>>(8*uint(5-i))) ^ ak[i]
	}
	autn[6], autn[7] = byte(amf>>8), byte(amf)
	copy(autn[8:], mac)
	return autn
}

// A pod stores the sequence number of the last session it accepted, and
// CheckSqn only accepts one past it. Pairing therefore has to leave that at 0,
// because the controller's first session uses SQN 1: storing 1 makes the very
// first session look stale and the pod answers a synchronization failure
// instead of pairing. Both activation paths depend on this.
func TestCheckSqnAcceptsTheFirstSessionAfterPairing(t *testing.T) {
	k, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	rand, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	const amf = uint16(47545)

	for _, tc := range []struct {
		name    string
		stored  uint64
		sqn     uint64
		wantNew bool
	}{
		{"a freshly paired pod accepts the first session", 0, 1, true},
		{"storing 1 at pairing would refuse the first session", 1, 1, false},
		{"a later session is accepted", 1, 2, true},
		{"a replayed session is refused", 5, 5, false},
		{"an older session is refused", 5, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEapAkaChallenge(k, tc.stored)
			e.rand = rand
			e.autn = challengeAutn(t, k, rand, tc.sqn, amf)

			fresh, err := e.CheckSqn()
			if err != nil {
				t.Fatalf("CheckSqn: %v", err)
			}
			if fresh != tc.wantNew {
				t.Errorf("stored %d, challenge SQN %d: fresh=%v, want %v", tc.stored, tc.sqn, fresh, tc.wantNew)
			}
			if e.Sqn != tc.sqn {
				t.Errorf("CheckSqn read SQN %d, want %d", e.Sqn, tc.sqn)
			}
		})
	}
}
