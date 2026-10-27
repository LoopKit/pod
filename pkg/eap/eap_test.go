package eap

import (
	"encoding/hex"
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

// The AUTN OmnipodKit sent in its first session after pairing with the
// simulator: CheckSqn reads its SQN, 1, verifies MAC-A over it, takes it
// after a pairing (last SQN 0) and calls it stale once 1 has been used.
func TestCheckSqnTakesOmnipodKitsAutn(t *testing.T) {
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	challenge := func(lastSqn uint64) *EapAkaChallenge {
		return &EapAkaChallenge{
			k:       unhex("6c04db96dba94827bfb5e23d821552f2"),
			op:      unhex("cdc202d5123e20f62b6d676ac72cb318"),
			rand:    unhex("d4e5514ae04b0016b4fdeeab719b800f"),
			autn:    unhex("81590495535eb9b9e21e56a91fa03fcf"),
			lastSqn: lastSqn,
		}
	}
	e := challenge(0)
	if fresh, err := e.CheckSqn(); err != nil || !fresh || e.Sqn != 1 {
		t.Fatalf("after pairing: fresh %v, SQN %d, %v; want fresh, SQN 1", fresh, e.Sqn, err)
	}
	if fresh, err := challenge(1).CheckSqn(); err != nil || fresh {
		t.Errorf("SQN 1 again: fresh %v, %v; want stale", fresh, err)
	}
	bad := challenge(0)
	bad.autn[15] ^= 1
	if _, err := bad.CheckSqn(); err == nil {
		t.Error("an AUTN with a corrupted MAC-A verified")
	}
}
