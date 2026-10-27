package message

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func Test_PrintfromByteArray(t *testing.T) {
	tests := []string{
		"54,57,00,03,00,00,06,e0,ff,ff,ff,fe,00,00,02,42,00,00,00,00,53,50,53,31,3d,00,30,2f,e5,7d,a3,47,cd,62,43,15,28,da,ac,5f,bb,29,07,30,ff,f6,84,af,c4,cf,c2,ed,90,99,5f,58,cb,3b,74,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00",
	}
	for _, test := range tests {
		h := strings.Replace(test, ",", "", -1)
		h = strings.Replace(h, " ", "", -1)
		in, err := hex.DecodeString(h)
		if err != nil {
			t.Error(err)
		}
		msg, err := Unmarshal(in)
		if err != nil {
			t.Error(err)
		}
		spew.Dump(msg)
	}
}

// A payload longer than 255 bytes (an Omnipod 5 SPS2.1 or SPS2) keeps its
// full 11-bit length through Marshal and Unmarshal.
func TestLongPayloadLength(t *testing.T) {
	for _, n := range []int{255, 256, 651, 1105, 2047} {
		m := NewMessage(MessageTypePairing, []byte{1, 2, 3, 4}, []byte{0xff, 0xff, 0xff, 0xfe})
		m.Payload = make([]byte, n)
		for i := range m.Payload {
			m.Payload[i] = byte(i)
		}
		raw, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := Unmarshal(raw)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if len(got.Payload) != n {
			t.Fatalf("%d bytes: read %d", n, len(got.Payload))
		}
	}
}

// A signed (type 4) message carries its ciphertext and tag as the payload
// and the 64-byte signature after it, outside the header's length.
func TestEncryptedSignedCarriesASignature(t *testing.T) {
	plaintextLen := 40
	payload := make([]byte, plaintextLen+8)
	sig := make([]byte, SignatureSize)
	for i := range sig {
		sig[i] = 0xa0 + byte(i)
	}
	m := NewMessage(MessageTypeEncryptedSigned, []byte{0, 0x2a, 0x1c, 0x6c}, []byte{0, 0x2a, 0x1c, 0x6e})
	m.Payload = make([]byte, plaintextLen) // the header counts the plaintext
	m.SequenceNumber = 7
	m.Eqos = 1
	header, _ := m.Marshal()
	raw := append(append(append([]byte{}, header[:16]...), payload...), sig...)

	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != MessageTypeEncryptedSigned || !got.EncryptedPayload {
		t.Fatalf("type %d encrypted %v", got.Type, got.EncryptedPayload)
	}
	if len(got.Payload) != plaintextLen+8 || string(got.Signature) != string(sig) {
		t.Fatalf("payload %d bytes, signature %x", len(got.Payload), got.Signature)
	}
	if _, err := Unmarshal(raw[:len(raw)-1]); err == nil {
		t.Fatal("a truncated signature was accepted")
	}
}

// The two header bytes are independent: a flag in the first must not leak
// into the second.
func TestHeaderFlagsDoNotLeak(t *testing.T) {
	m := NewMessage(MessageTypeClear, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	m.Sas = true
	raw, _ := m.Marshal()
	if raw[2] != 0x10 || raw[3] != 0x00 {
		t.Fatalf("header bytes %02x %02x, want 10 00", raw[2], raw[3])
	}
}
