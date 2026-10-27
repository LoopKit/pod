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

// An Omnipod 5 pairing message runs past 1000 bytes, and the length field
// holding that is 11 bits spread over two header bytes. Reading it a byte
// at a time silently wraps, which is how a 1089-byte SPS2 would come back
// as nonsense.
func TestLongPayloadLength(t *testing.T) {
	for _, size := range []int{0, 1, 20, 255, 256, 642, 1089, 2047} {
		msg := NewMessage(MessageTypePairing, []byte{0, 0x2a, 0x1c, 0x6c}, []byte{0xff, 0xff, 0xff, 0xfe})
		msg.Payload = make([]byte, size)
		for i := range msg.Payload {
			msg.Payload[i] = byte(i)
		}
		raw, err := msg.Marshal()
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}

		back, err := Unmarshal(raw)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if len(back.Payload) != size {
			t.Errorf("%d bytes came back as %d", size, len(back.Payload))
			continue
		}
		if hex.EncodeToString(back.Payload) != hex.EncodeToString(msg.Payload) {
			t.Errorf("%d bytes came back changed", size)
		}
	}
}

// wireMessage builds the bytes a message has on the wire. An encrypted
// payload is the ciphertext followed by its 8-byte tag, and the header's
// length field counts only the ciphertext: EncryptMessage marshals the
// plaintext message and then appends the tag to Raw, so the length that
// went into the header is the plaintext's.
func wireMessage(t *testing.T, msgType MessageType, ciphertext, tag, signature []byte) []byte {
	t.Helper()
	size := len(ciphertext)
	header := []byte{
		'T', 'W',
		0x00, byte(msgType),
		0x00, 0x00,
		byte(size >> 3), byte(size << 5),
		0x00, 0x2a, 0x1c, 0x6d,
		0x00, 0x2a, 0x1c, 0x6c,
	}
	out := append(append([]byte(nil), header...), ciphertext...)
	out = append(out, tag...)
	return append(out, signature...)
}

// A signed message carries 64 bytes of signature after the payload, and
// the length field counts neither those nor the payload's 8-byte tag
// (OmnipodKit's MessagePacket.asData and getCmdMessage).
func TestSignedMessage(t *testing.T) {
	ciphertext := make([]byte, 40)
	for i := range ciphertext {
		ciphertext[i] = byte(i)
	}
	tag := []byte{0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7}
	signature := make([]byte, SignatureLength)
	for i := range signature {
		signature[i] = byte(0xA0 + i%16)
	}
	raw := wireMessage(t, MessageTypeEncryptedSigned, ciphertext, tag, signature)

	back, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Type != MessageTypeEncryptedSigned {
		t.Errorf("type is %d, want %d", back.Type, MessageTypeEncryptedSigned)
	}
	if !back.EncryptedPayload {
		t.Error("a signed message should carry an encrypted payload")
	}
	if hex.EncodeToString(back.Signature) != hex.EncodeToString(signature) {
		t.Errorf("the signature came back as %x", back.Signature)
	}
	// The payload is the ciphertext and its tag, without the signature.
	wantPayload := append(append([]byte(nil), ciphertext...), tag...)
	if hex.EncodeToString(back.Payload) != hex.EncodeToString(wantPayload) {
		t.Errorf("the payload came back as %d bytes: %x", len(back.Payload), back.Payload)
	}

	// The signature covers the header and the payload, and nothing else.
	input := back.SigningInput()
	if want := 16 + len(wantPayload); len(input) != want {
		t.Fatalf("the signing input is %d bytes, want %d", len(input), want)
	}
	if hex.EncodeToString(input) != hex.EncodeToString(raw[:16+len(wantPayload)]) {
		t.Error("the signing input is not the header followed by the payload")
	}
}

// A signed message that stops short of its signature has to be refused
// rather than read past its end.
func TestSignedMessageTruncated(t *testing.T) {
	raw := wireMessage(t, MessageTypeEncryptedSigned, make([]byte, 24), make([]byte, 8), make([]byte, SignatureLength))
	for _, cut := range []int{1, SignatureLength / 2, SignatureLength} {
		if _, err := Unmarshal(raw[:len(raw)-cut]); err == nil {
			t.Errorf("a message %d bytes short of its signature was accepted", cut)
		}
	}
}

// An unsigned encrypted message still parses as it always did.
func TestEncryptedMessageUnchanged(t *testing.T) {
	raw := wireMessage(t, MessageTypeEncrypted, make([]byte, 16), make([]byte, 8), nil)
	back, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.Signature != nil {
		t.Error("an unsigned message came back with a signature")
	}
	if !back.EncryptedPayload || len(back.Payload) != 24 {
		t.Errorf("the payload came back as %d bytes", len(back.Payload))
	}
}

// A message type the pod does not know must be refused.
func TestUnknownMessageType(t *testing.T) {
	raw := wireMessage(t, MessageType(5), make([]byte, 8), nil, nil)
	if _, err := Unmarshal(raw); err == nil {
		t.Error("a message of an unknown type was accepted")
	}
}
