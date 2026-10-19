package crc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The vector from OmnipodKit's CRC16Tests.
func TestCRC16MatchesOmnipodKit(t *testing.T) {
	in, _ := hex.DecodeString("1f01482a10030e0100")
	if got := CRC16Value(in); got != 0x802c {
		t.Fatalf("crc16 = %04x, want 802c", got)
	}
	if got := CRC16(in); !bytes.Equal(got, []byte{0x80, 0x2c}) {
		t.Fatalf("crc16 bytes = %x", got)
	}
}

// The SPS0 payloads seen in Omnipod 5 pairing captures: the phone's
// 00 01 09 a2 18 and the pod's 00 00 09 91 29.
func TestXMODEMMatchesTheSPS0Captures(t *testing.T) {
	if got := XMODEM([]byte{0x00, 0x01, 0x09}); got != 0xa218 {
		t.Fatalf("phone SPS0 crc = %04x, want a218", got)
	}
	if got := XMODEM([]byte{0x00, 0x00, 0x09}); got != 0x9129 {
		t.Fatalf("pod SPS0 crc = %04x, want 9129", got)
	}
}
