package crc

import (
	"encoding/hex"
	"testing"
)

// The vector OmnipodKit's CRC16Tests checks.
func TestCRC16Sum(t *testing.T) {
	data, _ := hex.DecodeString("1f01482a10030e0100")
	if got := CRC16Sum(data); got != 0x802c {
		t.Errorf("CRC16Sum = %04x, want 802c", got)
	}
}

// Real pod messages carry their checksum in the last two bytes, so
// computing it over the rest has to give those bytes back. These are the
// messages in OmnipodKit's MessageTests.
func TestCRC16OverCapturedMessages(t *testing.T) {
	for _, encoded := range []string{
		"1f00ee84300a1d18003f1800004297ff8128",
		"ffffffff041d011b13881008340a5002070002070002030000a62b000447941f00ee878352",
		"ffffffff0c1d011b13881008340a50031b0008080004030812a011000c175717244389816c",
		"ffffffff04170115020700020700020e0000a5ad00053030971f08686301fd",
	} {
		msg, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		body, want := msg[:len(msg)-2], msg[len(msg)-2:]
		if got := CRC16(body); hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("CRC16(%s...) = %x, want %x", encoded[:12], got, want)
		}
	}
}

// The SPS0 pairing payload carries CRC-16/XMODEM, whose check value over
// "123456789" is the published 0x31c3.
func TestXMODEM(t *testing.T) {
	if got := XMODEM([]byte("123456789")); got != 0x31c3 {
		t.Errorf("XMODEM = %04x, want 31c3", got)
	}
}
