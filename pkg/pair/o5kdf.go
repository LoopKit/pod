package pair

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// FirmwareID is the fixed 6-byte value the Omnipod 5 PDM firmware mixes into
// the pairing KDF. Source: OmnipodKit O5LTKExchanger.swift FIRMWARE_ID.
var FirmwareID = []byte{0x9b, 0x0a, 0xb9, 0x6a, 0x76, 0xf4}

// o5KDFInput builds the length-prefixed buffer that is hashed with SHA-256 to
// derive the (conf, ltk) pair during O5 pairing.
//
// Layout (each length is a 64-bit big-endian unsigned integer):
//
//	be64(len(FirmwareID))  || FirmwareID         (6 bytes)
//	be64(4)                || 0x00000000         (4 bytes)
//	be64(len(pdmPublic))   || pdmPublic          (64 bytes raw X||Y)
//	be64(len(podPublic))   || podPublic          (64 bytes raw X||Y)
//	be64(len(sharedSecret))|| sharedSecret       (32 bytes)
//
// Total: 8+6 + 8+4 + 8+64 + 8+64 + 8+32 = 210 bytes.
//
// Mirrors O5KeyExchange.swift:88-99.
func o5KDFInput(pdmPublic, podPublic, sharedSecret []byte) []byte {
	var buf bytes.Buffer
	writeLP := func(b []byte) {
		var lp [8]byte
		binary.BigEndian.PutUint64(lp[:], uint64(len(b)))
		buf.Write(lp[:])
		buf.Write(b)
	}
	writeLP(FirmwareID)
	writeLP([]byte{0x00, 0x00, 0x00, 0x00})
	writeLP(pdmPublic)
	writeLP(podPublic)
	writeLP(sharedSecret)
	return buf.Bytes()
}

// o5DeriveKeys derives the (conf, ltk) 16-byte keys from pairing inputs.
// Mirrors O5KeyExchange.swift:83-108.
func o5DeriveKeys(pdmPublic, podPublic, sharedSecret []byte) (conf, ltk []byte, err error) {
	if len(pdmPublic) != 64 {
		return nil, nil, fmt.Errorf("o5DeriveKeys: pdmPublic must be 64 bytes (raw X||Y), got %d", len(pdmPublic))
	}
	if len(podPublic) != 64 {
		return nil, nil, fmt.Errorf("o5DeriveKeys: podPublic must be 64 bytes (raw X||Y), got %d", len(podPublic))
	}
	if len(sharedSecret) != 32 {
		return nil, nil, fmt.Errorf("o5DeriveKeys: sharedSecret must be 32 bytes, got %d", len(sharedSecret))
	}
	sum := sha256.Sum256(o5KDFInput(pdmPublic, podPublic, sharedSecret))
	return sum[0:16], sum[16:32], nil
}
