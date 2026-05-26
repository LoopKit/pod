package pair

import (
	"encoding/binary"
	"fmt"
)

// SPSDirection identifies which direction a pairing AES-CCM nonce is for.
type SPSDirection byte

const (
	// SPSWrite is PDM->Pod direction; the leading byte is 0x01 and the
	// nonce halves are pdmNonce[0:6] || podNonce[0:6].
	SPSWrite SPSDirection = 0x01
	// SPSRead is Pod->PDM direction; the leading byte is 0x02 and the
	// nonce halves are podNonce[0:6] || pdmNonce[0:6].
	SPSRead SPSDirection = 0x02
)

// spsNonceState tracks the per-side counters that participate in the SPS-nonce
// builder. The first 8 bytes of the 16-byte pdm/pod nonces from SPS1 are
// treated as a little-endian uint64 counter that increments after every SPS
// message in the matching direction.
//
// Mirrors O5KeyExchange.swift:138-162 (incrementNonceInPlace / getSPSNonce).
type spsNonceState struct {
	pdm []byte // 16 bytes
	pod []byte // 16 bytes
}

func newSPSNonceState(pdmNonce, podNonce []byte) (*spsNonceState, error) {
	if len(pdmNonce) != 16 || len(podNonce) != 16 {
		return nil, fmt.Errorf("spsNonce: pdmNonce and podNonce must be 16 bytes each (got %d, %d)", len(pdmNonce), len(podNonce))
	}
	s := &spsNonceState{
		pdm: make([]byte, 16),
		pod: make([]byte, 16),
	}
	copy(s.pdm, pdmNonce)
	copy(s.pod, podNonce)
	return s, nil
}

// build returns a fresh 13-byte SPS-nonce for the given direction.
//
//	write: [0x01] || pdmNonce[0:6] || podNonce[0:6]
//	read:  [0x02] || podNonce[0:6] || pdmNonce[0:6]
//
// Mirrors O5KeyExchange.swift:112-136.
func (s *spsNonceState) build(dir SPSDirection) []byte {
	out := make([]byte, 0, 13)
	out = append(out, byte(dir))
	switch dir {
	case SPSWrite:
		out = append(out, s.pdm[:6]...)
		out = append(out, s.pod[:6]...)
	case SPSRead:
		out = append(out, s.pod[:6]...)
		out = append(out, s.pdm[:6]...)
	default:
		panic(fmt.Sprintf("spsNonce: invalid direction %d", dir))
	}
	return out
}

// increment bumps the per-direction counter. The first 8 bytes of the matching
// nonce are interpreted as a little-endian uint64 and incremented by 1; the
// last 8 bytes are left unchanged. Mirrors O5KeyExchange.swift:152-162.
func (s *spsNonceState) increment(dir SPSDirection) {
	var target []byte
	switch dir {
	case SPSWrite:
		target = s.pdm
	case SPSRead:
		target = s.pod
	default:
		panic(fmt.Sprintf("spsNonce: invalid direction %d", dir))
	}
	v := binary.LittleEndian.Uint64(target[:8])
	v++
	binary.LittleEndian.PutUint64(target[:8], v)
}
