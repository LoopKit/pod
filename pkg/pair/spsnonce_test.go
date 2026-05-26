package pair

import (
	"bytes"
	"testing"
)

func TestSPSNonceLayout(t *testing.T) {
	pdm := bytes.Repeat([]byte{0xAA}, 16)
	pod := bytes.Repeat([]byte{0xBB}, 16)
	s, err := newSPSNonceState(pdm, pod)
	if err != nil {
		t.Fatal(err)
	}

	w := s.build(SPSWrite)
	if len(w) != 13 {
		t.Fatalf("write nonce expected 13 bytes, got %d", len(w))
	}
	if w[0] != 0x01 {
		t.Errorf("write nonce[0] = %x, want 0x01", w[0])
	}
	if !bytes.Equal(w[1:7], bytes.Repeat([]byte{0xAA}, 6)) {
		t.Errorf("write nonce should start with pdm[0:6]: got %x", w[1:7])
	}
	if !bytes.Equal(w[7:13], bytes.Repeat([]byte{0xBB}, 6)) {
		t.Errorf("write nonce should end with pod[0:6]: got %x", w[7:13])
	}

	r := s.build(SPSRead)
	if r[0] != 0x02 {
		t.Errorf("read nonce[0] = %x, want 0x02", r[0])
	}
	if !bytes.Equal(r[1:7], bytes.Repeat([]byte{0xBB}, 6)) {
		t.Errorf("read nonce should start with pod[0:6]: got %x", r[1:7])
	}
}

func TestSPSNonceIncrementsLittleEndianFirst8(t *testing.T) {
	pdm := []byte{0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	pod := bytes.Repeat([]byte{0}, 16)
	s, err := newSPSNonceState(pdm, pod)
	if err != nil {
		t.Fatal(err)
	}

	// 0x000000000000fffe + 1 == 0x000000000000ffff
	s.increment(SPSWrite)
	if s.pdm[0] != 0xff || s.pdm[1] != 0xff {
		t.Fatalf("after 1 increment expected first 2 bytes ff ff, got %x %x", s.pdm[0], s.pdm[1])
	}
	// + 1 == 0x0000000000010000 (carry)
	s.increment(SPSWrite)
	if s.pdm[0] != 0x00 || s.pdm[1] != 0x00 || s.pdm[2] != 0x01 {
		t.Fatalf("after carry expected 00 00 01, got %x %x %x", s.pdm[0], s.pdm[1], s.pdm[2])
	}
	// last 8 bytes must be untouched
	for i := 8; i < 16; i++ {
		if s.pdm[i] != 0 {
			t.Errorf("byte %d should be 0, got %x", i, s.pdm[i])
		}
	}
}
