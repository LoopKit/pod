package testfixtures

import "testing"

func TestCapturesLoad(t *testing.T) {
	caps := Captures()
	if len(caps) != 3 {
		t.Fatalf("expected 3 captures, got %d", len(caps))
	}
	for _, c := range caps {
		if c.PDMSPS1 == nil || c.PodSPS1 == nil {
			t.Fatalf("%s: missing SPS1", c.Name)
		}
		if len(c.PDMSPS1.Public) != 64 || len(c.PDMSPS1.Nonce) != 16 {
			t.Fatalf("%s: PDM SPS1 sizes wrong", c.Name)
		}
		if len(c.PodSPS1.Public) != 64 || len(c.PodSPS1.Nonce) != 16 {
			t.Fatalf("%s: pod SPS1 sizes wrong", c.Name)
		}
		// SPS2.1 phone->pod is 634 cert + 8 tag = 642
		if len(c.PDMSPS21Ciphertext) != 642 {
			t.Errorf("%s: PDM SPS2.1 expected 642 bytes, got %d", c.Name, len(c.PDMSPS21Ciphertext))
		}
		// SPS2.1 pod->phone is 633 cert + 8 tag = 641
		if len(c.PodSPS21Ciphertext) != 641 {
			t.Errorf("%s: pod SPS2.1 expected 641 bytes, got %d", c.Name, len(c.PodSPS21Ciphertext))
		}
	}
}
