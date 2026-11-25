package bluetooth

import "testing"

func TestRandomStaticAddressesAreStaticAndDiffer(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s := RandomStaticAddress()
		a, err := ParseStaticAddress(s)
		if err != nil {
			t.Fatalf("RandomStaticAddress made %q, which doesn't parse: %s", s, err)
		}
		if a[0]&0xC0 != 0xC0 {
			t.Fatalf("%s is not a static random address: the top two bits must be 1", s)
		}
		if seen[s] {
			t.Fatalf("%s came up twice in 100 addresses", s)
		}
		seen[s] = true
	}
}

func TestParseStaticAddress(t *testing.T) {
	a, err := ParseStaticAddress("C4:1F:22:9A:07:5E")
	if err != nil {
		t.Fatalf("a good address didn't parse: %s", err)
	}
	if a != [6]byte{0xC4, 0x1F, 0x22, 0x9A, 0x07, 0x5E} {
		t.Fatalf("parsed as % X, want C4 1F 22 9A 07 5E", a)
	}

	for _, bad := range []string{
		"",
		"C4:1F:22:9A:07",       // too short
		"C4:1F:22:9A:07:5E:00", // too long
		"c4:1f:22:9a:07:5e",    // not as RandomStaticAddress writes it
		"44:1F:22:9A:07:5E",    // not a static random address
	} {
		if _, err := ParseStaticAddress(bad); err == nil {
			t.Errorf("%q parsed, want an error", bad)
		}
	}
}
