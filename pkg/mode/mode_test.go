package mode

import "testing"

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Mode
		err  bool
	}{
		{"dash", Dash, false},
		{"o5", O5, false},
		{"", "", true},
		{"O5", "", true},
		{"eros", "", true},
	} {
		got, err := Parse(tc.in)
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("Parse(%q) = %q, %v; want %q, err=%v", tc.in, got, err, tc.want, tc.err)
		}
	}
}

func TestZeroValueIsDash(t *testing.T) {
	var m Mode
	if m.IsO5() || m.String() != "dash" || m.ProductID() != 4 {
		t.Fatalf("zero value: IsO5=%v String=%q ProductID=%d", m.IsO5(), m, m.ProductID())
	}
	if !O5.IsO5() || O5.ProductID() != 5 {
		t.Fatal("O5 is not an Omnipod 5")
	}
}
