package pod

import (
	"path/filepath"
	"testing"

	"github.com/avereha/pod/pkg/mode"
)

// A restarted pod keeps the mode it was created with; -mode only decides
// a fresh pod.
func TestResolveModeKeepsTheSavedPod(t *testing.T) {
	for _, tc := range []struct {
		saved, flag  mode.Mode
		want         mode.Mode
		wantConflict bool
	}{
		{mode.O5, mode.O5, mode.O5, false},
		{mode.O5, mode.Dash, mode.O5, true},
		{mode.Dash, mode.O5, mode.Dash, true},
		{"", mode.Dash, mode.Dash, false}, // a state file from before modes
		{"", mode.O5, mode.Dash, true},
	} {
		got, conflict := ResolveMode(&PODState{Mode: tc.saved}, tc.flag)
		if got != tc.want || conflict != tc.wantConflict {
			t.Errorf("saved %q, -mode %q: got %q conflict=%v, want %q conflict=%v",
				tc.saved, tc.flag, got, conflict, tc.want, tc.wantConflict)
		}
	}
}

func TestModeIsSavedAndRestored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.toml")
	s := NewFreshState(path, mode.O5)
	s.ControllerID = []byte{0, 0x2a, 0x1c, 0x6c}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := NewState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != mode.O5 || string(got.ControllerID) != string(s.ControllerID) {
		t.Fatalf("restored mode %q controller %x", got.Mode, got.ControllerID)
	}
}
