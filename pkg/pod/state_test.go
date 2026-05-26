package pod

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	toml "github.com/pelletier/go-toml"

	"github.com/avereha/pod/pkg/pair"
)

func TestResolveMode(t *testing.T) {
	tests := []struct {
		name         string
		state        *PODState
		flagMode     pair.Mode
		fresh        bool
		wantResolved pair.Mode
		wantConflict bool
	}{
		{
			name:         "fresh start with o5 flag",
			state:        &PODState{Mode: pair.ModeO5},
			flagMode:     pair.ModeO5,
			fresh:        true,
			wantResolved: pair.ModeO5,
			wantConflict: false,
		},
		{
			name:         "fresh start overrides persisted dash with o5 flag",
			state:        &PODState{Mode: pair.ModeDash},
			flagMode:     pair.ModeO5,
			fresh:        true,
			wantResolved: pair.ModeO5,
			wantConflict: false,
		},
		{
			name:         "restart o5 with default dash flag picks o5 and flags conflict",
			state:        &PODState{Mode: pair.ModeO5},
			flagMode:     pair.ModeDash,
			fresh:        false,
			wantResolved: pair.ModeO5,
			wantConflict: true,
		},
		{
			name:         "restart matching dash",
			state:        &PODState{Mode: pair.ModeDash},
			flagMode:     pair.ModeDash,
			fresh:        false,
			wantResolved: pair.ModeDash,
			wantConflict: false,
		},
		{
			name:         "restart matching o5",
			state:        &PODState{Mode: pair.ModeO5},
			flagMode:     pair.ModeO5,
			fresh:        false,
			wantResolved: pair.ModeO5,
			wantConflict: false,
		},
		{
			name:         "legacy state (no mode field) with default dash flag",
			state:        &PODState{}, // Mode is zero == ModeDash
			flagMode:     pair.ModeDash,
			fresh:        false,
			wantResolved: pair.ModeDash,
			wantConflict: false,
		},
		{
			name:         "nil state defers to flag",
			state:        nil,
			flagMode:     pair.ModeO5,
			fresh:        false,
			wantResolved: pair.ModeO5,
			wantConflict: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, conflict := ResolveMode(tc.state, tc.flagMode, tc.fresh)
			if got != tc.wantResolved {
				t.Errorf("resolved mode = %v, want %v", got, tc.wantResolved)
			}
			if conflict != tc.wantConflict {
				t.Errorf("conflict = %v, want %v", conflict, tc.wantConflict)
			}
		})
	}
}

// TestNewDoesNotOverwriteO5StateWithDashFlag exercises the original PR audit
// bug: ./pod (with default -mode dash) against an O5 state.toml must not
// rewrite the file to mode = "dash".
func TestNewDoesNotOverwriteO5StateWithDashFlag(t *testing.T) {
	dir, err := ioutil.TempDir("", "podstate-")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	statePath := filepath.Join(dir, "state.toml")

	// Seed an O5 state on disk.
	seed := &PODState{Filename: statePath, Mode: pair.ModeO5}
	if err := seed.Save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	// Simulate the buggy invocation: user reruns ./pod with the default
	// -mode dash flag. main.go first calls ResolveMode to reconcile.
	loaded, err := NewState(statePath)
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	resolved, conflict := ResolveMode(loaded, pair.ModeDash, false)
	if !conflict {
		t.Fatalf("expected conflict to be reported, got false")
	}
	if resolved != pair.ModeO5 {
		t.Fatalf("expected resolved=O5, got %v", resolved)
	}

	// pod.New gets called with the resolved value (O5) and freshState=false.
	// We don't need a real bluetooth.Ble for the path under test, but
	// pod.New stores the value and calls state.Save() only on fresh starts.
	p := New(nil, statePath, false, resolved)
	if p == nil {
		t.Fatalf("New returned nil")
	}

	// Re-read state.toml from disk and confirm mode is still O5.
	raw, err := ioutil.ReadFile(statePath)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	var got PODState
	if err := toml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("toml unmarshal: %v", err)
	}
	if got.Mode != pair.ModeO5 {
		t.Errorf("persisted mode after restart = %v, want %v (O5)", got.Mode, pair.ModeO5)
	}
}

// TestNewFreshStartPersistsFlag confirms that on -fresh the flag value wins
// and is persisted to disk.
func TestNewFreshStartPersistsFlag(t *testing.T) {
	dir, err := ioutil.TempDir("", "podstate-")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	statePath := filepath.Join(dir, "state.toml")

	p := New(nil, statePath, true, pair.ModeO5)
	if p == nil {
		t.Fatalf("New returned nil")
	}

	raw, err := ioutil.ReadFile(statePath)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	var got PODState
	if err := toml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("toml unmarshal: %v", err)
	}
	if got.Mode != pair.ModeO5 {
		t.Errorf("persisted mode after fresh start = %v, want %v (O5)", got.Mode, pair.ModeO5)
	}
}
