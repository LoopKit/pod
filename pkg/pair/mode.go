package pair

import "fmt"

// Mode selects which pairing protocol variant the simulator implements.
type Mode int

const (
	ModeDash Mode = iota
	ModeO5
)

func (m Mode) String() string {
	switch m {
	case ModeDash:
		return "dash"
	case ModeO5:
		return "o5"
	}
	return fmt.Sprintf("Mode(%d)", int(m))
}

// ParseMode parses "dash" or "o5"; case-insensitive is not supported because
// the flag value comes from a known small set.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "dash":
		return ModeDash, nil
	case "o5":
		return ModeO5, nil
	}
	return 0, fmt.Errorf("invalid pair mode %q (want dash or o5)", s)
}

// IsO5 returns true when this pairing context is operating in Omnipod 5 mode.
// Useful from packages where the local symbol `pair` shadows this package.
func (c *Pair) IsO5() bool { return c.Mode == ModeO5 }
