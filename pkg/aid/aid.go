// Package aid answers the Omnipod 5 setup commands the phone sends
// between pairing the pod and setting it up.
//
// These are not Omnipod command blocks: they are ASCII key-value pairs,
// sent through the same encrypted transport but without the S0.0= wrapper
// and without the acknowledgement that follows a command
// (OmnipodKit's O5AidCommands and BlePodComms.o5SendAidSetupCommands).
//
//	set and read   S<f>.<a>=<data>,G<f>.<a>   answered  <f>.<a>=<data>
//	read           G<f>.<a>                   answered  <f>.<a>=<data>
//	extended set   SE<f>.<a>=<data>           answered  ES<f>.<a>=0
//
// The pod keeps what it is told and reads it back, which is what a real
// pod does for every one of these the phone sends during activation.
package aid

import (
	"bytes"
	"fmt"
)

// Command is one parsed AID command.
type Command struct {
	// Kind is "set", "get" or "extended set".
	Kind string
	// Feature and Attribute name what is being set or read, as in "3.1".
	Feature   string
	Attribute string
	// Data is what a set carries. It may be ASCII or raw bytes.
	Data []byte
}

// Key is the "<feature>.<attribute>" this command addresses.
func (c Command) Key() string { return c.Feature + "." + c.Attribute }

func (c Command) String() string {
	if c.Kind == "get" {
		return fmt.Sprintf("%s %s", c.Kind, c.Key())
	}
	return fmt.Sprintf("%s %s = %x (%d bytes)", c.Kind, c.Key(), c.Data, len(c.Data))
}

// Looks returns true when a decrypted payload looks like an AID command
// rather than an Omnipod command block, which always begins "S0.0=".
func Looks(payload []byte) bool {
	if bytes.HasPrefix(payload, []byte("S0.0=")) {
		return false
	}
	return bytes.HasPrefix(payload, []byte("SE")) ||
		bytes.HasPrefix(payload, []byte("S")) ||
		bytes.HasPrefix(payload, []byte("G"))
}

// Parse reads one AID command.
func Parse(payload []byte) (Command, error) {
	switch {
	case bytes.HasPrefix(payload, []byte("SE")):
		feature, attribute, data, err := splitSet(payload[2:])
		if err != nil {
			return Command{}, err
		}
		return Command{Kind: "extended set", Feature: feature, Attribute: attribute, Data: data}, nil

	case bytes.HasPrefix(payload, []byte("S")):
		feature, attribute, rest, err := splitSet(payload[1:])
		if err != nil {
			return Command{}, err
		}
		// A set is followed by the read of the same attribute, which the
		// pod answers; the data is everything before that suffix.
		suffix := []byte(",G" + feature + "." + attribute)
		if !bytes.HasSuffix(rest, suffix) {
			return Command{}, fmt.Errorf("set of %s.%s does not end in %q: %x", feature, attribute, suffix, payload)
		}
		return Command{Kind: "set", Feature: feature, Attribute: attribute, Data: rest[:len(rest)-len(suffix)]}, nil

	case bytes.HasPrefix(payload, []byte("G")):
		feature, attribute, err := splitKey(payload[1:])
		if err != nil {
			return Command{}, err
		}
		return Command{Kind: "get", Feature: feature, Attribute: attribute}, nil
	}
	return Command{}, fmt.Errorf("not an AID command: %x", payload)
}

// splitSet reads "<feature>.<attribute>=" and returns what follows.
func splitSet(b []byte) (feature, attribute string, rest []byte, err error) {
	eq := bytes.IndexByte(b, '=')
	if eq < 0 {
		return "", "", nil, fmt.Errorf("AID set has no '=': %x", b)
	}
	feature, attribute, err = splitKey(b[:eq])
	if err != nil {
		return "", "", nil, err
	}
	return feature, attribute, b[eq+1:], nil
}

// splitKey reads "<feature>.<attribute>".
func splitKey(b []byte) (feature, attribute string, err error) {
	dot := bytes.IndexByte(b, '.')
	if dot < 0 {
		return "", "", fmt.Errorf("AID key has no '.': %x", b)
	}
	feature, attribute = string(b[:dot]), string(b[dot+1:])
	if feature == "" || attribute == "" {
		return "", "", fmt.Errorf("AID key %q is incomplete", string(b))
	}
	return feature, attribute, nil
}

// Store is what the pod remembers of what the phone set.
type Store struct {
	values map[string][]byte
}

func NewStore() *Store { return &Store{values: map[string][]byte{}} }

// Value returns what was set for a key.
func (s *Store) Value(key string) ([]byte, bool) {
	v, ok := s.values[key]
	return v, ok
}

// unifiedAidPodStatus is the answer to the status read the phone makes on
// a pod whose firmware is new enough (G3.12): a length and a body the
// phone only logs during setup.
var unifiedAidPodStatus = append([]byte{0x00, 0x1b}, make([]byte, 27)...)

// Respond keeps what a command sets and returns the payload to answer
// with, or nil for a command the pod should not answer.
func (s *Store) Respond(c Command) []byte {
	switch c.Kind {
	case "extended set":
		// An extended set is acknowledged, not read back.
		s.values[c.Key()] = append([]byte(nil), c.Data...)
		return []byte("ES" + c.Key() + "=0")

	case "set":
		s.values[c.Key()] = append([]byte(nil), c.Data...)
		return append([]byte(c.Key()+"="), c.Data...)

	case "get":
		if v, ok := s.values[c.Key()]; ok {
			return append([]byte(c.Key()+"="), v...)
		}
		// The two status reads are the only ones the phone makes without
		// having set the attribute first.
		if c.Key() == "3.12" || c.Key() == "3.11" {
			return append([]byte(c.Key()+"="), unifiedAidPodStatus...)
		}
		return []byte(c.Key() + "=")
	}
	return nil
}
