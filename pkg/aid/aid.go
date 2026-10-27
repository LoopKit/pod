// Package aid answers the Omnipod 5 "AID" setup commands OmnipodKit sends
// between AssignAddress (0x07) and SetupPod (0x03) during pairing
// (OmnipodKit O5AidCommands.swift, BlePodComms.o5SendAidSetupCommands).
//
// They travel in the same encrypted messages as Omnipod commands but are
// plain ASCII key=value text, not SLPE-wrapped:
//
//	S<feature>.<attribute>=<data>,G<feature>.<attribute>   set and get
//	G<feature>.<attribute>                                 get
//	SE<feature>.<attribute>=<data>                         extended set
//
// where <data> is text ("8") or raw bytes (the TDI and target profile).
// The pod answers "<feature>.<attribute>=<data>" with the value it holds,
// or "ES<feature>.<attribute>=0" to an extended set.
package aid

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// Kind is the form of an AID command.
type Kind int

const (
	KindSetGet Kind = iota
	KindGet
	KindExtendedSet
)

func (k Kind) String() string {
	switch k {
	case KindSetGet:
		return "set+get"
	case KindGet:
		return "get"
	case KindExtendedSet:
		return "extended set"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// Command is one parsed AID command.
type Command struct {
	Kind      Kind
	Feature   string // "255", "3", "2"
	Attribute string // "2", "1", "9", "7", "11", "12"
	Data      []byte // what a set sets; nil for a get
}

// The commands OmnipodKit sends, by feature.attribute.
const (
	UTC                     = "255.2" // SE255.2=<unix time>
	TDI                     = "3.2"   // 5 bytes: 00 03 00 0e 00
	TargetGlucoseProfile    = "3.1"   // 00c0 then 48 big-endian uint32 mg/dL
	DIA                     = "3.9"   // "8"
	EGV                     = "3.7"   // "3670015"
	AlgorithmInsulinHistory = "2.1"   // 00a8 then 24 seven-byte records
	PodStatus               = "3.11"  // older pods
	UnifiedPodStatus        = "3.12"
)

// IsCommand says whether a decrypted payload is an AID command rather than
// an SLPE-wrapped Omnipod command, which starts with "S0.0=" and a binary
// length.
func IsCommand(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	switch payload[0] {
	case 'G':
		return payload[1] >= '1' && payload[1] <= '9'
	case 'S':
		if payload[1] == 'E' {
			return payload[2] >= '1' && payload[2] <= '9'
		}
		// "S0.0=" is an Omnipod command; an AID feature is never 0.
		return payload[1] >= '1' && payload[1] <= '9'
	}
	return false
}

func splitFeatureAttribute(s string) (string, string, error) {
	dot := strings.IndexByte(s, '.')
	if dot < 1 || dot == len(s)-1 {
		return "", "", fmt.Errorf("malformed feature.attribute %q", s)
	}
	for _, r := range s[:dot] + s[dot+1:] {
		if r < '0' || r > '9' {
			return "", "", fmt.Errorf("malformed feature.attribute %q", s)
		}
	}
	return s[:dot], s[dot+1:], nil
}

// Parse reads a decrypted AID command.
func Parse(payload []byte) (*Command, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("AID command %q too short", payload)
	}
	if bytes.HasPrefix(payload, []byte("SE")) {
		eq := bytes.IndexByte(payload, '=')
		if eq < 0 {
			return nil, errors.New("extended set without '='")
		}
		f, a, err := splitFeatureAttribute(string(payload[2:eq]))
		if err != nil {
			return nil, err
		}
		return &Command{Kind: KindExtendedSet, Feature: f, Attribute: a, Data: append([]byte(nil), payload[eq+1:]...)}, nil
	}
	switch payload[0] {
	case 'S':
		eq := bytes.IndexByte(payload, '=')
		if eq < 0 {
			return nil, errors.New("set without '='")
		}
		f, a, err := splitFeatureAttribute(string(payload[1:eq]))
		if err != nil {
			return nil, err
		}
		// The data may hold any byte, so the get is found by its length.
		suffix := []byte(",G" + f + "." + a)
		if len(payload) < eq+1+len(suffix) || !bytes.HasSuffix(payload, suffix) {
			return nil, fmt.Errorf("set of %s.%s without its get", f, a)
		}
		return &Command{Kind: KindSetGet, Feature: f, Attribute: a, Data: append([]byte(nil), payload[eq+1:len(payload)-len(suffix)]...)}, nil
	case 'G':
		f, a, err := splitFeatureAttribute(string(payload[1:]))
		if err != nil {
			return nil, err
		}
		return &Command{Kind: KindGet, Feature: f, Attribute: a}, nil
	}
	return nil, fmt.Errorf("not an AID command: %q", payload)
}

// Key is the command's feature.attribute.
func (c *Command) Key() string { return c.Feature + "." + c.Attribute }

// ResponsePrefix is what the pod's answer starts with
// (O5AidCommands.responsePrefix, extendedSetResponsePrefix).
func (c *Command) ResponsePrefix() string {
	if c.Kind == KindExtendedSet {
		return "ES" + c.Key() + "="
	}
	return c.Key() + "="
}

// Encode is the command on the wire.
func (c *Command) Encode() []byte {
	switch c.Kind {
	case KindGet:
		return []byte("G" + c.Key())
	case KindExtendedSet:
		return append([]byte("SE"+c.Key()+"="), c.Data...)
	}
	out := append([]byte("S"+c.Key()+"="), c.Data...)
	return append(out, []byte(",G"+c.Key())...)
}

// Settings is what a pod holds of the values the phone set, by key.
type Settings map[string][]byte

// Respond answers a command and records what it set: an extended set is
// acknowledged with 0, a set is echoed back as the pod now holds it, and a
// get returns the held value or, for the status queries, a status.
func (s Settings) Respond(c *Command) []byte {
	prefix := []byte(c.ResponsePrefix())
	switch c.Kind {
	case KindExtendedSet:
		s[c.Key()] = c.Data
		return append(prefix, '0')
	case KindSetGet:
		s[c.Key()] = c.Data
		return append(prefix, c.Data...)
	}
	if v, ok := s[c.Key()]; ok {
		return append(prefix, v...)
	}
	switch c.Key() {
	case PodStatus:
		// A 2-byte length and a 28-byte body.
		return append(append(prefix, 0x00, 0x1c), make([]byte, 28)...)
	case UnifiedPodStatus:
		return append(prefix, make([]byte, 29)...)
	}
	return prefix
}
