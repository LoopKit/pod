// Package aid implements the Omnipod 5 "AID" (Algorithm Integration Device)
// setup-command exchange that runs between AssignAddress and SetupPod during
// pairing.
//
// On the wire, AID commands and responses are *plain ASCII* (no
// StringLengthPrefixEncoding wrapper) carried inside the same AES-CCM
// encrypted Type-1 transport that standard Omnipod commands use. The
// decrypted payload looks like one of:
//
//	"S<feature>.<attribute>=<data>,G<feature>.<attribute>"   // SET+GET
//	"G<feature>.<attribute>"                                  // GET only
//	"SE<feature>.<attribute>=<data>"                          // Extended SET
//
// Where <data> is either ASCII text (e.g. "8" for DIA) or raw binary bytes
// (e.g. for TDI / target BG profile). Responses use a matching prefix:
//
//	SET+GET / GET response: "<feature>.<attribute>=<data>"
//	Extended SET response:  "ES<feature>.<attribute>=0"
//
// Source: OmnipodKit O5AidCommands.swift and BleMessageTransport.swift
// (sendO5AidCommand).
package aid

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// Kind is the structural form of an AID command on the wire.
type Kind int

const (
	KindSetGet Kind = iota // S<f>.<a>=<data>,G<f>.<a>
	KindGet                // G<f>.<a>
	KindExtSet             // SE<f>.<a>=<data>
)

// Command is a parsed AID command from the controller.
type Command struct {
	Kind      Kind
	Feature   string // e.g. "3", "255", "2"
	Attribute string // e.g. "1", "2", "11", "12"
	Data      []byte // empty for KindGet
}

// IsAIDPayload returns true if `payload` looks like an AID command rather than
// a standard SLPE-wrapped Omnipod command (which would start with "S0.0=").
//
// AID command first byte is always ASCII 'S' or 'G'. SLPE-wrapped Omnipod
// commands also start with 'S' (`S0.0=`), so we look at the feature byte:
// AID always uses non-zero feature numbers, while standard commands use
// feature "0".
func IsAIDPayload(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	switch payload[0] {
	case 'G':
		// "G<digit>.<digit>" — anything that looks like that is AID.
		return payload[1] >= '0' && payload[1] <= '9'
	case 'S':
		// Standard SLPE Omnipod commands begin with literal "S0.0=" with a
		// length prefix following. AID commands begin with "S<feature>." or
		// "SE<feature>." where <feature> is something other than just "0".
		if payload[1] == 'E' {
			return true
		}
		// Distinguish "S0.0=" (standard) from "S<n>.<m>=" / "SE..." (AID).
		// Read up to the first '.' and check whether the feature is "0".
		dot := bytes.IndexByte(payload, '.')
		if dot < 1 || dot > 5 {
			return false
		}
		feature := string(payload[1:dot])
		return feature != "0"
	}
	return false
}

// Parse decodes a decrypted AID payload.
//
// The returned Command's Data is a sub-slice of payload — copy it if the
// caller wants to retain it past the next read.
func Parse(payload []byte) (*Command, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("aid: payload too short (%d bytes)", len(payload))
	}

	// Detect Extended SET first: "SE<f>.<a>=<data>"
	if bytes.HasPrefix(payload, []byte("SE")) {
		eq := bytes.IndexByte(payload, '=')
		if eq < 0 {
			return nil, errors.New("aid: SE command missing '='")
		}
		f, a, err := splitFeatureAttr(string(payload[2:eq]))
		if err != nil {
			return nil, fmt.Errorf("aid: SE: %w", err)
		}
		return &Command{Kind: KindExtSet, Feature: f, Attribute: a, Data: payload[eq+1:]}, nil
	}

	// SET+GET: "S<f>.<a>=<data>,G<f>.<a>"
	if payload[0] == 'S' {
		eq := bytes.IndexByte(payload, '=')
		if eq < 0 {
			return nil, errors.New("aid: S command missing '='")
		}
		f, a, err := splitFeatureAttr(string(payload[1:eq]))
		if err != nil {
			return nil, fmt.Errorf("aid: S: %w", err)
		}
		// Locate ",G<f>.<a>" suffix — search for ',' and verify the rest
		// matches the SET feature/attribute. Binary data may legally contain
		// commas, so we anchor by length: the suffix is exactly
		// ",G<f>.<a>" and nothing follows it.
		suffix := []byte(",G" + f + "." + a)
		if !bytes.HasSuffix(payload, suffix) {
			return nil, fmt.Errorf("aid: S command missing trailing %q", string(suffix))
		}
		data := payload[eq+1 : len(payload)-len(suffix)]
		return &Command{Kind: KindSetGet, Feature: f, Attribute: a, Data: data}, nil
	}

	// GET: "G<f>.<a>"
	if payload[0] == 'G' {
		f, a, err := splitFeatureAttr(string(payload[1:]))
		if err != nil {
			return nil, fmt.Errorf("aid: G: %w", err)
		}
		return &Command{Kind: KindGet, Feature: f, Attribute: a}, nil
	}

	return nil, fmt.Errorf("aid: unrecognised payload prefix %q", string(payload[:1]))
}

func splitFeatureAttr(s string) (string, string, error) {
	dot := strings.IndexByte(s, '.')
	if dot < 1 || dot == len(s)-1 {
		return "", "", fmt.Errorf("malformed feature.attribute %q", s)
	}
	return s[:dot], s[dot+1:], nil
}

// ResponsePrefix is the ASCII prefix the pod must emit in its response.
// Source: O5AidCommands.swift responsePrefix / extendedSetResponsePrefix.
func (c *Command) ResponsePrefix() string {
	if c.Kind == KindExtSet {
		return "ES" + c.Feature + "." + c.Attribute + "="
	}
	return c.Feature + "." + c.Attribute + "="
}

// Encode renders the command back to wire bytes. Used in tests.
func (c *Command) Encode() []byte {
	switch c.Kind {
	case KindSetGet:
		out := []byte("S" + c.Feature + "." + c.Attribute + "=")
		out = append(out, c.Data...)
		out = append(out, []byte(",G"+c.Feature+"."+c.Attribute)...)
		return out
	case KindGet:
		return []byte("G" + c.Feature + "." + c.Attribute)
	case KindExtSet:
		out := []byte("SE" + c.Feature + "." + c.Attribute + "=")
		out = append(out, c.Data...)
		return out
	}
	panic(fmt.Sprintf("aid: unknown kind %d", c.Kind))
}

// BuildResponse generates the pod's response payload for a parsed command.
//
// For now we implement plausible canned responses sufficient to satisfy
// OmnipodKit's activation flow, without modeling the underlying state:
//
//   - SE<f>.<a>=...     -> "ES<f>.<a>=0"  (ack)
//   - SET+GET S<f>.<a>= -> "<f>.<a>="     + echoed data
//   - GET G<f>.<a>      -> "<f>.<a>="     + canned per-attribute payload
//
// The opaque byte payloads we return for GET commands are crafted to match the
// shapes captured in `Omnipod5APK/BTSNOOP/ios_snoop2/comm1.log`. Real-pod
// fidelity (returning state-derived values) is the job of Step 5/7.
func (c *Command) BuildResponse() []byte {
	prefix := c.ResponsePrefix()
	switch c.Kind {
	case KindExtSet:
		return []byte(prefix + "0")
	case KindSetGet:
		out := []byte(prefix)
		out = append(out, c.Data...)
		return out
	case KindGet:
		body := cannedGetResponse(c.Feature, c.Attribute)
		out := []byte(prefix)
		out = append(out, body...)
		return out
	}
	return nil
}

// cannedGetResponse returns a placeholder body for AID GET commands. Phase-1
// activation only cares that the response *exists* and starts with the right
// prefix; OmnipodKit logs the raw bytes and continues. Sizes mirror what the
// captures show, so on-the-wire framing matches.
func cannedGetResponse(feature, attribute string) []byte {
	switch feature + "." + attribute {
	case "3.11":
		// Gen1 AID Pod Status: 28-byte body preceded by 2-byte length 0x001c.
		body := make([]byte, 30)
		body[0] = 0x00
		body[1] = 0x1c
		return body
	case "3.12":
		// Unified AID Pod Status: 29 bytes.
		return make([]byte, 29)
	}
	return nil
}
