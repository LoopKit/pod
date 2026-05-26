package aid

import (
	"bytes"
	"testing"
)

func TestIsAIDPayload(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"standard SLPE", []byte{'S', '0', '.', '0', '=', 0x00, 0x10}, false},
		{"AID SET+GET", []byte("S3.2=hello,G3.2"), true},
		{"AID GET", []byte("G3.11"), true},
		{"AID Extended SET", []byte("SE255.2=12345"), true},
		{"AID GET 3.12", []byte("G3.12"), true},
		{"too short", []byte{'S'}, false},
		{"random bytes", []byte{0x01, 0x02, 0x03, 0x04}, false},
		// Regression cases: real-world Dash SLPE-wrapped command payloads
		// must NOT be classified as AID — they all begin with the literal
		// "S0.0=" envelope (feature "0"), and an O5-side AID parse would
		// silently corrupt the Dash command path otherwise. The body bytes
		// after the 2-byte length prefix include the command type
		// (data[6] in command.Unmarshal): 0x03 SET_UNIQUE_ID, 0x07
		// GET_VERSION, 0x0e GET_STATUS, 0x1a PROGRAM_INSULIN.
		{
			name: "Dash SET_UNIQUE_ID (S0.0= prefix)",
			// "S0.0=" + 2-byte length + 4-byte id + 2-byte lsf + 0x03 type
			// + body bytes + 2-byte crc + ",G0.0".
			data: append(
				append([]byte("S0.0="), 0x00, 0x15),
				append([]byte{
					0xff, 0xff, 0xff, 0xfe, // id
					0x00, 0x13, // lsf (seq=0,len=0x13)
					0x03, // SET_UNIQUE_ID
					// SetUniqueID body is large; just stub plausible bytes.
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
					0x11, // 17 body bytes (length=0x13 = 19 -> body+crc=19)
					0xab, 0xcd, // crc
				}, []byte(",G0.0")...)...,
			),
			want: false,
		},
		{
			name: "Dash GET_VERSION (S0.0= prefix)",
			// Empty-body GET_VERSION still has the S0.0= envelope.
			data: append(
				append([]byte("S0.0="), 0x00, 0x0a),
				append([]byte{
					0xff, 0xff, 0xff, 0xfe, // id
					0x00, 0x02, // lsf (len=2)
					0x07,       // GET_VERSION
					0x00,       // body
					0xab, 0xcd, // crc
				}, []byte(",G0.0")...)...,
			),
			want: false,
		},
		{
			name: "Dash GET_STATUS (S0.0= prefix)",
			data: append(
				append([]byte("S0.0="), 0x00, 0x0a),
				append([]byte{
					0xff, 0xff, 0xff, 0xfe, // id
					0x00, 0x02, // lsf
					0x0e,       // GET_STATUS
					0x00,       // body
					0xab, 0xcd, // crc
				}, []byte(",G0.0")...)...,
			),
			want: false,
		},
		{
			name: "Dash PROGRAM_INSULIN (S0.0= prefix)",
			data: append(
				append([]byte("S0.0="), 0x00, 0x10),
				append([]byte{
					0xff, 0xff, 0xff, 0xfe, // id
					0x00, 0x08, // lsf
					0x1a,                                     // PROGRAM_INSULIN
					0x13, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // body
					0xab, 0xcd, // crc
				}, []byte(",G0.0")...)...,
			),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAIDPayload(tc.data); got != tc.want {
				t.Errorf("IsAIDPayload(%q) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

func TestParseSetGet_ASCII(t *testing.T) {
	c, err := Parse([]byte("S3.9=8,G3.9"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != KindSetGet || c.Feature != "3" || c.Attribute != "9" || string(c.Data) != "8" {
		t.Fatalf("got %+v / %q", c, string(c.Data))
	}
}

func TestParseSetGet_Binary(t *testing.T) {
	bin := []byte{0x00, 0x03, 0x00, 0x0E, 0x00}
	payload := []byte("S3.2=")
	payload = append(payload, bin...)
	payload = append(payload, []byte(",G3.2")...)
	c, err := Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Data, bin) {
		t.Fatalf("data mismatch: %x vs %x", c.Data, bin)
	}
}

func TestParseSetGet_BinaryWithEmbeddedComma(t *testing.T) {
	// Binary blob can contain commas; the trailing ",G3.2" suffix is
	// length-anchored, not value-anchored.
	bin := []byte{0x00, ',', 'G', 0x03, ',', 'X'}
	payload := []byte("S3.2=")
	payload = append(payload, bin...)
	payload = append(payload, []byte(",G3.2")...)
	c, err := Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Data, bin) {
		t.Fatalf("data mismatch: %x vs %x", c.Data, bin)
	}
}

func TestParseGet(t *testing.T) {
	c, err := Parse([]byte("G3.11"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != KindGet || c.Feature != "3" || c.Attribute != "11" {
		t.Fatalf("got %+v", c)
	}
	if len(c.Data) != 0 {
		t.Errorf("GET should have empty Data")
	}
}

func TestParseExtSet(t *testing.T) {
	c, err := Parse([]byte("SE255.2=1234567890"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != KindExtSet || c.Feature != "255" || c.Attribute != "2" {
		t.Fatalf("got %+v", c)
	}
	if string(c.Data) != "1234567890" {
		t.Errorf("data = %q", string(c.Data))
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	for _, tc := range [][]byte{
		[]byte("S3.9=8,G3.9"),
		[]byte("G3.12"),
		[]byte("SE255.2=1700000000"),
	} {
		c, err := Parse(tc)
		if err != nil {
			t.Fatal(err)
		}
		got := c.Encode()
		if !bytes.Equal(got, tc) {
			t.Errorf("round-trip mismatch:\n have: %q\n want: %q", got, tc)
		}
	}
}

func TestBuildResponse(t *testing.T) {
	cases := []struct {
		in       []byte
		wantHead string
	}{
		{[]byte("SE255.2=1700000000"), "ES255.2=0"},
		{[]byte("S3.9=8,G3.9"), "3.9=8"},
		{[]byte("G3.12"), "3.12="},
	}
	for _, tc := range cases {
		c, err := Parse(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		resp := c.BuildResponse()
		if !bytes.HasPrefix(resp, []byte(tc.wantHead)) {
			t.Errorf("response %q should start with %q", resp, tc.wantHead)
		}
	}
}

func TestBuildResponseSetGetEchoesBinary(t *testing.T) {
	bin := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00}
	payload := []byte("S3.2=")
	payload = append(payload, bin...)
	payload = append(payload, []byte(",G3.2")...)
	c, err := Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	resp := c.BuildResponse()
	want := []byte("3.2=")
	want = append(want, bin...)
	if !bytes.Equal(resp, want) {
		t.Errorf("expected echo, got %x", resp)
	}
}
