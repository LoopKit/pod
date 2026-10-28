package response

import (
	"encoding/binary"
	"testing"
)

// The phone refuses a pod whose version response reports a product other
// than the pod type the user picked, and decodes the lot number for the
// UI, so both have to follow the mode.
func TestVersionResponseProduct(t *testing.T) {
	for _, tc := range []struct {
		name    string
		product Product
		wantID  byte
		wantLot uint32
	}{
		{"default is a DASH", Product{}, ProductIDDash, LotDash},
		{"dash", DashProduct(), ProductIDDash, LotDash},
		{"omnipod 5", Omnipod5Product(), ProductIDOmnipod5, LotOmnipod5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			short, err := (&VersionResponse{Product: tc.product}).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if short[productIDOffset15] != tc.wantID {
				t.Errorf("0x15 product id = %02x, want %02x", short[productIDOffset15], tc.wantID)
			}
			if got := binary.BigEndian.Uint32(short[lotOffset15:]); got != tc.wantLot {
				t.Errorf("0x15 lot = %08x, want %08x", got, tc.wantLot)
			}

			long, err := (&SetUniqueID{Product: tc.product}).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if long[productIDOffset1B] != tc.wantID {
				t.Errorf("0x1B product id = %02x, want %02x", long[productIDOffset1B], tc.wantID)
			}
			if got := binary.BigEndian.Uint32(long[lotOffset1B:]); got != tc.wantLot {
				t.Errorf("0x1B lot = %08x, want %08x", got, tc.wantLot)
			}
		})
	}
}

// The lot numbers have to decode to the product code the phone shows, the
// way OmnipodKit's lotDecode reads them.
func TestLotProductCode(t *testing.T) {
	for _, tc := range []struct {
		lot  uint32
		want uint32
	}{
		{LotDash, 0x04},     // D1, DASH U100
		{LotOmnipod5, 0x07}, // H1, Omnipod 5 U100
	} {
		if got := (tc.lot >> 25) & 0x3f; got != tc.want {
			t.Errorf("lot %08x has product number %02x, want %02x", tc.lot, got, tc.want)
		}
	}
}
