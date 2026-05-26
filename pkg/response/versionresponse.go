package response

import (
	"encoding/hex"

	"github.com/avereha/pod/pkg/pair"
)

// This is the special case - sent with the 0x0115 response to 0x07 message

// dashVersionResponseHex is the captured Dash byte stream returned by a real
// Dash pod for the GetVersion (0x07) command. Locking it as a named constant
// lets the regression test pin the exact bytes.
const dashVersionResponseHex = "0115040A00010300040208146DB10006E45100FFFFFFFF"

// o5VersionResponseHex is the Omnipod 5 byte stream for the same command,
// captured from a real Omnipod 5 pod (Pod Type ID 05, firmware 9.0.4, BLE
// firmware 5.0.2, Lot 261724721, TID 491153). Layout:
//
//	01 LL MXMYMZ IXIYIZ ID 0J LLLLLLLL TTTTTTTT GS IIIIIIII
//	01 15 09 00 04 05 00 02 05 02 0F999A31 00077E91 05 FFFFFFFF
//
// where MXMYMZ is the pod firmware version, IXIYIZ is the BLE-stack firmware,
// ID is the pod type identifier (0x05 = Omnipod 5), LLLLLLLL is the lot
// number, TTTTTTTT is the per-pod TID, and GS is a gain/status-style byte
// not present in the Dash variant.
const o5VersionResponseHex = "011509000405000205020F999A3100077E9105FFFFFFFF"

type VersionResponse struct {
	Seq uint16

	// Mode selects which captured byte stream Marshal returns. Zero value
	// (pair.ModeDash) preserves the legacy behaviour for any caller that
	// constructs this struct without setting it.
	Mode pair.Mode
}

func (r *VersionResponse) Marshal() ([]byte, error) {
	hexStr := dashVersionResponseHex
	if r.Mode == pair.ModeO5 {
		hexStr = o5VersionResponseHex
	}
	response, _ := hex.DecodeString(hexStr)

	return response, nil
}
