package response

import (
	"encoding/hex"

	"github.com/avereha/pod/pkg/pair"
)

// This is the special case - sent with the 0x011B response to 0x03 message

// dashSetUniqueIDResponseHex is the captured Dash byte stream returned by a
// real Dash pod for the SetUniqueID (0x03) command. Locking it as a named
// constant lets the regression test pin the exact bytes.
const dashSetUniqueIDResponseHex = "011B13881008340A50040A00010300040308146DB10006E45100001091"

// o5SetUniqueIDResponseHex is the Omnipod 5 byte stream for the same command,
// captured from a real Omnipod 5 pod (Pod Type ID 05, firmware 9.0.4, BLE
// firmware 5.0.2, Lot 261724721, TID 491153). Layout:
//
//	01 LL VVVV BR PR PP CP PL MXMYMZ IXIYIZ ID 0J LLLLLLLL TTTTTTTT IIIIIIII
//	01 1B 1388 10 08 34 0A 50 09 00 04 05 00 02 05 03 0F999A31 00077E91 00000000
//
// where MXMYMZ is the pod firmware version, IXIYIZ is the BLE-stack firmware,
// ID is the pod type identifier (0x05 = Omnipod 5), LLLLLLLL is the lot
// number, and TTTTTTTT is the per-pod TID.
const o5SetUniqueIDResponseHex = "011B13881008340A5009000405000205030F999A3100077E9100000000"

type SetUniqueID struct {
	Seq uint16

	// Mode selects which captured byte stream Marshal returns. Zero value
	// (pair.ModeDash) preserves the legacy behaviour for any caller that
	// constructs this struct without setting it.
	Mode pair.Mode
}

func (r *SetUniqueID) Marshal() ([]byte, error) {
	hexStr := dashSetUniqueIDResponseHex
	if r.Mode == pair.ModeO5 {
		hexStr = o5SetUniqueIDResponseHex
	}
	response, _ := hex.DecodeString(hexStr)

	return response, nil
}
