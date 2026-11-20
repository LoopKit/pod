package response

import (
	"encoding/binary"
	"encoding/hex"
)

// This is a special case as there are two varients for the  0x7 and 0x3 commands.
// This is the longer 0x1B VersionResponse varient for 0x03 setuniqueid command.

const (
	// 0x1B version response offsets
	firmwareOffset1B  = 9
	productIDOffset1B = 15
	lotOffset1B       = 17
	tidOffset1B       = 21
	addressOffset1B   = 25
)

type SetUniqueID struct {
	Seq     uint16
	Product Product
}

func (r *SetUniqueID) Marshal() ([]byte, error) {
	response, _ := hex.DecodeString("011B13881008340A500000000000000003000000000000000000000000")
	product := r.Product.orDash()

	// Patch in the Product specific ID, Lot and TID values
	response[productIDOffset1B] = product.ID
	binary.BigEndian.PutUint32(response[lotOffset1B:], product.Lot)
	binary.BigEndian.PutUint32(response[tidOffset1B:], product.Tid)

	// Keep the fixed 0.0.0 values for the firmware and iFirmware for simulated pods.

	// Should also do the work to patch in our configured pod address,
	// but this isn't checked by OmnipodKit so can leave 0 for now.
	return response, nil
}
