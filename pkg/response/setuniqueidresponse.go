package response

import (
	"encoding/binary"
	"encoding/hex"
)

// This is the special case - sent with the 0x011B response to 0x03 message

type SetUniqueID struct {
	Seq     uint16
	Product Product
}

func (r *SetUniqueID) Marshal() ([]byte, error) {
	response, _ := hex.DecodeString("011B13881008340A50040A00010300040308146DB10006E45100001091")
	product := r.Product.orDash()
	response[productIDOffset1B] = product.ID
	binary.BigEndian.PutUint32(response[lotOffset1B:], product.Lot)
	return response, nil
}
