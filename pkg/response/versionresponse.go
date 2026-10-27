package response

import (
	"encoding/binary"
	"encoding/hex"
)

// The version responses a pod returns to the two setup commands. Byte 8 of
// the 0x15 answer and byte 15 of the 0x1B one are the product id, which the
// phone checks against the pod type the user chose
// (OmnipodKit's VersionResponse and BlePodComms.setupPod).
const (
	// The product ids are OmnipodKit's PodType.PodModelType values.
	ProductIDDash     byte = 0x04
	ProductIDOmnipod5 byte = 0x05

	productIDOffset15 = 8
	productIDOffset1B = 15
	lotOffset15       = 10
	lotOffset1B       = 17
)

// Lot numbers whose product code decodes the way the phone expects for
// each kind of pod: bits 25-30 hold the product, 4 for a DASH U100 and 7
// for an Omnipod 5 U100 (OmnipodKit's lotDecode).
const (
	LotDash     uint32 = 0x08146DB1 // decodes as D1
	LotOmnipod5 uint32 = 0x0E146DB1 // decodes as H1
)

// Product is which pod the version responses report. The zero value is a
// DASH, which is what the simulator was before it could be anything else.
type Product struct {
	ID  byte
	Lot uint32
}

// DashProduct and Omnipod5Product are the two the simulator serves.
func DashProduct() Product     { return Product{ID: ProductIDDash, Lot: LotDash} }
func Omnipod5Product() Product { return Product{ID: ProductIDOmnipod5, Lot: LotOmnipod5} }

func (p Product) orDash() Product {
	if p.ID == 0 {
		return DashProduct()
	}
	return p
}

// This is the special case - sent with the 0x0115 response to 0x07 message

type VersionResponse struct {
	Seq     uint16
	Product Product
}

func (r *VersionResponse) Marshal() ([]byte, error) {
	response, _ := hex.DecodeString("0115040A00010300040208146DB10006E45100FFFFFFFF")
	product := r.Product.orDash()
	response[productIDOffset15] = product.ID
	binary.BigEndian.PutUint32(response[lotOffset15:], product.Lot)
	return response, nil
}
