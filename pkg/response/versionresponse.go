package response

import (
	"encoding/binary"
	"encoding/hex"
)

// There are different version response variants retrurned for the 0x7 and 0x3 commands.
// Byte 8 of the shorter 0x15 response for the 0x7 Assign ID command and the
// the byte 15 of the longer 0x1B response for the 0x3 Setup Pod command are
// the product id, which the phone checks against the pod type the user chose
// (OmnipodKit's VersionResponse and BlePodComms.setupPod).
const (
	// The product ids are OmnipodKit's PodType.PodModelType values.
	ProductIDDash     byte = 0x04
	ProductIDOmnipod5 byte = 0x05

	// 0x15 version response offsets
	productIDOffset15 = 8
	lotOffset15       = 10
	tidOffset15       = 14
)

const (
	// Lot numbers whose product code decodes the way the phone expects for
	// each kind of pod: bits 25-30 hold the product, 4 for a DASH U100 and 7
	// for an Omnipod 5 U100 (OmnipodKit's lotDecode).
	LotDash     uint32 = 0x084B9D91 // decodes as PD1U11111111
	LotOmnipod5 uint32 = 0x0E4B9D91 // decodes as PH1U11111111

	// Tid is the pod's sequence number within its lot.
	// This value is returned in the version respones.
	// Use per pod type values based on its product id #.
	TidDash     uint32 = 4444444
	TidOmnipod5 uint32 = 5555555
)

// Product is which pod the version responses report. The zero value is a
// DASH, which is what the simulator was before it could be anything else.
type Product struct {
	ID  byte
	Lot uint32
	Tid uint32
}

// DashProduct and Omnipod5Product are the two products the simulator serves.
func DashProduct() Product     { return Product{ID: ProductIDDash, Lot: LotDash, Tid: TidDash} }
func Omnipod5Product() Product { return Product{ID: ProductIDOmnipod5, Lot: LotOmnipod5, Tid: TidOmnipod5} }

func (p Product) orDash() Product {
	if p.ID == 0 {
		return DashProduct()
	}
	return p
}


type VersionResponse struct {
	Seq     uint16
	Product Product
}

// This is the VersionResponse sent with the shorter 0x15 response to 0x07 command.

func (r *VersionResponse) Marshal() ([]byte, error) {
	response, _ := hex.DecodeString("01150000000000000002000000000000000000FFFFFFFF")
	product := r.Product.orDash()

	// Patch in the Product specific ID, Lot and TID values.
	response[productIDOffset15] = product.ID
	binary.BigEndian.PutUint32(response[lotOffset15:], product.Lot)
	binary.BigEndian.PutUint32(response[tidOffset15:], product.Tid)

	// Keep the fixed 0.0.0 values for the firmware and iFirmware for simulated pods.
	return response, nil
}
