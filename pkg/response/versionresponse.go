package response

import (
	"encoding/binary"

	"github.com/avereha/pod/pkg/mode"
)

// Firmware is a pod's firmware or BLE firmware version.
type Firmware [3]byte

// PodIdentity is what a pod reports of itself in its two version responses
// (OmnipodKit VersionResponse.swift). The DASH values are the ones the
// simulator has always sent, which also appear in its advertisement; the
// Omnipod 5 ones are from OmnipodKit's O5CommLogFixtures.
type PodIdentity struct {
	Mode     mode.Mode
	Firmware Firmware
	BLE      Firmware
	Lot      uint32
	Tid      uint32
}

// Identity is the pod identity for a mode.
func Identity(m mode.Mode) PodIdentity {
	if m.IsO5() {
		return PodIdentity{Mode: mode.O5, Firmware: Firmware{9, 0, 3}, BLE: Firmware{6, 0, 2}, Lot: 0x0E986131, Tid: 0x000818A3}
	}
	return PodIdentity{Mode: mode.Dash, Firmware: Firmware{4, 10, 0}, BLE: Firmware{1, 3, 0}, Lot: 0x08146DB1, Tid: 0x0006E451}
}

func (p PodIdentity) common(progress PodProgress) []byte {
	out := append([]byte{}, p.Firmware[:]...)
	out = append(out, p.BLE[:]...)
	out = append(out, p.Mode.ProductID(), byte(progress))
	out = binary.BigEndian.AppendUint32(out, p.Lot)
	return binary.BigEndian.AppendUint32(out, p.Tid)
}

// VersionResponse is the 0x15 version response to the 0x07 AssignAddress
// command (GetVersion here): firmware, BLE firmware, product id, progress,
// lot, tid, a byte Eros pods use for gain and RSSI, and an address.
//
//	01 15 MXMYMZ IXIYIZ ID 0J LLLLLLLL TTTTTTTT GS IIIIIIII
type VersionResponse struct {
	PodIdentity
	PodProgress PodProgress
	GainRSSI    byte
	Address     uint32
}

// AssignAddressResponse is the version response for a pod that has just
// been told its address, as a real one answers.
func AssignAddressResponse(m mode.Mode) *VersionResponse {
	r := &VersionResponse{PodIdentity: Identity(m), PodProgress: PodProgressReminderInitialized, Address: 0xFFFFFFFF}
	if m.IsO5() {
		r.GainRSSI = 0x05 // as captured
	}
	return r
}

func (r *VersionResponse) Marshal() ([]byte, error) {
	out := append([]byte{0x01, 0x15}, r.common(r.PodProgress)...)
	out = append(out, r.GainRSSI)
	return binary.BigEndian.AppendUint32(out, r.Address), nil
}
