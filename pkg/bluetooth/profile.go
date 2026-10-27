package bluetooth

import (
	"encoding/binary"
	"fmt"
)

// Mode is the kind of pod being simulated. It decides the BLE profile, the
// pairing exchange and the product id in the pod's version responses.
type Mode string

const (
	ModeDash Mode = "dash"
	ModeO5   Mode = "o5"
)

// ParseMode reads a -mode value.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeDash:
		return ModeDash, nil
	case ModeO5:
		return ModeO5, nil
	}
	return "", fmt.Errorf("mode %q: want dash or o5", s)
}

// Description names the mode the way the control panel and the log do.
func (m Mode) Description() string {
	if m == ModeO5 {
		return "Omnipod 5"
	}
	return "Omnipod DASH"
}

// IsO5 says whether this is an Omnipod 5.
func (m Mode) IsO5() bool { return m == ModeO5 }

// Profile is what the two pod kinds do differently at the link layer
// (OmnipodKit's BlePodProfile).
type Profile struct {
	Mode   Mode
	Layout PacketLayout

	ServiceUUID  string
	CmdCharUUID  string
	DataCharUUID string
}

const (
	podServiceUUID   = "1A7E4024-E3ED-4464-8B7E-751E03D0DC5F"
	cmdCharUUID      = "1A7E2441-E3ED-4464-8B7E-751E03D0DC5F"
	dashDataCharUUID = "1A7E2442-E3ED-4464-8B7E-751E03D0DC5F"
	o5DataCharUUID   = "1A7E2443-E3ED-4464-8B7E-751E03D0DC5F"
)

// ProfileFor is the profile a mode runs on.
func ProfileFor(m Mode) Profile {
	if m.IsO5() {
		return Profile{
			Mode: ModeO5,
			// An Omnipod 5 fills a 247-byte ATT MTU, and skips the
			// RTS/CTS handshake a DASH does before every message.
			Layout: PacketLayout{
				MaxPayloadSize:           244,
				MaxFragments:             15,
				FirstHeaderWithoutMiddle: 7,
				FirstHeaderWithMiddle:    2,
				LastHeader:               6,
			},
			ServiceUUID:  podServiceUUID,
			CmdCharUUID:  cmdCharUUID,
			DataCharUUID: o5DataCharUUID,
		}
	}
	return Profile{
		Mode: ModeDash,
		Layout: PacketLayout{
			MaxPayloadSize:           20,
			MaxFragments:             15,
			FirstHeaderWithoutMiddle: 7,
			FirstHeaderWithMiddle:    2,
			LastHeader:               6,
		},
		ServiceUUID:  podServiceUUID,
		CmdCharUUID:  cmdCharUUID,
		DataCharUUID: dashDataCharUUID,
	}
}

// UsesRTS says whether a message exchange opens with RTS/CTS on the
// command characteristic. Only a DASH does; an Omnipod 5 writes its
// packets straight away and answers a finished message with SUCCESS
// (PeripheralManager.sendMessagePacket / readMessagePacket).
func (p Profile) UsesRTS() bool { return !p.Mode.IsO5() }

// O5NotPairedPdmId is the controller id an unpaired Omnipod 5 advertises.
const O5NotPairedPdmId uint32 = 0xFFFFFFFE

// o5AdvertisementUUID is the single service UUID an Omnipod 5 advertises:
// its controller's id, and a trailing status byte that goes from 00 to 02
// when the pod wants attention (o5ServiceAdvertisementUUID,
// o5FaultAdvertisementUUID).
func o5AdvertisementUUID(pdmId uint32, attention bool) string {
	status := "00"
	if attention {
		status = "02"
	}
	return fmt.Sprintf("CE1F923D-C539-48EA-7300-0A%08X%s", pdmId, status)
}

// AdvertisedServiceUUIDs is what the pod puts in kCBAdvDataServiceUUIDs:
// one 128-bit UUID for an Omnipod 5, and the nine 16-bit ones a DASH
// advertises.
func (p Profile) AdvertisedServiceUUIDs(podId []byte, pdmId uint32, state AdvertState) []string {
	if p.Mode.IsO5() {
		id := O5NotPairedPdmId
		if pdmId != 0 {
			id = pdmId
		}
		return []string{o5AdvertisementUUID(id, state.Fault != 0)}
	}
	var uuids []string
	for _, u := range AdvertisedServices(podId, state) {
		uuids = append(uuids, fmt.Sprintf("%04X", u))
	}
	return uuids
}

// O5PdmIdFromHello reads the controller id out of the phone's HELLO
// (PeripheralManager.sendHello writes 06 01 04 then the 4-byte id).
func O5PdmIdFromHello(cmd []byte) (uint32, bool) {
	if len(cmd) < 7 || cmd[0] != 0x06 {
		return 0, false
	}
	return binary.BigEndian.Uint32(cmd[3:7]), true
}
