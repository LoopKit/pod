package response

import (
	"github.com/avereha/pod/pkg/mode"
)

// SetUniqueID is the 0x1B version response to the 0x03 SetupPod command
// (SetUniqueID here): the pulse size and rates, then the fields of the
// shorter response, then the pod's address.
//
//	01 1B VVVV BR PR PP CP PL MXMYMZ IXIYIZ ID 0J LLLLLLLL TTTTTTTT IIIIIIII
//	   1388 = 0.05 U pulses, 10 = 2 s per bolus pulse, 08 = 1 s per prime pulse,
//	   34 = 52 prime pulses, 0A = 10 cannula pulses, 50 = 80 hours
type SetUniqueID struct {
	PodIdentity
	PodProgress PodProgress
	Address     []byte // 4 bytes
}

// SetupPodResponse is the version response of a pod that has completed
// pairing with address id.
func SetupPodResponse(m mode.Mode, id []byte) *SetUniqueID {
	return &SetUniqueID{PodIdentity: Identity(m), PodProgress: PodProgressPairingCompleted, Address: id}
}

func (r *SetUniqueID) Marshal() ([]byte, error) {
	out := []byte{0x01, 0x1B, 0x13, 0x88, 0x10, 0x08, 0x34, 0x0A, 0x50}
	out = append(out, r.common(r.PodProgress)...)
	addr := make([]byte, 4)
	copy(addr, r.Address)
	return append(out, addr...), nil
}
