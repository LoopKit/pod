package response

// ErrorResponse is the 0x06 block a pod answers a command it rejects with:
// the error code, then the fault code (0 when none) and the pod progress
// (OmnipodKit ErrorResponse.swift).
//
//	06 03 EE FF 0P
type ErrorResponse struct {
	Code        uint8
	FaultEvent  uint8
	PodProgress PodProgress
}

// ErrorO5InvalidCommand is what an Omnipod 5 answers a command that had to
// be signed but was not (OmnipodKit ErrorResponseCode.o5InvalidCommand).
const ErrorO5InvalidCommand = 0x2A

func (r *ErrorResponse) Marshal() ([]byte, error) {
	return []byte{0x06, 0x03, r.Code, r.FaultEvent, byte(r.PodProgress) & 0x0f}, nil
}
