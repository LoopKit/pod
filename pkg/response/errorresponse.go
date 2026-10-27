package response

// ErrorResponse is how a pod refuses a command it will not carry out:
// block type 06, the error code, any saved fault code, and the pod's
// progress (OmnipodKit's ErrorResponse).
type ErrorResponse struct {
	Code        uint8
	FaultEvent  uint8
	PodProgress PodProgress
}

// ErrorInvalidCommand is what an Omnipod 5 answers a command it cannot
// use, among them one that should have been signed and was not
// (ErrorResponseCode.o5InvalidCommand).
const ErrorInvalidCommand uint8 = 0x2A

func (r *ErrorResponse) Marshal() ([]byte, error) {
	return []byte{0x06, 0x03, r.Code, r.FaultEvent, byte(r.PodProgress)}, nil
}
