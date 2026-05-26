package command

import (
	"github.com/avereha/pod/pkg/pair"
	"github.com/avereha/pod/pkg/response"
	log "github.com/sirupsen/logrus"
)

type SetUniqueID struct {
	Seq     uint8
	ID      []byte
	Payload []byte
}

func UnmarshalSetUniqueID(data []byte) (*SetUniqueID, error) {
	ret := &SetUniqueID{}
	log.Debugf("SetUniqueID, 0x03, received, data %x", data)
	ret.Payload = make([]byte, 4)
	copy(ret.Payload, data[1:5])
	log.Tracef("ret.UniqueId: %x", ret.Payload)
	return ret, nil
}

func (g *SetUniqueID) GetSeq() uint8 {
	return g.Seq
}

func (g *SetUniqueID) IsResponseHardcoded() bool {
	return true
}

func (g *SetUniqueID) DoesMutatePodState() bool {
	return true
}

func (g *SetUniqueID) GetResponse() (response.Response, error) {
	// TODO improve responses
	return &response.SetUniqueID{}, nil
}

// GetResponseForMode returns the SetUniqueID response stamped with the active
// pairing mode so the response layer can pick the right byte stream. Until
// Joe's O5 captures land, both modes yield the same bytes.
func (g *SetUniqueID) GetResponseForMode(mode pair.Mode) (response.Response, error) {
	return &response.SetUniqueID{Mode: mode}, nil
}

func (g *SetUniqueID) SetHeaderData(seq uint8, id []byte) error {
	g.ID = id
	g.Seq = seq
	return nil
}

func (g *SetUniqueID) GetHeaderData() (uint8, []byte, error) {
	return g.Seq, g.ID, nil
}

func (g *SetUniqueID) GetPayload() Payload {
	return g.Payload
}

func (g *SetUniqueID) GetType() Type {
	return SET_UNIQUE_ID
}
