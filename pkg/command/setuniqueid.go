package command

import (
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

// IsResponseHardcoded is false: the version response names the pod the
// simulator plays and carries the id this command set.
func (g *SetUniqueID) IsResponseHardcoded() bool {
	return false
}

func (g *SetUniqueID) DoesMutatePodState() bool {
	return true
}

func (g *SetUniqueID) GetResponse() (response.Response, error) {
	return response.SetupPodResponse("", g.Payload), nil
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
