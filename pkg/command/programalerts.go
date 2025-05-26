package command

import (
	"github.com/avereha/pod/pkg/response"
	log "github.com/sirupsen/logrus"
)

type ProgramAlerts struct {
	Seq       uint8
	ID        []byte
	AlertMask uint8
}

func UnmarshalProgramAlerts(data []byte) (*ProgramAlerts, error) {
	ret := &ProgramAlerts{}
	log.Debugf("ProgramAlerts, 0x19, received, data %x", data)

	// 19 LL NNNNNNNN IVXX YYYY 0J0K IVXX YYYY 0J0K IVXX YYYY 0J0K IVXX YYYY 0J0K   11 05 NNNNNNNN MM
	//    1c 494e532e 2800 125e 060f 3800 0b56 030f 4c00 01ea 010f 79a4 10ba 050f   11 05 494e532e ff
	//     0  1 2 3 4  5 6  7 8  910 1112 1314 1516 1718 1920 2122 2324 2526 2728
	const bytesPerAlert = 6
	const offsetAlert0 = 5
	ret.AlertMask = 0
	var nAlerts = int((data[0] + 1 - offsetAlert0) / bytesPerAlert)
	for i := 0; i < nAlerts; i++ {
		// IVXX = 0iiiabcx xxxxxxxx, extract 3 bit iii value and
		// turn into mask to be used to clear any triggered alerts.
		// We don't (yet) emulate alert triggers based on alert programming though.
		var alertNum = (data[offsetAlert0 + (i * bytesPerAlert)] & 0x70) >> 4
		ret.AlertMask |= (1 << alertNum)
	}
	log.Debugf("ProgramAlerts, AlertMask 0x%x", ret.AlertMask)
	return ret, nil
}

func (g *ProgramAlerts) GetSeq() uint8 {
	return g.Seq
}

func (g *ProgramAlerts) IsResponseHardcoded() bool {
	return false
}

func (g *ProgramAlerts) DoesMutatePodState() bool {
	return true
}

func (g *ProgramAlerts) GetResponse() (response.Response, error) {
	return &response.GeneralStatusResponse{}, nil
}

func (g *ProgramAlerts) SetHeaderData(seq uint8, id []byte) error {
	g.ID = id
	g.Seq = seq
	return nil
}

func (g *ProgramAlerts) GetHeaderData() (uint8, []byte, error) {
	return g.Seq, g.ID, nil
}

func (g *ProgramAlerts) GetPayload() Payload {
	return nil
}

func (g *ProgramAlerts) GetType() Type {
	return PROGRAM_ALERTS
}
