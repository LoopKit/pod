package response

import (
	"bytes"
	"fmt"

	"github.com/avereha/pod/pkg/crc"
	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/mode"

	log "github.com/sirupsen/logrus"
)

type Response interface {
	Marshal() ([]byte, error)
}

type ResponseMetadata struct {
	CmdSeq uint8
	MsgSeq uint8
	AckSeq uint8

	RequestID []byte
	Src       []byte
	Dst       []byte

	// Mode decides the CRC: an Omnipod 5 ends its responses with the
	// Omnipod CRC16, which OmnipodKit checks; a DASH pod's CRC follows an
	// algorithm nobody has matched and OmnipodKit ignores it, so the
	// simulator sends zeros as it always has.
	Mode mode.Mode
}

func messageCRC(m mode.Mode, data []byte) []byte {
	if m.IsO5() {
		return crc.CRC16(data)
	}
	return []byte{0, 0}
}

func payloadWithHeaderAndCRC(rsp Response, seq uint8, responseID []byte, m mode.Mode) ([]byte, error) {
	var buf bytes.Buffer
	var header uint16
	var msgType uint16

	payload, err := rsp.Marshal()
	if err != nil {
		return nil, err
	}

	msgType = uint16(payload[0])

	// write header
	buf.Write(responseID) // 4 bytes
	if buf.Len() != 4 {
		return nil, fmt.Errorf("responseID should be 4 bytes, got:  %x", responseID)
	}
	seq &= 0x0F
	header = uint16(seq) << 10
	payloadLen := uint16(len(payload))
	header |= (payloadLen & 0x03FF) // last 10 bits

	buf.WriteByte(byte(header >> 8))
	buf.WriteByte(byte(header))
	buf.Write(payload)
	buf.Write(messageCRC(m, buf.Bytes()))

	log.Infof("pkg response 0x%x; HEX, %x", msgType, buf.Bytes())

	return buf.Bytes(), nil
}

func Marshal(rsp Response, metadata *ResponseMetadata) (*message.Message, error) {
	var buf bytes.Buffer

	payload, err := payloadWithHeaderAndCRC(rsp, metadata.CmdSeq, metadata.RequestID, metadata.Mode)
	if err != nil {
		return nil, err
	}

	buf.WriteString("0.0=")  // TODO figure out error cases: 0.2, 0.5, 0.0=00, 1.0=
	totalLen := len(payload) // length including header and CRC
	buf.WriteByte(byte(totalLen >> 8))
	buf.WriteByte(byte(totalLen))
	buf.Write(payload)

	return RawMessage(buf.Bytes(), metadata), nil
}

// RawMessage is the pod's reply carrying payload as it is, for an Omnipod
// 5 AID setup answer, which is plain text rather than an SLPE-wrapped
// Omnipod response.
func RawMessage(payload []byte, metadata *ResponseMetadata) *message.Message {
	msg := message.NewMessage(message.MessageTypeEncrypted, metadata.Src, metadata.Dst)
	msg.Payload = payload
	msg.SequenceNumber = metadata.MsgSeq
	msg.Ack = true
	msg.AckNumber = metadata.AckSeq
	msg.Eqos = 1 // It seems to be some sort of flag that this is a reply
	// TODO fill other msg fields
	return msg
}
