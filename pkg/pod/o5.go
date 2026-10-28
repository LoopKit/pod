package pod

import (
	"github.com/avereha/pod/pkg/aid"
	"github.com/avereha/pod/pkg/command"
	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/pair"
	"github.com/avereha/pod/pkg/response"

	log "github.com/sirupsen/logrus"
)

// startO5Activation pairs the pod as an Omnipod 5. The exchange runs in
// the same shape as the DASH one — the phone writes, the pod answers — but
// with two more rounds, in which each side shows a certificate and signs
// what has been said (OmnipodKit's O5LTKExchanger).
func (p *Pod) startO5Activation() {
	o5, err := pair.NewO5()
	if err != nil {
		p.startOver("could not make the pod's pairing keys: %s", err)
		return
	}

	// Each step reads the phone's message and answers it. A reply of nil
	// means the phone speaks next without the pod saying anything.
	steps := []struct {
		name  string
		parse func(*message.Message) error
		reply func() (*message.Message, error)
	}{
		{"SP1SP2", o5.ParseSP1SP2, nil},
		{"SPS0", o5.ParseSPS0, o5.GenerateSPS0},
		{"SPS1", o5.ParseSPS1, o5.GenerateSPS1},
		{"SPS2.1", o5.ParseSPS21, o5.GenerateSPS21},
		{"SPS2", o5.ParseSPS2, o5.GenerateSPS2},
		{"SP0GP0", o5.ParseSP0GP0, o5.GenerateP0},
	}

	for _, step := range steps {
		msg, ok := p.readSetup()
		if !ok {
			return
		}
		if err := step.parse(msg); err != nil {
			p.startOver("error parsing %s: %s", step.name, err)
			return
		}
		log.Infof("pkg pod; Received %s", step.name)
		if step.reply == nil {
			continue
		}
		reply, err := step.reply()
		if err != nil {
			p.startOver("could not answer %s: %s", step.name, err)
			return
		}
		p.ble.WriteMessage(reply)
	}

	ltk, err := o5.LTK()
	if err != nil {
		p.startOver("pairing produced no long-term key: %s", err)
		return
	}

	p.mtx.Lock()
	p.state.LTK = ltk
	p.state.Id = o5.PodID()
	p.state.ControllerPublic = o5.ControllerPublic()
	if pdmId := o5.PdmID(); len(pdmId) == 4 {
		p.state.PdmId = uint32(pdmId[0])<<24 | uint32(pdmId[1])<<16 | uint32(pdmId[2])<<8 | uint32(pdmId[3])
	}
	p.state.EapAkaSeq = 0 // the controller's first session uses SQN 1
	pdmId := p.state.PdmId
	if err := p.state.Save(); err != nil {
		log.Errorf("pkg pod; could not save the pod state: %s", err)
	}
	p.mtx.Unlock()

	log.Infof("pkg pod; LTK %x", ltk)
	p.ble.SetPdmId(pdmId)

	p.EapAka()
}

// o5RequiresSignature says whether an Omnipod 5 refuses this command
// unless it arrived signed. A real pod insists on a signature for
// everything that starts or stops insulin
// (OmnipodKit's requiresType4Signing).
func o5RequiresSignature(t command.Type) bool {
	switch t {
	case command.PROGRAM_INSULIN, // 0x1a, which precedes basal, temp basal and bolus
		command.DEACTIVATE,    // 0x1c
		command.STOP_DELIVERY: // 0x1f
		return true
	}
	return false
}

// checkO5Signature decides whether a command may be carried out. A
// command that needs a signature must carry one that verifies against the
// controller key the pod kept while pairing; anything else is refused the
// way a real pod refuses it.
//
// signingInput must be taken before the message is decrypted: the
// signature covers the header and the still-encrypted payload.
func (p *Pod) checkO5Signature(cmd command.Command, msgType message.MessageType, signature, signingInput []byte) response.Response {
	if !p.isO5() || !o5RequiresSignature(cmd.GetType()) {
		return nil
	}

	name := command.CommandName[cmd.GetType()]
	switch {
	case msgType != message.MessageTypeEncryptedSigned || signature == nil:
		log.Errorf("pkg pod; %s arrived unsigned; refusing it with error 0x%02x", name, response.ErrorInvalidCommand)
	case !pair.VerifyP256(p.state.ControllerPublic, signingInput, signature):
		log.Errorf("pkg pod; the signature on %s does not verify; refusing it with error 0x%02x", name, response.ErrorInvalidCommand)
	default:
		log.Infof("pkg pod; the signature on %s verifies", name)
		return nil
	}

	p.state.SignedRejected++
	return &response.ErrorResponse{
		Code:        response.ErrorInvalidCommand,
		FaultEvent:  p.state.FaultEvent,
		PodProgress: p.state.PodProgress,
	}
}

// handleAidCommand answers one of the Omnipod 5 setup commands the phone
// sends between pairing and setting the pod up. They go through the same
// encrypted transport as a command but are not command blocks, and the
// phone does not acknowledge the answer, so this consumes two nonces
// rather than three (OmnipodKit's sendO5AidCommand).
//
// It reports whether the exchange is still in step.
func (p *Pod) handleAidCommand(payload []byte, src, dst []byte, seq uint8) bool {
	cmd, err := aid.Parse(payload)
	if err != nil {
		log.Errorf("pkg pod; could not read the AID command %x: %s", payload, err)
		return false
	}
	log.Infof("pkg pod; AID %s", cmd)

	answer := p.aid.Respond(cmd)
	if answer == nil {
		log.Warnf("pkg pod; no answer for AID %s", cmd)
		return false
	}
	log.Debugf("pkg pod; answering AID %s with %q", cmd.Key(), answer)

	p.state.MsgSeq++
	msg := message.NewMessage(message.MessageTypeEncrypted, dst, src)
	msg.Payload = answer
	msg.SequenceNumber = p.state.MsgSeq
	msg.Ack = true
	msg.AckNumber = seq + 1
	msg.Eqos = 1

	if err := p.encryptAndSend(msg); err != nil {
		log.Errorf("pkg pod; could not send the AID answer: %s", err)
		return false
	}
	return true
}
