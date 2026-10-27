package pod

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/avereha/pod/pkg/aid"
	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/command"
	"github.com/avereha/pod/pkg/eap"
	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/pair"

	"github.com/avereha/pod/pkg/encrypt"
	"github.com/avereha/pod/pkg/response"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

type PodMsgBody struct {
	// This contains the decrypted message body
	//   MsgBodyCommand: incoming after stripping off address and crc
	//   MsgBodyResponse: outgoing before adding address and crc
	//      not sure how to get this to this level and don't really need it
	//   DeactivateFlag: set to true once 0x1c input is detected
	MsgBodyCommand []byte
	// MsgBodyResponse []byte
	DeactivateFlag bool
}

type Pod struct {
	ble            *bluetooth.Ble
	state          *PODState
	mtx            sync.Mutex
	webMessageHook func([]byte)

	// aid holds what an Omnipod 5 phone set with its AID setup commands.
	aid aid.Settings
	// badSignatures counts type 4 commands whose signature did not verify.
	badSignatures int

	// snapshot is the state as of the last completed command, for the
	// status page: mtx is held while a command waits for the phone's ACK.
	snapMtx               sync.Mutex
	snapshot              PODState
	snapshotBadSignatures int
}

// Once one of these are set, the next command will crash the executable.
var crashBeforeProcessingCommand bool
var crashAfterProcessingCommand bool

func New(ble *bluetooth.Ble, state *PODState) *Pod {
	ret := &Pod{
		ble:   ble,
		state: state,
		aid:   aid.Settings{},
	}
	ret.takeSnapshot()
	return ret
}

// advertisedID is the id the pod puts in its advertisement: its own for a
// DASH pod, the phone's for an Omnipod 5 (OmnipodKit setUuidPdmId).
func (p *Pod) advertisedID() []byte {
	if p.state.Mode.IsO5() {
		return p.state.ControllerID
	}
	return p.state.Id
}

// helloControllerID reads the phone's id from its HELLO, 06 01 04 and the id.
func helloControllerID(cmd bluetooth.Packet) []byte {
	if len(cmd) == 7 && cmd[0] == 0x06 && cmd[1] == 0x01 && cmd[2] == 0x04 {
		return append([]byte(nil), cmd[3:7]...)
	}
	return nil
}

// identity is an Omnipod 5 pod's signing key and certificate, made once.
func (p *Pod) identity() (*pair.PodIdentity, error) {
	if id, err := pair.LoadPodIdentity(p.state.O5PrivateKey, p.state.O5CertDER); err == nil {
		return id, nil
	}
	id, err := pair.NewPodIdentity()
	if err != nil {
		return nil, err
	}
	p.state.O5PrivateKey = id.Private()
	p.state.O5CertDER = id.CertDER
	return id, p.state.Save()
}

func (p *Pod) SetWebMessageHook(hook func([]byte)) {
	p.webMessageHook = hook
}

func (p *Pod) GetPodStateJson() ([]byte, error) {
	p.mtx.Lock()
	data, error := json.Marshal(p.state)
	p.mtx.Unlock()

	return data, error
}

func (p *Pod) notifyStateChange() {
	if p.webMessageHook != nil {
		data, err := p.GetPodStateJson()
		if err != nil {
			log.Error(err)
		} else {
			p.webMessageHook(data)
		}
	} else {
		log.Infof("No webMessageHook")
	}
}

func (p *Pod) StartAcceptingCommands() {
	log.Infof("pkg pod; Listening for commands")
	firstCmd, _ := p.ble.ReadCmd()
	log.Infof("pkg pod; got first command: as string: %s", firstCmd)
	if id := helloControllerID(firstCmd); id != nil {
		log.Infof("pkg pod; HELLO from controller %x", id)
		p.state.ControllerID = id
	}

	p.ble.StartMessageLoop()

	if p.state.LTK != nil { // paired, just establish new session
		p.EapAka()
	} else {
		p.StartActivation() // not paired, get the LTK
	}
}

// readSetup waits for the phone's next pairing or session message. A new
// connection abandons the exchange: the phone starts over on it.
func (p *Pod) readSetup() (*message.Message, bool) {
	for {
		msg, _, didReconnect := p.ble.ReadMessageWithTimeout(time.Minute)
		if didReconnect {
			log.Infof("pkg pod; new connection — starting over")
			go p.StartAcceptingCommands()
			return nil, false
		}
		if msg != nil {
			return msg, true
		}
	}
}

// startOver hangs up on a phone whose message the pod can't use. The phone
// reconnects and sets up a new session.
func (p *Pod) startOver(format string, args ...interface{}) {
	log.Errorf("pkg pod; "+format+"; hanging up", args...)
	p.ble.ShutdownConnection()
	go p.StartAcceptingCommands()
}

// StartActivation pairs with the phone: SP1/SP2, SPS1, SPS2, SP0/GP0 for a
// DASH pod; an Omnipod 5 adds SPS0 after SP1/SP2 and SPS2.1 before SPS2
// (OmnipodKit DashLTKExchanger, O5LTKExchanger).
func (p *Pod) StartActivation() {

	o5 := p.state.Mode.IsO5()
	pair := &pair.Pair{Mode: p.state.Mode}
	if o5 {
		id, err := p.identity()
		if err != nil {
			log.Fatalf("pkg pod; no pod identity: %s", err)
		}
		pair.SetIdentity(id)
	}
	msg, ok := p.readSetup()
	if !ok {
		return
	}
	if err := pair.ParseSP1SP2(msg); err != nil {
		p.startOver("error parsing SP1SP2 %s", err)
		return
	}
	if p.state.ControllerID == nil {
		p.state.ControllerID = pair.ControllerID()
	}

	if o5 {
		if msg, ok = p.readSetup(); !ok {
			return
		}
		if err := pair.ParseSPS0(msg); err != nil {
			p.startOver("error parsing SPS0 %s", err)
			return
		}
		msg, err := pair.GenerateSPS0()
		if err != nil {
			log.Fatal(err)
		}
		p.ble.WriteMessage(msg)
	}

	// read PDM public key and nonce
	if msg, ok = p.readSetup(); !ok {
		return
	}
	if err := pair.ParseSPS1(msg); err != nil {
		p.startOver("error parsing SPS1 %s", err)
		return
	}

	msg, err := pair.GenerateSPS1()
	if err != nil {
		log.Fatal(err)
	}
	// send POD public key and nonce
	p.ble.WriteMessage(msg)

	if o5 {
		// the phone's certificate, then the pod's
		if msg, ok = p.readSetup(); !ok {
			return
		}
		if err := pair.ParseSPS21(msg); err != nil {
			p.startOver("error parsing SPS2.1 %s", err)
			return
		}
		msg, err = pair.GenerateSPS21()
		if err != nil {
			log.Fatal(err)
		}
		p.ble.WriteMessage(msg)
	}

	// read PDM conf value (DASH) or its certificate and signature (Omnipod 5)
	if msg, ok = p.readSetup(); !ok {
		return
	}
	if err := pair.ParseSPS2(msg); err != nil {
		p.startOver("error parsing SPS2 %s", err)
		return
	}

	// send POD conf value
	msg, err = pair.GenerateSPS2()
	if err != nil {
		log.Fatal(err)
	}
	p.ble.WriteMessage(msg)

	// receive SP0GP0 constant from PDM
	if msg, ok = p.readSetup(); !ok {
		return
	}
	err = pair.ParseSP0GP0(msg)
	if err != nil {
		p.startOver("could not parse SP0GP0: %s", err)
		return
	}

	// send P0 constant
	msg, err = pair.GenerateP0()
	if err != nil {
		log.Fatal(err)
	}
	p.ble.WriteMessage(msg)

	p.state.LTK, err = pair.LTK()
	if err != nil {
		log.Fatalf("pkg pod; could not get LTK %s", err)
	}
	log.Infof("pkg pod; LTK %x", p.state.LTK)
	if key := pair.PDMPublicKey(); key != nil {
		p.state.PDMPublicKey = key
		log.Infof("pkg pod; keeping the phone's signing key for its signed commands")
	}
	p.state.EapAkaSeq = 0 // the controller's first session uses SQN 1
	p.state.Save()

	p.EapAka()
}

func (p *Pod) EapAka() {

	var session *eap.EapAkaChallenge
	var msg *message.Message
	var ok bool
	for {
		session = eap.NewEapAkaChallenge(p.state.LTK, p.state.EapAkaSeq)
		if msg, ok = p.readSetup(); !ok {
			return
		}
		if err := session.ParseChallenge(msg); err != nil {
			p.startOver("error parsing the EAP-AKA challenge: %s", err)
			return
		}
		fresh, err := session.CheckSqn()
		if err != nil {
			p.startOver("error checking the EAP-AKA challenge: %s", err)
			return
		}
		if fresh {
			break
		}
		// Another controller has had a session since this one's last: tell it our SQN.
		// It retries on the same connection with the next one.
		log.Infof("pkg pod; EAP-AKA SQN %d is not past %d; sending a synchronization failure", session.Sqn, p.state.EapAkaSeq)
		if msg, err = session.GenerateSynchronizationFailure(); err != nil {
			log.Fatalf("pkg pod; error generating the eap-aka synchronization failure: %s", err)
		}
		p.ble.WriteMessage(msg)
	}

	msg, err := session.GenerateChallengeResponse()
	if err != nil {
		log.Fatalf("pkg pod; error generating the eap-aka challenge response")
	}
	p.ble.WriteMessage(msg)

	if msg, ok = p.readSetup(); !ok {
		return
	}
	log.Debugf("pkg pod; success? %x", msg.Payload) // TODO: figure out how error looks like
	err = session.ParseSuccess(msg)
	if err != nil {
		p.startOver("error parsing the EAP-AKA Success packet: %s", err)
		return
	}
	p.state.CK, p.state.NoncePrefix = session.CKNoncePrefix()

	p.state.NonceSeq = 1
	p.state.MsgSeq = 1
	p.state.EapAkaSeq = session.Sqn
	log.Infof("pkg pod; got CK: %x", p.state.CK)
	log.Infof("pkg pod; got NONCE: %x", p.state.NoncePrefix)
	log.Infof("pkg pod; using NONCE SEQ: %d", p.state.NonceSeq)
	log.Infof("pkg pod; EAP-AKA session SQN: %d", p.state.EapAkaSeq)

	err = p.state.Save()
	if err != nil {
		log.Fatalf("pkg pod; Could not save the pod state: %s", err)
	}
	p.mtx.Lock()
	p.takeSnapshot()
	p.mtx.Unlock()

	// initialize pMsg
	var pMsg PodMsgBody
	pMsg.MsgBodyCommand = make([]byte, 16)
	pMsg.DeactivateFlag = false
	log.Tracef("pkd pod; pMsg initialized: %+v", pMsg)

	p.CommandLoop(pMsg)
}

func (p *Pod) CommandLoop(pMsg PodMsgBody) {
	var lastMsgSeq uint8 = 0
	var data []byte = make([]byte, 4)
	var n int = 0
	o5 := p.state.Mode.IsO5()
	for {
		if pMsg.DeactivateFlag {
			log.Infof("pkg pod; Pod was deactivated. Use -fresh for new pod")
			time.Sleep(1 * time.Second)
			log.Exit(0)
		}
		log.Infof("pkg pod;   *** Waiting for the next command ***")
		msg, didTimeout, didReconnect := p.ble.ReadMessageWithTimeout(3 * time.Minute)
		if didReconnect {
			// The phone dropped the link and came back. The message loop was
			// stopped by the CentralConnected handler, so hand off to a fresh
			// StartAcceptingCommands, which restarts it and renegotiates the
			// EAP-AKA session over the new connection.
			log.Infof("pkg pod; new connection — re-establishing session")
			go func() {
				p.StartAcceptingCommands()
			}()
			return
		}
		if didTimeout {
			p.ble.ShutdownConnection()
			go func() {
				p.StartAcceptingCommands()
			}()
			return
		}
		log.Tracef("pkg pod; got command message: %s", spew.Sdump(msg))

		if msg.SequenceNumber == lastMsgSeq {
			// this is a retry because we did not answer yet
			// ignore duplicate commands/mesages
			continue
		}
		lastMsgSeq = msg.SequenceNumber

		// Lock mutex before we start using/modifying state
		p.mtx.Lock()

		// An Omnipod 5 phone signs its insulin, cancel and deactivate
		// commands (type 4): the signature covers the header and the
		// ciphertext, so it is checked before decrypting.
		signed := false
		if msg.Type == message.MessageTypeEncryptedSigned {
			signed = p.verifySignature(msg)
		}

		decrypted, err := encrypt.DecryptMessage(p.state.CK, p.state.NoncePrefix, p.state.NonceSeq, msg)
		if err != nil {
			p.mtx.Unlock()
			p.startOver("could not decrypt message: %s", err)
			return
		}
		p.state.NonceSeq++

		var reply *message.Message
		if o5 && aid.IsCommand(decrypted.Payload) {
			// An Omnipod 5 AID setup command, between AssignAddress and
			// SetupPod. It is plain text, answered in plain text, and
			// does not count as an Omnipod command.
			reply, err = p.answerAID(msg, decrypted.Payload)
			if err != nil {
				p.mtx.Unlock()
				p.startOver("%s", err)
				return
			}
		} else {
			if len(decrypted.Payload) < 16 {
				p.mtx.Unlock()
				p.startOver("decrypted payload too short: %x", decrypted.Payload)
				return
			}
			cmd, err := command.Unmarshal(decrypted.Payload)
			if err != nil {
				p.mtx.Unlock()
				p.startOver("could not unmarshal command: %s", err)
				return
			}
			cmdSeq, requestID, err := cmd.GetHeaderData()
			if err != nil {
				p.mtx.Unlock()
				p.startOver("could not get command header data: %s", err)
				return
			}
			p.state.CmdSeq = cmdSeq

			log.Debugf("pkd pod; cmd: %x", decrypted.Payload)
			data = decrypted.Payload
			n = len(data)
			log.Debugf("pkg pod; len = %d", n)
			pMsg.MsgBodyCommand = data[13 : n-5]
			log.Tracef("pkg pod; command pod message body = %x", pMsg.MsgBodyCommand)

			var rsp response.Response
			if o5 && command.RequiresSignature(cmd.GetType()) && !signed {
				// A real Omnipod 5 refuses the command rather than run it.
				log.Errorf("pkg pod; %s was not validly signed; answering error 0x%02X", command.CommandName[cmd.GetType()], response.ErrorO5InvalidCommand)
				rsp = &response.ErrorResponse{Code: response.ErrorO5InvalidCommand, FaultEvent: p.state.FaultEvent, PodProgress: p.state.PodProgress}
			} else {
				if data[13] == 0x1c {
					pMsg.DeactivateFlag = true
				}

				p.handleCommand(cmd)

				if cmd.IsResponseHardcoded() {
					rsp, err = cmd.GetResponse()
					if err != nil {
						log.Fatalf("pkg pod; could not get command response: %s", err)
					}
				} else {
					rsp = p.getResponse(cmd)
				}

				if cmd.GetType() == command.SET_UNIQUE_ID {
					// Set the unique ID
					log.Tracef("SET_UNIQUE_ID cmd.GetPayload() %x", cmd.GetPayload())
					uniqueId := cmd.GetPayload()
					log.Tracef("SET_UNIQUE_ID uniqueId %x", uniqueId)
					p.state.Id = uniqueId
					p.ble.RefreshAdvertisingWithSpecifiedId(p.advertisedID())
				}

				switch c := cmd.(type) {
				case *command.StopDelivery:
					// Need to clear BolusEnd *after* response is generated, as it is used
					// to calculate remaining
					if c.StopBolus {
						p.state.BolusEnd = time.Time{}
					}
				}
			}

			p.state.MsgSeq++
			p.state.CmdSeq++
			p.state.Save()
			responseMetadata := &response.ResponseMetadata{
				Dst:       msg.Source,
				Src:       msg.Destination,
				CmdSeq:    p.state.CmdSeq,
				MsgSeq:    p.state.MsgSeq,
				RequestID: requestID,
				AckSeq:    msg.SequenceNumber + 1,
				Mode:      p.state.Mode,
			}
			reply, err = response.Marshal(rsp, responseMetadata)
			if err != nil {
				log.Fatalf("pkg pod; could not marshal command response: %s", err)
			}
		}
		reply, err = encrypt.EncryptMessage(p.state.CK, p.state.NoncePrefix, p.state.NonceSeq, reply)
		if err != nil {
			log.Fatalf("pkg pod; could not encrypt response: %s", err)
		}
		p.state.NonceSeq++
		p.state.Save()

		log.Tracef("pkg pod; sending response: %s", spew.Sdump(reply))
		p.ble.WriteMessage(reply)

		log.Debugf("pkg pod; reading response ACK. Nonce seq %d", p.state.NonceSeq)
		msg, _, didReconnect = p.ble.ReadMessageWithTimeout(3 * time.Minute)
		if msg == nil {
			// The phone never acknowledged; it will ask again on its next session.
			p.state.Save()
			p.takeSnapshot()
			p.mtx.Unlock()
			log.Infof("pkg pod; no response ACK — re-establishing session")
			if !didReconnect {
				p.ble.ShutdownConnection()
			}
			go p.StartAcceptingCommands()
			return
		}
		// TODO check for SEQ numbers here and the Ack flag
		decrypted, err = encrypt.DecryptMessage(p.state.CK, p.state.NoncePrefix, p.state.NonceSeq, msg)
		if err == nil {
			p.state.NonceSeq++
			if len(decrypted.Payload) != 0 {
				err = fmt.Errorf("not an empty ACK: %s", spew.Sdump(msg))
			}
		}
		p.state.Save()
		p.takeSnapshot()
		p.mtx.Unlock()
		if err != nil {
			p.startOver("could not read the response ACK: %s", err)
			return
		}

		log.Debugf("notifyingStateChange")
		p.notifyStateChange()
	}
}

// verifySignature checks a type 4 command against the phone's key from
// pairing. Caller holds p.mtx.
func (p *Pod) verifySignature(msg *message.Message) bool {
	if len(p.state.PDMPublicKey) == 0 {
		log.Warnf("pkg pod; a signed command, but no phone key from pairing to check it with")
		return false
	}
	ok, err := pair.VerifySignedMessage(p.state.PDMPublicKey, msg.Raw[:16], msg.Payload, msg.Signature)
	if err != nil {
		log.Errorf("pkg pod; could not check the command's signature: %s", err)
	} else if !ok {
		log.Errorf("pkg pod; the command's signature does not verify")
	} else {
		log.Debugf("pkg pod; the command's signature verifies")
		return true
	}
	p.badSignatures++
	return false
}

// answerAID answers an Omnipod 5 AID setup command. Caller holds p.mtx.
func (p *Pod) answerAID(msg *message.Message, payload []byte) (*message.Message, error) {
	cmd, err := aid.Parse(payload)
	if err != nil {
		return nil, fmt.Errorf("could not parse AID command %q: %s", payload, err)
	}
	answer := p.aid.Respond(cmd)
	log.Infof("pkg pod; AID %s %s %q; answering %q", cmd.Kind, cmd.Key(), cmd.Data, answer)
	p.state.MsgSeq++
	p.state.Save()
	return response.RawMessage(answer, &response.ResponseMetadata{
		Dst:    msg.Source,
		Src:    msg.Destination,
		MsgSeq: p.state.MsgSeq,
		AckSeq: msg.SequenceNumber + 1,
		Mode:   p.state.Mode,
	}), nil
}

func (p *Pod) makeGeneralStatusResponse() response.Response {
	log.Debugf("pkg pod; General status response LastProgSeqNum = %d", p.state.LastProgSeqNum)

	var now = time.Now()

	return &response.GeneralStatusResponse {
		LastProgSeqNum:      p.state.LastProgSeqNum,
		Reservoir:           p.state.Reservoir,
		Alerts:              p.state.ActiveAlertSlots,
		BolusActive:         p.state.BolusEnd.After(now),
		TempBasalActive:     p.state.TempBasalEnd.After(now),
		BasalActive:         p.state.BasalActive,
		ExtendedBolusActive: p.state.ExtendedBolusActive,
		PodProgress:         p.state.PodProgress,
		Delivered:           p.state.Delivered,
		BolusRemaining:      p.state.BolusRemaining(),
		MinutesActive:       p.state.MinutesActive(),
	}
}

func (p *Pod) makeDetailedStatusResponse() response.Response {

	var now = time.Now()

	return &response.DetailedStatusResponse {
		LastProgSeqNum:      p.state.LastProgSeqNum,
		Reservoir:           p.state.Reservoir,
		Alerts:              p.state.ActiveAlertSlots,
		BolusActive:         p.state.BolusEnd.After(now),
		TempBasalActive:     p.state.TempBasalEnd.After(now),
		BasalActive:         p.state.BasalActive,
		ExtendedBolusActive: p.state.ExtendedBolusActive,
		PodProgress:         p.state.PodProgress,
		Delivered:           p.state.Delivered,
		BolusRemaining:      p.state.BolusRemaining(),
		MinutesActive:       p.state.MinutesActive(),
		FaultEvent:          p.state.FaultEvent,
		FaultEventTime:      p.state.FaultTime,
	}
}

func (p *Pod) makeType1StatusResponse() response.Response {

	return &response.Type1StatusResponse {
		TriggeredAlerts:     p.state.TriggerTimes,
	}
}

func (p *Pod) makeType3StatusResponse() response.Response {

	return &response.Type3StatusResponse {
		FaultEvent:          p.state.FaultEvent,
		FaultEventTime:      p.state.FaultTime,
		MinutesActive:       p.state.MinutesActive(),
	}
}

func (p *Pod) makeType5StatusResponse() response.Response {

	var activationTime = p.state.ActivationTime

	return &response.Type5StatusResponse {
		FaultEvent:          p.state.FaultEvent,
		FaultEventTime:      p.state.FaultTime,
		Year:                uint8(activationTime.Year() - 2000),
		Month:               uint8(activationTime.Month()),
		Day:                 uint8(activationTime.Day()),
		Hour:                uint8(activationTime.Hour()),
		Minute:              uint8(activationTime.Minute()),
	}
}

func (p *Pod) getResponse(cmd command.Command) response.Response {
	var rsp response.Response

	switch c := cmd.(type) {
	case *command.GetVersion: // 0x07, AssignAddress: the shorter version response
		return response.AssignAddressResponse(p.state.Mode)
	case *command.SetUniqueID: // 0x03, SetupPod: the longer version response
		return response.SetupPodResponse(p.state.Mode, c.Payload)
	}

	getStatus, isStatusRequest := cmd.(*command.GetStatus)
	if p.state.MinutesActive() >= 80 * 60 && p.state.FaultEvent == 0 {
		p.state.FaultEvent = 0x1C // 0x1C = exceeded maximum pod life of 80 hours
	}
	if !isStatusRequest || getStatus.RequestType == 0 || getStatus.RequestType == 7 {
		// Not a get status command or a type 0 or type 7 get status
		if p.state.FaultEvent == 0 {
			// Pod is not faulted, return a general status response for the type 0 or 7 get status
			rsp = p.makeGeneralStatusResponse()
		} else {
			// Pod is faulted, return a detailed status response
			rsp = p.makeDetailedStatusResponse()
		}
	} else {
		// Return the requested status type independent of the pod fault state
		switch getStatus.RequestType {
		case 1:
			rsp = p.makeType1StatusResponse()
		case 2:
			rsp = p.makeDetailedStatusResponse()
		case 3:
			rsp = p.makeType3StatusResponse()
		case 5:
			rsp = p.makeType5StatusResponse()
		default:
			// Includes 0x46, 0x50, 0x51 and the nack responses that are all hardcoded
			log.Fatalf("pkg pod; getStatus: unexpected type 0x%x", getStatus.RequestType)
		}
	}

	return rsp
}

// clear the alert bit mask and the trigger times array for alerts in the mask
func (p *Pod) clearAlerts(alertMask uint8) {
	p.state.ActiveAlertSlots = p.state.ActiveAlertSlots &^ alertMask

	for i := 0; i < 8; i++ {
		if ((1 << i) & alertMask) != 0 {
			p.state.TriggerTimes[i] = 0
		}
	}
}

func (p *Pod) handleCommand(cmd command.Command) {

	// this progress advancement happens in the pump control logic in a real pod
	if p.state.PodProgress == response.PodProgressPriming {
		// if enough time has passed for priming to finish, advance PodProgress
		if p.state.BolusEnd.Before(time.Now()) {
			log.Infof("*** Advancing progress to PodProgressPrimingCompleted as prime bolus has ended")
			p.state.PodProgress = response.PodProgressPrimingCompleted
		}
	}
	if p.state.PodProgress == response.PodProgressInsertingCannula {
		// if enough time has passed for cannula insert bolus to finish, advance PodProgress
		if p.state.BolusEnd.Before(time.Now()) {
			log.Infof("*** Advancing progress to PodProgressRunningAbove50U as cannula insert bolus has ended")
			p.state.PodProgress = response.PodProgressRunningAbove50U
		}
	}

	if p.state.PodProgress == response.PodProgressRunningAbove50U {
		// transition PodProgress when reservoir is below 50 / 0.05 = 1000 pulses
		if p.state.Reservoir <= 1000 {
			log.Infof("*** Advancing progress to PodProgressRunningBelow50U based on reservoir value")
			p.state.PodProgress = response.PodProgressRunningBelow50U
		}
	}

	if crashBeforeProcessingCommand && cmd.DoesMutatePodState() {
		log.Fatalf("pkg pod; Crashing before processing command with sequence %d", cmd.GetSeq())
	}

	switch c := cmd.(type) {
	case *command.GetVersion: // 0x03
		p.state.PodProgress = response.PodProgressReminderInitialized

	case *command.SetUniqueID: // 0x07
		p.state.PodProgress = response.PodProgressPairingCompleted

	case *command.GetStatus: // 0x0E
		break

	case *command.SilenceAlerts: // 0x11
		// clears the ActiveAlertSlots bits and Trigger Times for the specified alerts
		p.clearAlerts(c.AlertMask)

	case *command.ProgramAlerts: // 0x19
		// For now just clears the ActiveAlertSlots bits and Trigger Times for alerts being programmed
		// Later could add code to manage timers for configured alerts to make the sim more pod-like.
		p.clearAlerts(c.AlertMask)

	case *command.ProgramInsulin: // 0x1A
		log.Debugf("pkg pod; ProgramInsulin: PodProgress = %d", p.state.PodProgress)

		if p.state.PodProgress < response.PodProgressPriming {
			// this must be the prime command
			p.state.PodProgress = response.PodProgressPriming
		} else if p.state.PodProgress < response.PodProgressBasalInitialized {
			// this must be the program scheduled basal command
			p.state.PodProgress = response.PodProgressBasalInitialized
		} else if p.state.PodProgress < response.PodProgressInsertingCannula {
			// this must be the insert cannula command
			p.state.PodProgress = response.PodProgressInsertingCannula
		}

		// Programming basal schedule
		if c.TableNum == 0 {
			p.state.BasalActive = true
		}

		// Programming temp basal
		if c.TableNum == 1 {
			p.state.TempBasalEnd = time.Now().Add(time.Duration(c.Duration) * time.Hour / 2)
		}

		// Programming bolus; just immediately decrement reservoir
		// Would be nice to eventually simulate actual pulses over time.
		if c.TableNum == 2 {
			p.state.Delivered += c.Pulses
			p.state.Reservoir -= c.Pulses
			if p.state.PodProgress >= response.PodProgressRunningAbove50U {
				p.state.BolusEnd = time.Now().Add(time.Duration(c.Pulses) * time.Second * 2)
			} else {
				p.state.BolusEnd = time.Now().Add(time.Duration(c.Pulses) * time.Second) // one sec/pulse during pod setup
			}
		}

	case *command.StopDelivery: // 0x1F
		if c.StopBolus {
			p.state.ExtendedBolusActive = false
		}
		if c.StopTempBasal {
			p.state.TempBasalEnd = time.Time{}
		}
		if c.StopBasal {
			p.state.BasalActive = false
		}

	default: // includes 0x08, 0x1C, 0x1E
		// No action
	}

	if cmd.DoesMutatePodState() {
		seq := cmd.GetSeq()
		log.Debugf("pkg pod; Updating LastProgSeqNum = %d", seq)
		p.state.LastProgSeqNum = seq
		if crashAfterProcessingCommand {
			p.state.Save()
			log.Fatalf("pkg pod; Crashing after processing command with sequence %d", seq)
		}
	}
}

func (p *Pod) SetReservoir(newVal float32) {
	p.mtx.Lock()
	p.state.Reservoir = uint16(newVal * 20)
	p.state.Save()
	p.takeSnapshot()
	p.mtx.Unlock()
}

func (p *Pod) SetAlerts(newVal uint8) {
	p.mtx.Lock()
	p.state.ActiveAlertSlots = newVal

	// Save the current pod time in alert trigger
	// time array for any alerts slots going active
	var podTime = p.state.MinutesActive()
	for i := 0; i < 8; i++ {
		if ((1 << i) & newVal) != 0 {
			p.state.TriggerTimes[i] = podTime
		}
	}
	p.state.Save()
	p.takeSnapshot()
	p.mtx.Unlock()
}

func (p *Pod) SetFault(newVal uint8) {
	p.mtx.Lock()
	p.state.FaultEvent = newVal
	p.state.FaultTime = p.state.MinutesActive()
	p.state.Save()
	p.takeSnapshot()
	p.mtx.Unlock()
}

func (p *Pod) SetActiveTime(newVal int) {
	p.mtx.Lock()
	p.state.ActivationTime = time.Now().Add(-time.Duration(newVal) * time.Minute)
	p.state.Save()
	p.takeSnapshot()
	p.mtx.Unlock()
}

func (p *Pod) CrashNextCommand(beforeProcessing bool) {
	p.mtx.Lock()
	if beforeProcessing {
		crashBeforeProcessingCommand = true
	} else {
		crashAfterProcessingCommand = true
	}
	p.state.Save()
	p.takeSnapshot()
	p.mtx.Unlock()
}
