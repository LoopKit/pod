package pod

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/command"
	"github.com/avereha/pod/pkg/eap"
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
}

// Once one of these are set, the next command will crash the executable.
var crashBeforeProcessingCommand bool
var crashAfterProcessingCommand bool

func New(ble *bluetooth.Ble, stateFile string, freshState bool) *Pod {
	var err error

	state := &PODState{
		Reservoir:      150 / 0.05,
		ActivationTime: time.Now(),
		Filename:       stateFile,
	}
	if !freshState {
		state, err = NewState(stateFile)
		if err != nil {
			log.Fatalf("pkg pod; could not restore pod state from %s: %+v", stateFile, err)
		}
	}

	ret := &Pod{
		ble:   ble,
		state: state,
	}

	return ret
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

	p.ble.StartMessageLoop()

	if p.state.LTK != nil { // paired, just establish new session
		p.EapAka()
	} else {
		p.StartActivation() // not paired, get the LTK
	}
}

func (p *Pod) StartActivation() {

	pair := &pair.Pair{}
	msg, _ := p.ble.ReadMessage()
	if err := pair.ParseSP1SP2(msg); err != nil {
		log.Fatalf("pkg pod; error parsing SP1SP2 %s", err)
	}
	// read PDM public key and nonce
	msg, _ = p.ble.ReadMessage()
	if err := pair.ParseSPS1(msg); err != nil {
		log.Fatalf("pkg pod; error parsing SPS1 %s", err)
	}

	msg, err := pair.GenerateSPS1()
	if err != nil {
		log.Fatal(err)
	}
	// send POD public key and nonce
	p.ble.WriteMessage(msg)

	// read PDM conf value
	msg, _ = p.ble.ReadMessage()
	pair.ParseSPS2(msg)

	// send POD conf value
	msg, err = pair.GenerateSPS2()
	if err != nil {
		log.Fatal(err)
	}
	p.ble.WriteMessage(msg)

	// receive SP0GP0 constant from PDM
	msg, _ = p.ble.ReadMessage()
	err = pair.ParseSP0GP0(msg)
	if err != nil {
		log.Fatalf("pkg pod; could not parse SP0GP0: %s", err)
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
	p.state.EapAkaSeq = 1
	p.state.Save()

	p.EapAka()
}

func (p *Pod) EapAka() {

	session := eap.NewEapAkaChallenge(p.state.LTK, p.state.EapAkaSeq)

	msg, _ := p.ble.ReadMessage()
	err := session.ParseChallenge(msg)
	if err != nil {
		log.Fatalf("pkg pod; error parsing the EAP-AKA challenge: %s", err)
	}

	msg, err = session.GenerateChallengeResponse()
	if err != nil {
		log.Fatalf("pkg pod; error generating the eap-aka challenge response")
	}
	p.ble.WriteMessage(msg)

	msg, _ = p.ble.ReadMessage()
	log.Debugf("pkg pod; success? %x", msg.Payload) // TODO: figure out how error looks like
	err = session.ParseSuccess(msg)
	if err != nil {
		log.Fatalf("pkg pod; error parsing the EAP-AKA Success packet: %s", err)
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
	for {
		if pMsg.DeactivateFlag {
			log.Infof("pkg pod; Pod was deactivated. Use -fresh for new pod")
			time.Sleep(1 * time.Second)
			log.Exit(0)
		}
		log.Infof("pkg pod;   *** Waiting for the next command ***")
		msg, didTimeout := p.ble.ReadMessageWithTimeout(3 * time.Minute)
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

		decrypted, err := encrypt.DecryptMessage(p.state.CK, p.state.NoncePrefix, p.state.NonceSeq, msg)
		if err != nil {
			log.Fatalf("pkg pod; could not decrypt message: %s", err)
		}
		p.state.NonceSeq++

		cmd, err := command.Unmarshal(decrypted.Payload)
		if err != nil {
			log.Fatalf("pkg pod; could not unmarshal command: %s", err)
		}
		cmdSeq, requestID, err := cmd.GetHeaderData()
		if err != nil {
			log.Fatalf("pkg pod; could not get command header data: %s", err)
		}
		p.state.CmdSeq = cmdSeq

		log.Debugf("pkd pod; cmd: %x", decrypted.Payload)
		data = decrypted.Payload
		n = len(data)
		log.Debugf("pkg pod; len = %d", n)
		if n < 16 {
			log.Fatalf("pkg pod; decrypted. Payload too short")
		}
		pMsg.MsgBodyCommand = data[13 : n-5]
		if data[13] == 0x1c {
			pMsg.DeactivateFlag = true
		}
		log.Tracef("pkg pod; command pod message body = %x", pMsg.MsgBodyCommand)

		p.handleCommand(cmd)

		var rsp response.Response
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
			log.Tracef("SET_UNIQUE_ID cmd.GetPayload() %@", cmd.GetPayload())
			uniqueId := cmd.GetPayload()
			log.Tracef("SET_UNIQUE_ID uniqueId %@", uniqueId)
			p.ble.RefreshAdvertisingWithSpecifiedId(uniqueId)
			p.state.Id = uniqueId
		}

		switch c := cmd.(type) {
		case *command.StopDelivery:
			// Need to clear BolusEnd *after* response is generated, as it is used
			// to calculate remaining
			if c.StopBolus {
				p.state.BolusEnd = time.Time{}
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
		}
		msg, err = response.Marshal(rsp, responseMetadata)
		if err != nil {
			log.Fatalf("pkg pod; could not marshal command response: %s", err)
		}
		msg, err = encrypt.EncryptMessage(p.state.CK, p.state.NoncePrefix, p.state.NonceSeq, msg)
		if err != nil {
			log.Fatalf("pkg pod; could not encrypt response: %s", err)
		}
		p.state.NonceSeq++
		p.state.Save()

		log.Tracef("pkg pod; sending response: %s", spew.Sdump(msg))
		p.ble.WriteMessage(msg)

		log.Debugf("pkg pod; reading response ACK. Nonce seq %d", p.state.NonceSeq)
		msg, _ = p.ble.ReadMessage()
		// TODO check for SEQ numbers here and the Ack flag
		decrypted, err = encrypt.DecryptMessage(p.state.CK, p.state.NoncePrefix, p.state.NonceSeq, msg)
		if err != nil {
			log.Fatalf("pkg pod; could not decrypt message: %s", err)
		}
		p.state.NonceSeq++
		if len(decrypted.Payload) != 0 {
			log.Fatalf("pkg pod; this should be empty message with ACK header %s", spew.Sdump(msg))
		}
		p.state.Save()
		p.mtx.Unlock()

		log.Debugf("notifyingStateChange")
		p.notifyStateChange()
	}
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

	getStatus, isStatusRequest := cmd.(*command.GetStatus)
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
	p.mtx.Unlock()
}

func (p *Pod) SetFault(newVal uint8) {
	p.mtx.Lock()
	p.state.FaultEvent = newVal
	p.state.FaultTime = p.state.MinutesActive()
	p.state.Save()
	p.mtx.Unlock()
}

func (p *Pod) SetActiveTime(newVal int) {
	p.mtx.Lock()
	p.state.ActivationTime = time.Now().Add(-time.Duration(newVal) * time.Minute)
	p.state.Save()
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
	p.mtx.Unlock()
}
