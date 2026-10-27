package pod

import (
	"fmt"
	"time"

	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/response"
)

var progressNames = map[response.PodProgress]string{
	response.PodProgressInitial:                "Initial",
	response.PodProgressMemoryInitialized:      "Memory initialized",
	response.PodProgressReminderInitialized:    "Reminder initialized",
	response.PodProgressPairingCompleted:       "Pairing completed",
	response.PodProgressPriming:                "Priming",
	response.PodProgressPrimingCompleted:       "Priming completed",
	response.PodProgressBasalInitialized:       "Basal initialized",
	response.PodProgressInsertingCannula:       "Inserting cannula",
	response.PodProgressRunningAbove50U:        "Running, above 50 U",
	response.PodProgressRunningBelow50U:        "Running, below 50 U",
	response.PodProgressFault:                  "Fault",
	response.PodProgressActivationTimeExceeded: "Activation time exceeded",
	response.PodProgressPodInactive:            "Inactive",
}

// Status is the pod as the control panel shows it.
type Status struct {
	ID string `json:"id"`
	// Mode is "dash" or "o5" and PodType names it for a reader.
	Mode    string `json:"mode"`
	PodType string `json:"podType"`
	// Controller is the phone the pod paired with, which an Omnipod 5
	// also advertises. Empty until it has paired.
	Controller string `json:"controller"`
	// SignedRejected counts the commands refused for want of a good
	// signature. Anything above zero wants looking into.
	SignedRejected      uint32    `json:"signedRejected"`
	Paired              bool      `json:"paired"`
	Connected           bool      `json:"connected"`
	Progress            int       `json:"progress"`
	ProgressName        string    `json:"progressName"`
	Reservoir           float64   `json:"reservoir"`
	Delivered           float64   `json:"delivered"`
	ActivationTime      time.Time `json:"activationTime"`
	MinutesActive       int       `json:"minutesActive"`
	Alerts              uint8     `json:"alerts"`
	Fault               uint8     `json:"fault"`
	FaultMinutes        uint16    `json:"faultMinutes"`
	BasalActive         bool      `json:"basalActive"`
	TempBasalActive     bool      `json:"tempBasalActive"`
	TempBasalEnd        time.Time `json:"tempBasalEnd"`
	BolusActive         bool      `json:"bolusActive"`
	BolusRemaining      float64   `json:"bolusRemaining"`
	ExtendedBolusActive bool      `json:"extendedBolusActive"`
	CrashNext           string    `json:"crashNext"`
	MsgSeq              uint8     `json:"msgSeq"`
	CmdSeq              uint8     `json:"cmdSeq"`
	NonceSeq            uint64    `json:"nonceSeq"`
	EapAkaSeq           uint64    `json:"eapAkaSeq"`
	LastProgSeqNum      uint8     `json:"lastProgSeqNum"`
}

func (p *Pod) takeSnapshot() {
	p.snapMtx.Lock()
	p.snapshot = *p.state
	p.snapMtx.Unlock()
	p.ble.SetAdvertisedState(bluetooth.AdvertState{Fault: p.state.FaultEvent, Alerts: p.state.ActiveAlertSlots})
}

// Status reports the pod as of its last completed command or change.
func (p *Pod) Status() Status {
	p.snapMtx.Lock()
	s := p.snapshot
	crash := ""
	if crashBeforeProcessingCommand {
		crash = "before"
	} else if crashAfterProcessingCommand {
		crash = "after"
	}
	p.snapMtx.Unlock()

	now := time.Now()
	name := progressNames[s.PodProgress]
	if name == "" {
		name = fmt.Sprintf("%d", s.PodProgress)
	}
	id := ""
	if len(s.Id) == 4 {
		id = fmt.Sprintf("%08X", s.Id)
	}
	controller := ""
	if s.PdmId != 0 {
		controller = fmt.Sprintf("%08X", s.PdmId)
	}
	mode := p.ble.Profile().Mode
	return Status{
		ID:                  id,
		Mode:                string(mode),
		PodType:             mode.Description(),
		Controller:          controller,
		SignedRejected:      s.SignedRejected,
		Paired:              s.LTK != nil,
		Connected:           p.ble.IsConnected(),
		Progress:            int(s.PodProgress),
		ProgressName:        name,
		Reservoir:           float64(s.Reservoir) * 0.05,
		Delivered:           float64(s.Delivered) * 0.05,
		ActivationTime:      s.ActivationTime,
		MinutesActive:       int(s.MinutesActive()),
		Alerts:              s.ActiveAlertSlots,
		Fault:               s.FaultEvent,
		FaultMinutes:        s.FaultTime,
		BasalActive:         s.BasalActive,
		TempBasalActive:     s.TempBasalEnd.After(now),
		TempBasalEnd:        s.TempBasalEnd,
		BolusActive:         s.BolusEnd.After(now),
		BolusRemaining:      float64(s.BolusRemaining()) * 0.05,
		ExtendedBolusActive: s.ExtendedBolusActive,
		CrashNext:           crash,
		MsgSeq:              s.MsgSeq,
		CmdSeq:              s.CmdSeq,
		NonceSeq:            s.NonceSeq,
		EapAkaSeq:           s.EapAkaSeq,
		LastProgSeqNum:      s.LastProgSeqNum,
	}
}
