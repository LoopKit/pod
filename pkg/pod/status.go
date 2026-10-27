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
	Mode                string    `json:"mode"`
	ModeName            string    `json:"modeName"`
	ControllerID        string    `json:"controllerId"`
	ID                  string    `json:"id"`
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
	BadSignatures       int       `json:"badSignatures"`
}

func (p *Pod) takeSnapshot() {
	p.snapMtx.Lock()
	p.snapshot = *p.state
	p.snapshotBadSignatures = p.badSignatures
	p.snapMtx.Unlock()
	p.ble.SetAdvertisedState(bluetooth.AdvertState{Fault: p.state.FaultEvent, Alerts: p.state.ActiveAlertSlots})
}

// Status reports the pod as of its last completed command or change.
func (p *Pod) Status() Status {
	p.snapMtx.Lock()
	s := p.snapshot
	badSignatures := p.snapshotBadSignatures
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
	if len(s.ControllerID) == 4 {
		controller = fmt.Sprintf("%08X", s.ControllerID)
	}
	return Status{
		Mode:                s.Mode.String(),
		ModeName:            s.Mode.Describe(),
		ControllerID:        controller,
		ID:                  id,
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
		BadSignatures:       badSignatures,
	}
}
