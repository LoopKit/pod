package pod

import (
	"io/ioutil"
	"time"

	toml "github.com/pelletier/go-toml"
	log "github.com/sirupsen/logrus"

	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/response"
)

type PODState struct {
	LTK       []byte `toml:"ltk"`
	EapAkaSeq uint64 `toml:"eap_aka_seq"`

	Id []byte `toml:"id"` // 4 byte

	MsgSeq   uint8  `toml:"msg_seq"`   // TODO: is this the same as nonceSeq?
	CmdSeq   uint8  `toml:"cmd_seq"`   // TODO: are all those 3 the same number ???
	NonceSeq uint64 `toml:"nonce_seq"` // or 16?

	LastProgSeqNum uint8 `toml:"last_prog_seq"`

	NoncePrefix []byte `toml:"nonce_prefix"`
	CK          []byte `toml:"ck"`

	PodProgress    response.PodProgress
	ActivationTime time.Time `toml:"activation_time"`

	Reservoir        uint16 `toml:"reservoir"`
	ActiveAlertSlots uint8  `toml:"alerts"`
	FaultEvent       uint8  `toml:"fault"`
	FaultTime        uint16 `toml:"fault_time"`
	Delivered        uint16 `toml:"delivered"`

	TriggerTimes [8]uint16 `toml:"trigger_times"`

	// At some point these could be replaced with details
	// of each kind of delivery (volume, start time, schedule, etc)
	BolusEnd            time.Time `toml:"bolus_end"`
	BolusCanceledAt     time.Time `toml:"bolus_canceled_at"`
	TempBasalEnd        time.Time `toml:"temp_basal_end"`
	ExtendedBolusActive bool      `toml:"extended_bolus_active"`
	BasalActive         bool      `toml:"basal_active"`

	// PeripheralID is the identifier the iOS Simulator transport gives the pod.
	PeripheralID string `toml:"peripheral_id"`

	// Mode is the kind of pod being simulated, "dash" or "o5". It is kept
	// with the state so that restarting the simulator does not change the
	// pod the phone paired with.
	Mode string `toml:"mode"`

	// PdmId is the controller that paired the pod. An Omnipod 5
	// advertises it, and the control panel shows it.
	PdmId uint32 `toml:"pdm_id"`

	// ControllerPublic is the phone's signing key, taken from the
	// certificate it showed while pairing. An Omnipod 5 checks the
	// signature on every insulin, cancel and deactivate command against it.
	ControllerPublic []byte `toml:"controller_public"`

	// SignedRejected counts the commands refused for want of a good
	// signature. A real pod answers those with error 0x2A, and anything
	// above zero here means the phone sent one the pod would not take.
	SignedRejected uint32 `toml:"signed_rejected"`

	Filename string
}

// NewFreshState is a new pod, not yet paired.
func NewFreshState(filename string, mode bluetooth.Mode) *PODState {
	return &PODState{
		Reservoir:      150 / 0.05,
		ActivationTime: time.Now(),
		Filename:       filename,
		Mode:           string(mode),
	}
}

// PodMode is the kind of pod this state belongs to. A state file written
// before the simulator could be anything else holds no mode and is a DASH.
func (p *PODState) PodMode() bluetooth.Mode {
	if p.Mode == string(bluetooth.ModeO5) {
		return bluetooth.ModeO5
	}
	return bluetooth.ModeDash
}

func NewState(filename string) (*PODState, error) {
	var ret PODState
	ret.Filename = filename
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = toml.Unmarshal(data, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (p *PODState) Save() error {
	log.Debugf("Saving state to file: %s", p.Filename)
	data, err := toml.Marshal(p)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(p.Filename, data, 0777)
}

func (p *PODState) MinutesActive() uint16 {
	return uint16(time.Now().Sub(p.ActivationTime).Round(time.Minute).Minutes())
}

// NOTE: only handles immediate boluses; any extended bolus is not accounted for
func (p *PODState) BolusRemaining() uint16 {
	now := time.Now()
	var secondsPerPulse uint16
	if p.BolusEnd.After(now) {
		// Add one so the response for a bolus command has a bolus remaining value that matches the bolus size
		bolusSecondsRemaining := uint16(p.BolusEnd.Sub(now).Seconds() + 1)
		if p.PodProgress > response.PodProgressInsertingCannula {
			secondsPerPulse = 2 // normal immediate bolus rate
		} else {
			secondsPerPulse = 1 // pod setup bolus rate
		}
		return bolusSecondsRemaining / secondsPerPulse
	} else {
		return 0
	}
}
