package pod

import (
	"io/ioutil"
	"time"

	toml "github.com/pelletier/go-toml"
	log "github.com/sirupsen/logrus"

	"github.com/avereha/pod/pkg/pair"
	"github.com/avereha/pod/pkg/response"
)

type PODState struct {
	LTK       []byte `toml:"ltk"`
	EapAkaSeq uint64 `toml:"eap_aka_seq"`

	// Mode is the active pairing mode (Dash or O5) that selects which
	// response variants the simulator produces. Persisted so the bytes the
	// pod returns to the controller stay consistent across restarts.
	Mode pair.Mode `toml:"mode"`

	Id []byte `toml:"id"` // 4 byte

	MsgSeq   uint8  `toml:"msg_seq"`   // TODO: is this the same as nonceSeq?
	CmdSeq   uint8  `toml:"cmd_seq"`   // TODO: are all those 3 the same number ???
	NonceSeq uint64 `toml:"nonce_seq"` // or 16?

	LastProgSeqNum uint8 `toml:"last_prog_seq"`

	NoncePrefix []byte `toml:"nonce_prefix"`
	CK          []byte `toml:"ck"`

	// O5 pairing identity: a P-256 ECDSA private key (raw 32-byte scalar)
	// and a self-signed DER X.509 certificate wrapping the matching public
	// key. Used to sign the SPS2 channel-binding transcript and to satisfy
	// OmnipodKit's `extractP256PublicKey(fromDERCert:)`. Generated once on
	// first activation and reused thereafter.
	O5PrivateKey []byte `toml:"o5_private_key"`
	O5CertDER    []byte `toml:"o5_cert_der"`

	// PDMPublicKey is the 64-byte raw P-256 public key (X||Y) extracted from
	// the PDM's TLS leaf cert during SPS2. Used to verify ECDSA signatures
	// on inbound Type-4 commands (programBolus, programBasal).
	PDMPublicKey []byte `toml:"pdm_public_key"`

	PodProgress    response.PodProgress
	ActivationTime time.Time `toml:"activation_time"`

	Reservoir        uint16 `toml:"reservoir"`
	ActiveAlertSlots uint8  `toml:"alerts"`
	FaultEvent       uint8  `toml:"fault"`
	FaultTime        uint16 `toml:"fault_time"`
	Delivered        uint16 `toml:"delivered"`

	TriggerTimes     [8]uint16 `toml:"trigger_times"`

	// At some point these could be replaced with details
	// of each kind of delivery (volume, start time, schedule, etc)
	BolusEnd            time.Time `toml:"bolus_end"`
	BolusCanceledAt     time.Time `toml:"bolus_canceled_at"`
	TempBasalEnd        time.Time `toml:"temp_basal_end"`
	ExtendedBolusActive bool      `toml:"extended_bolus_active"`
	BasalActive         bool      `toml:"basal_active"`

	Filename string
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

// ResolveMode picks the effective pairing mode for this process, honouring
// persisted state across restarts so the operator doesn't silently rewrite
// an O5 state.toml to Dash by forgetting the -mode flag.
//
// Precedence:
//
//   - freshState=true: the CLI flag wins; caller is expected to persist it.
//   - freshState=false: state.Mode wins. If it differs from the CLI flag,
//     conflict=true is reported so the caller can warn the operator. The
//     resolved value is still the persisted one (use -fresh to override).
//
// Because pair.ModeDash is the zero value, a legacy state file written
// before the mode field existed deserializes as ModeDash, which lines up
// with the default CLI flag and produces no conflict.
func ResolveMode(state *PODState, flagMode pair.Mode, freshState bool) (resolved pair.Mode, conflict bool) {
	if freshState || state == nil {
		return flagMode, false
	}
	if state.Mode != flagMode {
		return state.Mode, true
	}
	return state.Mode, false
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
