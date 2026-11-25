package pod

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/command"
	"github.com/avereha/pod/pkg/response"
)

func TestAFaultFreezesTheBolusRemaining(t *testing.T) {
	// An 80 pulse (4 U) bolus, 20 s in: 70 pulses still to go
	s := &PODState{
		PodProgress:    response.PodProgressRunningAbove50U,
		ActivationTime: time.Now().Add(-2 * time.Hour),
		Delivered:      1080,
		Reservoir:      920,
		BolusEnd:       time.Now().Add(140 * time.Second),
	}

	s.SetFault(0x18)

	if got := s.BolusRemaining(); got != 70 {
		t.Fatalf("bolus remaining after the fault = %d, want 70", got)
	}
	if s.Delivered != 1010 || s.Reservoir != 990 {
		t.Fatalf("delivered %d, reservoir %d; want 1010 and 990", s.Delivered, s.Reservoir)
	}
	if !s.BolusEnd.IsZero() {
		t.Fatalf("the bolus is still running after the fault, until %v", s.BolusEnd)
	}

	// A second fault code doesn't take the remainder again
	s.SetFault(0x14)
	if got := s.BolusRemaining(); got != 70 || s.Delivered != 1010 {
		t.Fatalf("after a second fault: remaining %d, delivered %d; want 70 and 1010", got, s.Delivered)
	}

	s.SetFault(0)
	if got := s.BolusRemaining(); got != 0 {
		t.Fatalf("bolus remaining after clearing the fault = %d, want 0", got)
	}
}

func TestAFaultWithNoBolusLeavesNothingUndelivered(t *testing.T) {
	s := &PODState{
		PodProgress:    response.PodProgressRunningAbove50U,
		ActivationTime: time.Now().Add(-2 * time.Hour),
		Delivered:      1080,
		BolusEnd:       time.Now().Add(-time.Minute),
	}

	s.SetFault(0x18)

	if got := s.BolusRemaining(); got != 0 || s.Delivered != 1080 {
		t.Fatalf("remaining %d, delivered %d; want 0 and 1080", got, s.Delivered)
	}
}

func TestAResetFaultClearsWhatThePodReports(t *testing.T) {
	// 3 U (60 pulses) bolus, 20 s in, on a pod 18 minutes old
	s := &PODState{
		PodProgress:    response.PodProgressRunningAbove50U,
		ActivationTime: time.Now().Add(-18 * time.Minute),
		Delivered:      149,
		Reservoir:      2851,
		BolusEnd:       time.Now().Add(100 * time.Second),
	}
	s.SetFault(0x10)

	p := &Pod{state: s}
	raw, _ := p.makeDetailedStatusResponse().Marshal()
	got := hex.EncodeToString(raw)
	// no bolus remaining, nothing delivered, fault 0x10 at no time, 0 minutes active
	want := "0216020d00000000000010000003ff0000"
	if got[:len(want)] != want {
		t.Fatalf("reset fault status %s, want it to start %s", got, want)
	}

	// The pod's own books still have the bolus stopped at the fault
	if s.Delivered != 99 || s.FaultBolusRemaining != 50 {
		t.Fatalf("delivered %d, fault bolus remaining %d; want 99 and 50", s.Delivered, s.FaultBolusRemaining)
	}

	s.ResetAt = time.Now().Add(-3 * time.Minute)
	if got := s.ReportedMinutesActive(); got != 3 {
		t.Fatalf("minutes active 3 minutes after the reset = %d, want 3", got)
	}

	s.SetFault(0)
	if !s.ResetAt.IsZero() || s.ReportedMinutesActive() != 18 {
		t.Fatalf("clearing the fault left reset at %v, minutes active %d", s.ResetAt, s.ReportedMinutesActive())
	}
}

func TestAnO5ResetFaultHasFaultTimeFFFF(t *testing.T) {
	s := &PODState{
		Mode:           string(bluetooth.ModeO5),
		PodProgress:    response.PodProgressRunningAbove50U,
		ActivationTime: time.Now().Add(-18 * time.Minute),
	}
	s.SetFault(0x34)
	if s.FaultTime != 0xFFFF {
		t.Fatalf("O5 reset fault time %04x, want ffff", s.FaultTime)
	}
}

func TestResetFaultCodes(t *testing.T) {
	for _, code := range []uint8{0x0D, 0x0E, 0x0F, 0x10, 0x12, 0x1E, 0x22, 0x34, 0x36, 0x3B, 0x4F, 0xD6, 0xD7} {
		if !IsResetFault(code) {
			t.Errorf("0x%02X is a reset fault", code)
		}
	}
	for _, code := range []uint8{0x14, 0x18, 0x1C, 0x31, 0xAA} {
		if IsResetFault(code) {
			t.Errorf("0x%02X is not a known reset fault", code)
		}
	}
}

func TestANonResetFaultKeepsItsTimeAndCounters(t *testing.T) {
	s := &PODState{
		PodProgress:    response.PodProgressRunningAbove50U,
		ActivationTime: time.Now().Add(-100 * time.Minute),
		Delivered:      1080,
	}
	s.SetFault(0x18)

	if s.FaultTime != 100 || !s.ResetAt.IsZero() {
		t.Fatalf("fault time %d, reset at %v; want 100 and none", s.FaultTime, s.ResetAt)
	}
	if delivered, _ := s.ReportedDelivery(); delivered != 1080 || s.ReportedMinutesActive() != 100 {
		t.Fatalf("reported delivered %d, minutes %d; want 1080 and 100", delivered, s.ReportedMinutesActive())
	}
}

func TestDeactivateReportsTheRealTimeAndReservoir(t *testing.T) {
	// Two hours in, 120 U left, a 4 U bolus 20 s in with 70 pulses to go
	s := &PODState{
		PodProgress:    response.PodProgressRunningAbove50U,
		ActivationTime: time.Now().Add(-2 * time.Hour),
		Delivered:      1080,
		Reservoir:      2400,
		BasalActive:    true,
		BolusEnd:       time.Now().Add(140 * time.Second),
	}
	p := &Pod{state: s}

	p.handleCommand(&command.Deactivate{})
	got := p.getResponse(&command.Deactivate{})
	rsp, ok := got.(*response.GeneralStatusResponse)
	if !ok {
		t.Fatalf("deactivate answered with %T, want a general status", got)
	}

	if rsp.MinutesActive != 120 {
		t.Fatalf("minutes active = %d, want 120", rsp.MinutesActive)
	}
	if rsp.Reservoir != 2470 || rsp.Delivered != 1010 {
		t.Fatalf("reservoir %d, delivered %d; want 2470 and 1010", rsp.Reservoir, rsp.Delivered)
	}
	if rsp.PodProgress != response.PodProgressPodInactive {
		t.Fatalf("pod progress = %d, want %d", rsp.PodProgress, response.PodProgressPodInactive)
	}
	if rsp.BasalActive || rsp.BolusActive || rsp.TempBasalActive || rsp.ExtendedBolusActive {
		t.Fatalf("delivery still running after deactivation: %+v", rsp)
	}
}

func TestTheEightyHourFaultHappensAtEightyHours(t *testing.T) {
	s := &PODState{
		PodProgress:    response.PodProgressRunningBelow50U,
		ActivationTime: time.Now().Add(-81 * time.Hour),
		Reservoir:      400,
	}
	p := &Pod{state: s}

	got := p.getResponse(&command.GetStatus{})
	if _, ok := got.(*response.DetailedStatusResponse); !ok {
		t.Fatalf("a pod past 80 hours answered with %T, want a detailed status", got)
	}
	if s.FaultEvent != 0x1C || s.FaultTime != 80*60 {
		t.Fatalf("fault 0x%02X at %d minutes, want 0x1C at %d", s.FaultEvent, s.FaultTime, 80*60)
	}
}
