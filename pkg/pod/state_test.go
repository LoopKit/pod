package pod

import (
	"testing"
	"time"

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
