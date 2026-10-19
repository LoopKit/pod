package main

import (
	"flag"

	"github.com/avereha/pod/pkg/api"
	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/mode"
	"github.com/avereha/pod/pkg/pod"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

func main() {
	var stateFile = flag.String("state", "state.toml", "pod state")
	var freshState = flag.Bool("fresh", false, "start fresh. not activated, empty state")
	var modeFlag = flag.String("mode", "dash", "the pod to simulate: dash (Omnipod DASH) or o5 (Omnipod 5)")
	// if both verbose and quiet are chosen, e.g., -v -q, the verbose dominates
	var traceLevel = flag.Bool("v", false, "verbose off by default, TraceLevel")
	var infoLevel = flag.Bool("q", false, "quiet off by default, InfoLevel")
	var apiAddr = flag.String("api", ":8080", "address of the control panel and its API")
	var transport = flag.String("transport", "ble", "ble (a Linux Bluetooth adapter) or impossible (ImpossiBLE's socket, for an app in the iOS Simulator)")
	var socket = flag.String("socket", "/tmp/impossible.sock", "ImpossiBLE socket for -transport impossible")

	flag.Parse()

	podMode, err := mode.Parse(*modeFlag)
	if err != nil {
		log.Fatalf("-mode: %s", err)
	}

	if *traceLevel {
		log.SetLevel(log.TraceLevel)
	} else if *infoLevel {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.DebugLevel)
	}

	log.SetFormatter(&logrus.TextFormatter{
		DisableQuote: true,
		ForceColors:  true,
		FullTimestamp: true,
	})

	var state *pod.PODState
	if *freshState {
		state = pod.NewFreshState(*stateFile, podMode)
	} else {
		state, err = pod.NewState(*stateFile)
		if err != nil {
			log.Fatalf("pkg pod; could not restore pod state from %s: %+v", *stateFile, err)
		}
		// The pod stays what the phone paired with; -mode decides a fresh pod.
		resolved, conflict := pod.ResolveMode(state, podMode)
		if conflict {
			log.Warnf("this pod was created as %s; ignoring -mode %s (use -fresh for a new %s pod)", resolved, podMode, podMode)
		}
		state.Mode = resolved
	}
	if state.PeripheralID == "" {
		state.PeripheralID = bluetooth.PeripheralID()
	}

	log.Infof("simulating an %s pod", state.Mode.Describe())
	log.Tracef("podId %x", state.Id)

	var attach func(*bluetooth.Ble) (bluetooth.Radio, error)
	switch *transport {
	case "ble":
		attach = func(b *bluetooth.Ble) (bluetooth.Radio, error) { return bluetooth.NewGattRadio(b, state.Id) }
	case "impossible":
		attach = func(b *bluetooth.Ble) (bluetooth.Radio, error) {
			return bluetooth.NewSimRadio(b, *socket, state.PeripheralID, state.Id)
		}
	default:
		log.Fatalf("transport %q: want ble or impossible", *transport)
	}
	ble, err := bluetooth.New(state.Mode, attach)
	if err != nil {
		log.Fatalf("Could not start %s: %s", *transport, err)
	}

	p := pod.New(ble, state)
	go func() {
		p.StartAcceptingCommands()
	}()

	log.Info("Starting API")
	s := api.New(p)
	s.Start(*apiAddr)
}
