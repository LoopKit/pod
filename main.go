package main

import (
	"flag"
	"time"

	"github.com/avereha/pod/pkg/api"
	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/pair"
	"github.com/avereha/pod/pkg/pod"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

func main() {
	var stateFile = flag.String("state", "state.toml", "pod state")
	var freshState = flag.Bool("fresh", false, "start fresh. not activated, empty state")
	var modeFlag = flag.String("mode", "dash", "pairing mode: dash or o5")
	// if both verbose and quiet are chosen, e.g., -v -q, the verbose dominates
	var traceLevel = flag.Bool("v", false, "verbose off by default, TraceLevel")
	var infoLevel = flag.Bool("q", false, "quiet off by default, InfoLevel")

	flag.Parse()

	pairMode, err := pair.ParseMode(*modeFlag)
	if err != nil {
		log.Fatalf("%v", err)
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

	// TODO: This is kinda ugly, move state reader into own file and pass state to both BLE and pod
	state := &pod.PODState{
		Filename: *stateFile,
	}
	if !(*freshState) {
		state, err = pod.NewState(*stateFile)
		if err != nil {
			log.Fatalf("pkg pod; could not restore pod state from %s: %+v", *stateFile, err)
		}
	}

	log.Tracef("podId %x", state.Id)

	// Reconcile the CLI -mode flag against any persisted mode so a
	// restart without -mode doesn't silently rewrite an O5 state to
	// Dash (the flag's default). On a fresh start the flag wins; on a
	// restart the persisted value wins and we warn on mismatch.
	resolvedMode, modeConflict := pod.ResolveMode(state, pairMode, *freshState)
	if modeConflict {
		log.Warnf("persisted mode %q differs from -mode flag %q; using persisted value (pass -fresh to override)",
			state.Mode, pairMode)
	}
	pairMode = resolvedMode

	ble, err := bluetooth.New("hci0", state.Id, pairMode)
	//defer ble.Close()
	if err != nil {
		log.Fatalf("Could not start BLE: %s", err)
	}

	log.Infof("pairing mode: %s", pairMode)
	p := pod.New(ble, *stateFile, *freshState, pairMode)
	go func() {
		p.StartAcceptingCommands()
	}()

	log.Info("Starting API")
	s := api.New(p)
	s.Start()

	time.Sleep(9999 * time.Second)
}
