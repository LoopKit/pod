# pod

Fake pod implementation: an Omnipod DASH by default, or an Omnipod 5 with `-mode o5`.

* The original 0pen-dash repository from which this was forked was removed by the owner.

* This fork has diverged from the original implementation, which was based on hardcoded responses. This version mimics more pod details like reservoir level, total delivery, alerts, and faults, and builds dynamic responses based on that state.

* This version also mimics a behavior we see in some DASH pods where the pod disconnects every 3 minutes; this can be used with iOS hooks to make a heartbeat to run Loop in situations where a BLE CGM is not available. 

* It serves a control panel at http://<host>:8080/ (`-api` changes the address): the pod's reservoir, delivery, age, alerts and fault, with controls to set the reservoir and pod age, raise alerts, trigger or clear a fault, and crash on the next command to test unacknowledged commands. The panel drives a JSON API: `GET /status`, and `POST /command` with `{"command": "changeReservoir", "value": 45}` (also `setActiveTime` in minutes, `setAlerts` as a slot mask, `setFault` with a fault code, 0 to clear, and `crashNextCommand` with `"beforeProcessing": true|false`).

* The websocket API at `/ws`, used by the separate [NodeJS/React frontend](https://github.com/ps2/pod_simulator_frontend), is still there.

* It can serve an app in the iOS Simulator instead of a phone; see [Run against the iOS Simulator](#run-against-the-ios-simulator).

* With `-mode o5` it is an Omnipod 5 pod for [OmnipodKit](https://github.com/loopandlearn/OmnipodKit); see [Simulate an Omnipod 5](#simulate-an-omnipod-5).

Requirements:
1. Version of iOS code (Loop app) that will interact with this simulator - Loop dev branch or FreeAPS freeaps_dev branch
2. Raspberry pi with Bluetooth BLE (using a pi3b or pi4 right now)
3. The user must have sudo privilege on the pi
4. Install the go language on your device (search internet for procedure)

You can build on pi directly or use cross-compiler and scp the executable

## Build on the pi

Log on the pi and type the following commands, starting at {your_path}/pod:
```
go build
sudo setcap 'cap_net_raw,cap_net_admin=eip' ./pod
```

## Run simulator on the pi

The simulator runs until:
* aborted with a control-C
* pod is deactivated on the phone
* quit out of phone app after establishing BLE connection

The simulator may error out unexpectedly. Just restart it and it should reconnect with the app (do not use the `-fresh` flag in this case.)

When in doubt, control-C and restart it.

To pair a new simulated dash pod, use this command on the pi:
```
./pod -q -fresh 
```

Timing for a new pod:
* start the pairing process in the app (by tapping on Pair Pod button)
* hit return on `./pod -q -fresh` command line on the pi
* if it fails to connect, wait for pairing attempt to fail and try again
* if it still fails, you can switch from Omnipod DASH on the app, add it back and try again

Working with an active pod simulator:
* If you need to quit and restart the app or to build the app fresh, it is best to control-C out of the pod simulator on the pi
* Restart or rebuild the app, then shortly after app opens, try to restore communication
* Otherwise, the app and simulator may stop being able to communicate
* In this case, you need to Deactivate Pod using app and add a new one

To restore communication between the app and an existing simulated dash pod, issue this command on the pi as soon as possible after resuming the app:
```
./pod -q
```

To change the reporting level, add one of these two flags:
* `-v` to make reporting more verbose (Trace Level)
* `-q` to make reporting less verbose (recommended)
* no extra flag - medium verbose (Debug Level)

Note that quitting the app will cause the following message:
```
FATA[####] pkg bluetooth; ** disconnect:
```

Simple restore communication as stated above.

## Run against the iOS Simulator

`-transport impossible` serves the pod to an app in the iOS Simulator through
[ImpossiBLE](https://github.com/mickeyl/ImpossiBLE): no Raspberry Pi and no radio, so it runs on any Mac. The app is
launched with ImpossiBLE's library injected, as [LoopKit/g7sim](https://github.com/LoopKit/g7sim) describes for the G7
emulator (its `simulator/build-impossible.sh` builds the library), and talks to the pod over ImpossiBLE's socket:

```
go build
./pod -transport impossible -fresh
```

Loop's Omnipod support (OmnipodKit) mocks pod commands in the Simulator unless it finds ImpossiBLE, and then pairs,
primes and runs the simulated pod as it would a real one.

ImpossiBLE connects the app to one socket, `/tmp/impossible.sock`. To run the pod alongside g7sim for the same app, give
each its own socket and let g7sim's `impossible-mux` hold ImpossiBLE's:

```
./pod -transport impossible -socket /tmp/impossible-pod.sock
g7sim -transport impossible -socket /tmp/impossible-g7.sock
impossible-mux /tmp/impossible-g7.sock /tmp/impossible-pod.sock
```

The pod holds a connect that asks for a start delay (`CBConnectPeripheralOptionStartDelayKey`) for that delay, as iOS
does, and hangs up after 3 minutes without a command, as above.

Its advertisement shows a fault or a firing alert, as a real pod's does: the 2nd service UUID becomes `C00A` on a fault
(`C005` for an alert), and the manufacturer data carries the fault code and alert slots. A fault set from the control
panel reaches a backgrounded Loop the way a real one does, through its scan for `C00A`; with `impossible-mux -suspend`
the advertisement wakes the suspended app. A real pod's fault is final, and Loop treats it so: clearing the fault here
doesn't restart Loop's scan for `C00A`. Relaunch Loop before testing another fault.

## Simulate an Omnipod 5

```
./pod -mode o5 -fresh
```

pairs as an Omnipod 5 with an app using OmnipodKit, over Bluetooth or `-transport impossible`. The mode is kept in
the state file, so a restart needs no `-mode` (a different `-mode` is ignored with a warning; `-fresh` makes a new
pod of the given mode). The control panel and `GET /status` show the mode.

What differs from the DASH pod, each as OmnipodKit expects it:

* It advertises one service UUID, `CE1F923D-C539-48EA-7300-0A<controller id>00`, with `FFFFFFFE` until it has paired
  and `02` as the last byte on a fault, and serves its data on characteristic `1A7E2443`.
* Messages travel in 244-byte packets with no RTS/CTS.
* Pairing adds SPS0, P-256 keys, and the SPS2.1/SPS2 exchange of certificates and signatures. The pod signs with
  a key and self-signed certificate it makes at its first pairing and keeps in the state file, and remembers the
  phone's signing key from the phone's SPS2 certificate.
* After AssignAddress it answers the AID setup commands (UTC time, TDI, target glucose profile, DIA, EGV, insulin
  history) with the values the app set.
* Bolus, basal, temp basal, cancel and deactivate commands must be signed by the phone; one that is not, or whose
  signature does not verify, is answered with error `0x2A`, and counted on the control panel.
* It reports product id 5 with the firmware, lot and tid of OmnipodKit's captured pod, and ends every response with
  the Omnipod CRC16 that OmnipodKit checks on an Omnipod 5.

OmnipodKit needs O5 registration data (certificates and signing key) to pair; `go run ./cmd/o5keypair` makes
self-signed data the simulator accepts (the pod does not validate the certificate chain, as OmnipodKit does not
validate the pod's). See `docs/O5_SIMULATOR_VALIDATION.md` for a step-by-step check with Loop in the iOS Simulator,
and `docs/O5_PORT_PLAN.md` for the protocol details and their sources.

# Original README.md

We maintained the original README file below. It may be helpful if someone plans to cross-compile the code and just transfer the executable.

The "scripts" folder contains bits and small pieces that I [original owner] used trying to figure out the protocol with data from logs.

## How to build

```
go build
```

building for Raspberry Pi:
```
GOARCH=arm go build`
```

## How to run

This was tested so far only on Linux.
Before running, bring the BLE device down and stop bluetooth daemon
```
sudo hciconfig
sudo hciconfig hci0 down

sudo service bluetooth stop
sudo  systemctl  disable bluetooth
```

Before running, the executable must be granted capabilities(or run as root):
```
sudo setcap 'cap_net_raw,cap_net_admin=eip' ./pod
```
And then run

```
./pod -fresh
```

## Flags

```
$ ./pod  --help
Usage of ./pod:
  -fresh
        start fresh. not activated, empty state
  -mode string
        the pod to simulate: dash (Omnipod DASH) or o5 (Omnipod 5) (default "dash")
  -state string
        pod state (default "state.toml")

```

When running with `-fresh`, the state will be saved, so running it twice(first with `-fresh`, then without) should work.

## How to build & run for Raspberry pi
Tested on `Raspberry Pi 3B+` running `Raspbian 10`

```
GOARCH=arm go build;
ssh pi 'killall pod';
scp pod pi:~/  
ssh pi " sudo setcap 'cap_net_raw,cap_net_admin=eip' ./pod; ./pod"
```
