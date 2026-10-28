# pod

Fake pod implementation

* The original 0pen-dash repository from which this was forked was removed by the owner.

* This fork has diverged from the original implementation, which was based on hardcoded responses. This version mimics more pod details like reservoir level, total delivery, alerts, and faults, and builds dynamic responses based on that state.

* This version also mimics a behavior we see in some DASH pods where the pod disconnects every 3 minutes; this can be used with iOS hooks to make a heartbeat to run Loop in situations where a BLE CGM is not available. 

* It serves a control panel at http://<host>:8080/ (`-api` changes the address): the pod's reservoir, delivery, age, alerts and fault, with controls to set the reservoir and pod age, raise alerts, trigger or clear a fault, and crash on the next command to test unacknowledged commands. The panel drives a JSON API: `GET /status`, and `POST /command` with `{"command": "changeReservoir", "value": 45}` (also `setActiveTime` in minutes, `setAlerts` as a slot mask, `setFault` with a fault code, 0 to clear, and `crashNextCommand` with `"beforeProcessing": true|false`).

* The websocket API at `/ws`, used by the separate [NodeJS/React frontend](https://github.com/ps2/pod_simulator_frontend), is still there.

* It can serve an app in the iOS Simulator instead of a phone; see [Run against the iOS Simulator](#run-against-the-ios-simulator).

* It simulates a DASH pod by default, or an Omnipod 5 with `-mode o5`; see [Simulate an Omnipod 5](#simulate-an-omnipod-5).

Requirements:
1. Version of iOS code (Loop app) that will interact with this simulator - Loop dev branch or FreeAPS freeaps_dev branch
2. Raspberry pi with Bluetooth BLE (using a pi3b or pi4 right now). For `-mode o5` the
   radio must report Bluetooth 4.2 or later, which not every pi does; see
   [An Omnipod 5 over real Bluetooth needs a 4.2+ radio](#an-omnipod-5-over-real-bluetooth-needs-a-42-radio)
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
* `-mode dash` (the default) or `-mode o5` to choose the pod to simulate
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

`-mode o5` makes the pod an Omnipod 5 instead of a DASH. The mode is kept in the state
file, so restarting the simulator does not change the pod the phone paired with; a
different `-mode` is then ignored with a warning, and `-fresh` starts a new pod.

```
./pod -transport impossible -mode o5 -fresh   # an app in the iOS Simulator
./pod -mode o5 -fresh                         # a phone, over a 4.2+ Bluetooth adapter
./pod -mode o5 -fresh -hci 1                  # ... over the dongle on hci1
```

An Omnipod 5 differs from a DASH in what it advertises and how it talks:

* one 128-bit service UUID, `CE1F923D-C539-48EA-7300-0A<controller id>00`, holding the
  controller it paired with (`FFFFFFFE` before pairing, and a trailing `02` instead of
  `00` while the pod wants attention, which is how a backgrounded app hears about a fault)
* the data characteristic `1A7E2443` rather than `1A7E2442`
* 244-byte packets and no RTS/CTS handshake: a message begins with its first packet, and
  whoever received it answers SUCCESS
* a longer pairing exchange, in which each side shows an X.509 certificate and signs what
  both have said (SPS0, SPS1, SPS2.1, SPS2), ending in the same long-term key and the same
  EAP-AKA session a DASH uses
* a real CRC16 on every response, which the phone checks for an Omnipod 5 and ignores for
  a DASH
* a signature on every command that starts or stops insulin. One that arrives unsigned, or
  signed by anything but the controller the pod paired with, is refused with error `0x2A`
  as a real pod refuses it, and the control panel counts it under "Signed commands
  rejected" — anything above zero is worth looking into.

The control panel shows the pod type and the controller alongside the rest.

### An Omnipod 5 over real Bluetooth needs a 4.2+ radio

Either transport serves an Omnipod 5, but a real Bluetooth adapter has to be new enough.
An Omnipod 5 packet is 244 bytes and needs a 247-byte ATT MTU; a phone asks for one that
large only of a **Bluetooth 4.2 or later** radio, and asks for 185 of anything older. The
phone fragments a message into packets but never fragments a packet, so on a short link
every write is silently truncated. Pairing then fails at SPS2.1, the first message that
needs more than one packet. The pod refuses such a link rather than stall on it, and says
so in the log.

What matters is the version the controller *reports*, not the board it is on. Measure it;
do not infer it from the model. A Pi 3B's own radio reports 4.1 and will not do, a Pi 3B+,
4 or 5 is usually 4.2 or 5.0, but a Pi 4 has been seen reporting 4.1 — the Pi's Bluetooth
firmware decides, so two of the same board can differ.

```
cat /proc/device-tree/model            # which board this is
hciconfig hci0 version                 # "HCI Version: 4.1" is too old; 4.2 or later is wanted
sudo hcitool -i hci0 lefeatures        # look for LE Data Packet Length Extension
```

If the board is supposed to be newer than the version it reports, find out which radio it
actually has before buying anything. Two boards both called a Pi 4 were seen reporting
differently, one pairing an Omnipod 5 and one failing at SPS2.1:

```
HCI Version: 5.0 (0x9)  Revision: 0x17e   Manufacturer: Cypress Semiconductor (305)   # paired
HCI Version: 4.1 (0x7)  Revision: 0x0     Manufacturer: Broadcom Corporation (15)     # did not
```

That gap has two possible causes and they need opposite remedies, so identify it rather
than guess. `dmesg` settles it, because it names the part and says whether the kernel's
firmware patch loaded:

```
cat /proc/device-tree/model; grep Revision /proc/cpuinfo
sudo dmesg | grep -iE "bcm|bluetooth|firmware"
```

* **`BCM43430A1`/`BCM43438`** is a Broadcom 4.1 radio — a Pi 3B or Zero W class part, whatever
  the board is called. It cannot serve an Omnipod 5, so use a dongle or another board.
* **`BCM4345C0`** is the Cypress part in a 3B+, 4, 5 or CM4, and should report 4.2 or later.
  If it reports less, or `dmesg` shows the patch failing to load, that is firmware: it comes
  from the `bluez-firmware` package, and an older one carries an `.hcd` predating 4.2
  support.

```
ls -l /lib/firmware/brcm/BCM4345C0*.hcd
dpkg -s bluez-firmware | grep -i Version
sudo apt update && sudo apt full-upgrade && sudo reboot
hciconfig hci0 version
```

The kernel asks for a device-tree-specific name first, such as
`brcm/BCM4345C0.raspberrypi,4-model-b.hcd`, and only then the plain `brcm/BCM4345C0.hcd`.
If `dmesg` reports the specific name missing while the plain file is there, give it the
name it asked for:

```
sudo cp /lib/firmware/brcm/BCM4345C0.hcd \
    "/lib/firmware/brcm/BCM4345C0.raspberrypi,4-model-b.hcd"   # the name from dmesg
```

`hciuart.service` is what attaches the adapter on a Pi, so check it is not disabled — the
instructions further down stop `bluetooth`, which is the daemon, not this.

The simulator logs the MTU as soon as the phone has negotiated one:

```
INFO  pkg bluetooth; the phone negotiated an ATT MTU of 256
ERROR pkg bluetooth; the phone negotiated an ATT MTU of 185, below the 247 an Omnipod 5 ...
```

On a radio that still reports older than 4.2, a **Bluetooth 4.2+ USB dongle** is the fix. It will not be `hci0`, and
the simulator takes the first adapter with LE support unless told otherwise, so name it:

```
hciconfig                              # find the dongle, usually hci1
./pod -mode o5 -fresh -hci 1
```

On a 4.2+ radio that still settles on 185, telling the controller to offer a long data
length at connection setup is worth a try (the command does not exist before 4.2):

```
sudo hcitool -i hci0 cmd 0x08 0x0024 fb 00 48 03   # LE Write Suggested Default Data Length
```

Failing all of that, `-transport impossible` serves an app in the iOS Simulator over a
socket, which carries whole packets and has no ATT MTU, so the radio stops mattering —
see [Run against the iOS Simulator](#run-against-the-ios-simulator).

### Registration data for the app

OmnipodKit will not begin an Omnipod 5 pairing without a controller signing key and
certificate chain. On a phone it downloads them, which needs Apple's App Attest and so
fails in the iOS Simulator. `cmd/o5keypair` makes a self-signed set instead:

```
go run ./cmd/o5keypair -swift > O5Data.swift     # to build into OmnipodKit
go run ./cmd/o5keypair > o5keypair.json          # the same data as JSON
```

Copy `O5Data.swift` into `LoopWorkspace/OmnipodKit/OmnipodKit/` and build. It defines
`O5RegistrationDataInstall`, which OmnipodKit looks up with `dlsym` at start, so the data
is in place before any pod is paired. OmnipodKit's project uses a synchronized folder, so
Xcode picks the file up on its own. Keep it out of git: it pairs with this simulator and
with nothing else, because neither side validates the other's certificate chain — each
only reads the public key out of the certificate to check the other's signature.

### Telling a simulated pod from a real one

Every pod this simulator serves shows the same certificate authority in SPS2.1
and its own certificate, signed by that authority, in SPS2 — the shape a real
pod uses, where SPS2.1 carries Insulet's intermediate and SPS2 the pod's own.

The authority is fixed and its private key is in this repository on purpose. It
is a development marker, not a secret: an app that pins it can report a pod as
simulated rather than merely failing to recognise it, the way g7sim's published
CA lets Loop mark a simulated G7. It proves nothing about authenticity and must
never be treated as if it did.

```
go run ./cmd/o5keypair -ca      # the CA, as hex to embed in an app
```

A real pod chains to `INS01PG1`, issued by `INS00PG1`, and its own certificate
may well be expired — one was found nineteen months past its notAfter and
pairing normally, because nothing checks. An authenticity check should verify
the chain and ignore validity dates.

### Pair it with Loop

Loop must come from LoopWorkspace `next-dev`, which pins the OmnipodKit that talks to a
simulated pod when it finds ImpossiBLE. Build it for a simulator, start the pod, then
launch Loop with ImpossiBLE's library injected:

```
./pod -transport impossible -mode o5 -fresh
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/path/to/libImpossiBLE.dylib \
    xcrun simctl launch booted <Loop's bundle id>
```

In Loop: Settings -> Insulin Pump -> Add Pump -> Omnipod, then Pod Type -> Omnipod 5. The
setup screen should say it is ready to pair; if it offers to download a certificate
instead, `O5Data.swift` was not built in. The pod log then shows the controller's HELLO,
the pairing rounds, `the phone's SPS2 signature verifies`, the EAP-AKA session, the setup
commands and the prime bolus.

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
