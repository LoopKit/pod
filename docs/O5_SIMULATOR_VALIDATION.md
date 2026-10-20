# Validate the Omnipod 5 simulator with OmnipodKit in the iOS Simulator

Everything runs on one Mac: Loop in the iOS Simulator, with CoreBluetooth replaced by
[ImpossiBLE](https://github.com/mickeyl/ImpossiBLE), talking to this pod simulator in
`-mode o5`. No radio, no Pi, no real pod.

## What you need

* A Mac with Xcode 15 or newer and Go 1.21 or newer. The ImpossiBLE build script below targets
  Apple Silicon (`arm64` Simulator); on an Intel Mac change its `-target` to
  `x86_64-apple-ios15.0-simulator`.
* Loop from [LoopKit/LoopWorkspace](https://github.com/LoopKit/LoopWorkspace) branch
  **`next-dev`**. It pins OmnipodKit `next-dev`, which talks to a simulated pod when it finds
  ImpossiBLE (`OmniPumpManager.mocksPod`). LoopWorkspace `dev` pins OmnipodKit `dev`, which
  still mocks pod commands in the Simulator, so pairing there would never reach the pod.
* ImpossiBLE's menu bar app must **not** be running: the pod becomes the provider on
  `/tmp/impossible.sock` and refuses to start while another provider holds it
  (`make mac-stop` in an ImpossiBLE checkout, or quit it from the menu bar).

## 1. Build the pod simulator and make test registration data

```bash
git clone -b omnipod-five-v2 https://github.com/jwoglom/pod
cd pod
go build
go run ./cmd/o5keypair -swift > O5Data.swift      # for step 3
go run ./cmd/o5keypair > o5keypair.json           # alternative, see "Importing instead"
```

OmnipodKit will not start Omnipod 5 pairing without registration data (a P-256 signing key
and certificates). On a phone it downloads them; in the Simulator that fails ("App Attest is
not supported on this device"), so the generator makes self-signed data that pairs with the
simulator only. The pod verifies the phone's SPS2 signature against the key in the
certificate but, like OmnipodKit, validates no chain.

## 2. Build ImpossiBLE's library

[LoopKit/g7sim](https://github.com/LoopKit/g7sim) carries a script that builds a pinned
ImpossiBLE with the fixes Loop needs, as a dylib to inject at launch:

```bash
git clone https://github.com/LoopKit/g7sim
g7sim/simulator/build-impossible.sh              # prints .../simulator/build/libImpossiBLE.dylib
```

## 3. Build Loop with the test registration data

```bash
git clone -b next-dev --recurse-submodules https://github.com/LoopKit/LoopWorkspace
cp /path/to/pod/O5Data.swift LoopWorkspace/OmnipodKit/OmnipodKit/O5Data.swift
cd LoopWorkspace && xed .
```

`O5Data.swift` defines `O5RegistrationDataInstall`, which OmnipodKit looks up with `dlsym` at
start and calls (`O5CertificateStore.loadOptionalO5Data`), so the data is in place before
any pod is paired. OmnipodKit's project uses a synchronized folder, so Xcode picks the file up;
if it does not appear under OmnipodKit, add it to the OmnipodKit target. Keep it out of git.

In Xcode: scheme `LoopWorkspace`, an iPhone simulator as the destination, then Product → Run
once so the app is installed and the simulator is booted. (Signing: a free team works for
the Simulator; set `LOOP_DEVELOPMENT_TEAM` in `LoopConfigOverride.xcconfig` if Xcode asks.)

## 4. Start the pod, then launch Loop with ImpossiBLE injected

```bash
cd pod
./pod -transport impossible -mode o5 -fresh
```

The log says `serving the iOS Simulator on /tmp/impossible.sock` and `simulating an Omnipod 5
pod`; the control panel is at <http://localhost:8080/> and shows "Omnipod 5 pod".

Launch Loop with the library injected. Either from the terminal:

```bash
xcrun simctl listapps booted | grep -B1 -A1 'loopkit.Loop"'   # find Loop's bundle id
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/path/to/g7sim/simulator/build/libImpossiBLE.dylib \
    xcrun simctl launch booted <Loop's bundle id>
```

or from Xcode: scheme LoopWorkspace → Edit Scheme → Run → Arguments → Environment Variables,
add `DYLD_INSERT_LIBRARIES` = the dylib path (a local change), then Run.

The pod log then shows `simulator: <bundle id> (ImpossiBLE 3.x) connected`. Without the
library Loop behaves as before: pairing is mocked and the pod sees nothing.

## 5. Pair and run the pod in Loop

1. Settings → Insulin Pump → Add Pump → **Omnipod**.
2. Insulin type, then Pod Type → **Omnipod 5**. The "Omnipod 5 Setup" screen should show
   "Ready to pair with an Omnipod 5 Pod" (the compiled-in data was found). If it asks to
   download a certificate, `O5Data.swift` was not built in.
3. Pair Pod. Watch the pod log: `HELLO from controller 002a1c6c`, `Received SPS0`, `SPS1`,
   `SPS2.1`, `SPS2`, `The phone's SPS2 signature verifies`, `LTK …`, then the EAP‑AKA session
   (`got CK`), then `GET_VERSION`, the AID setup lines (`AID extended set 255.2 …`,
   `3.2`, `3.1`, `3.9`, `3.7`, `2.1` ×3), `SET_UNIQUE_ID` and the prime bolus, which must
   arrive as a signed command (`the command's signature verifies`).
4. Continue through Loop's wizard: prime (about a minute), attach, insert cannula (0.5 U
   bolus), done. The control panel should show progress "Running, above 50 U", the pod id
   and `controller 002A1C6C`, and "Signed commands rejected: 0".
5. Exercise it: a manual bolus, a temp basal (Loop's "Manual Temp Basal" in pump settings),
   suspend and resume delivery, read the pod status (Pod Diagnostics → Read Pod Status),
   trigger an alert and a fault from the control panel, and Deactivate Pod. Every
   insulin/cancel/deactivate command must verify; a nonzero "Signed commands rejected" means
   OmnipodKit sent one unsigned or with a bad signature, which the pod answered with error
   `0x2A`.
6. Reconnect: `kill`/relaunch Loop (or background it 3 minutes until the pod hangs up) and
   confirm the next command re-establishes the session (`new connection — re-establishing
   session` in the pod log, then normal commands).

A faulted pod advertises `CE1F923D-…-0A002A1C6C02`; OmnipodKit's O5 fault scan looks for
exactly that UUID, so a fault set on the control panel while Loop is backgrounded should
make Loop connect and read the fault.

## What to compare against the real-pod behaviour

* Pairing must complete with no `SPS2 signature does not verify` warning on either side.
  OmnipodKit's log (Console.app, process Loop, subsystem OmnipodKit) prints
  `Pod SPS2 signature verification PASSED`.
* No `AESCCM: Message authentication failed` in the pod log: that is a nonce or key drift
  between the two sides.
* No `invalidCrc` from OmnipodKit: the pod's response CRC16 is what it checks on O5 pods.
* `Signed commands rejected` stays 0.

## Importing instead of compiling the data in

OmnipodKit also imports an `o5keypair.json` from Settings → Omnipod → Omnipod 5 Support →
(…) → Load custom certificate. That screen exists only once a pod has been paired through
Loop, so this route needs a pod first, for example this simulator in `-mode dash`. Drop
`o5keypair.json` onto the Simulator window to put it in the Files app, import it, deactivate
the DASH pod, "Switch to another pod or pump type", choose Omnipod 5, and restart the pod
with `-mode o5 -fresh`.

## DASH regression check

Run the same wizard with `./pod -transport impossible -mode dash -fresh` and Pod Type
Omnipod DASH: pairing, priming, cannula insertion, a bolus, a temp basal and deactivation
must work as on LoopKit/pod `main`.

## With a simulated CGM too

g7sim's `impossible-mux` lets one app use both providers:

```bash
./pod -transport impossible -mode o5 -fresh -socket /tmp/impossible-pod.sock
g7sim -transport impossible -socket /tmp/impossible-g7.sock
impossible-mux /tmp/impossible-g7.sock /tmp/impossible-pod.sock
```
