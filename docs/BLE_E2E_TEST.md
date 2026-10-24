# Test the Linux Bluetooth radio over the air

`pkg/pod/ble_e2e_linux_test.go` runs the pod binary on one Bluetooth controller and the Go model of
OmnipodKit's phone (`pkg/pod/phone_test.go`) on another, over the Linux Bluetooth stack: the path an
iPhone takes to a pod on a Raspberry Pi, which the in-memory tests and the iOS Simulator (ImpossiBLE)
do not exercise. The phone behaves as iOS does where it matters here: it starts its own ATT MTU
exchange as it connects, and it cuts a write without response to MTU-3 bytes. It pairs, opens a
session, and sends AssignAddress, the Omnipod 5 AID setup, SetupPod, a status read and a bolus
(unsigned, then signed, on an Omnipod 5).

It needs Linux with two controllers. Two virtual ones from BlueZ's `btvirt` do; on a Mac, in a
[Lima](https://lima-vm.io) VM. The test is behind the `ble_e2e` build tag, so `go test ./...` and CI
skip it.

## Run it

On a Mac (Intel or Apple Silicon), from the repository:

```bash
brew install lima
limactl start --name=podble --tty=false --vm-type=vz --cpus=2 --memory=3 --containerd=none \
    --mount-only "$PWD:w" template:ubuntu-24.04
limactl shell podble -- sh scripts/ble-e2e/setup-vm.sh   # once: packages, hci_vhci, btvirt
scripts/ble-e2e/build.sh                                  # on the Mac: out/pod, out/pod_e2e.test
limactl shell podble -- sh scripts/ble-e2e/run-all.sh
```

`run-all.sh` prints a line per scenario and exits 1 if one does not do what it should; each run's
`summary.txt`, `pod.log` (with `-v`) and `test.log` are in `scripts/ble-e2e/out/results/<name>/`.
One scenario on its own: `scripts/ble-e2e/run-scenario.sh NAME MODE PHONE_MTU PHONE_SERVER_MTU [POD]`.
`build.sh REF` also builds the pod of a commit as `out/pod-REF`, to run against: `run-all.sh pod-REF`.

On Linux without a VM, run `setup-vm.sh` and the other two scripts directly (Ubuntu 24.04; they stop
nothing but their own processes, but `setup-vm.sh` masks `bluetoothd`).

## Scenarios

| name | phone offers | phone answers the pod's request | should |
|---|---|---|---|
| `o5-185-527` | 185 | 527 | pass: the pod asks for 256 and gets it |
| `o5-185-185`, `o5-185-error`, `o5-185-ignore` | 185 | 185, an error, nothing | fail: the MTU stays 185, the pod warns, SPS2.1 is cut short |
| `o5-527-527` | 527 | 527 | pass: 256 at once, the pod does not ask |
| `o5-none-527` | nothing | 527 | pass: the pod asks |
| `dash-185-527`, `dash-527-527` | 185, 527 | 527 | pass: DASH packets fit any MTU; the pod does not ask |

The pod at commit `ba86841` (before the MTU request) fails `o5-185-527` as a Pi did with an iPhone
offering 185; at `40cd439` (the request without `6dc120d`) the MTU is 256 but the kernel drops the
pod's packets ("Unexpected start frame" in `dmesg`, counted in the summary).

## What the scripts work around

- **btvirt answers a command it does not implement with Command Status**, and paypal/gatt panics on
  that: its controller reset sends BR/EDR commands such as Write Inquiry Scan Type (0x0c43).
  `setup-vm.sh` patches the emulator to answer them with success, as a real controller does.
- **The controllers are LE-only (`btvirt -L`).** With the default Bluetooth 5.2 ones, the kernel scans
  for the pod with extended scanning, and btdev does not report gatt's legacy advertising to it.
- **The phone's adapter must have LE on**, or the kernel refuses the connection. The test turns on LE
  and power through the management socket; `btmgmt` 5.72 applies `--index` only after running a
  command given on its command line, so it cannot do this.
- **bluetoothd is masked** so it leaves the controllers alone, and btvirt and the pod run as their
  own systemd units, so that one run's leftovers do not hold the next one up.
