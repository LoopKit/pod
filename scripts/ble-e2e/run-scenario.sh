#!/bin/sh
# One over-the-air run: two fresh virtual controllers, the pod on hci0 (HCI
# user channel, as on a Pi), the phone model on hci1 (the kernel's ATT).
#   run-scenario.sh NAME MODE PHONE_MTU PHONE_SERVER_MTU [POD_BINARY]
# MODE is dash or o5; PHONE_MTU is what the phone offers as it connects
# ("none" for nothing); PHONE_SERVER_MTU how it answers an exchange the pod
# starts (an MTU, "error" or "ignore"); POD_BINARY is in out/ (default pod).
# Results go to out/results/NAME. See docs/BLE_E2E_TEST.md.
set -u
[ "$(id -u)" -eq 0 ] || exec sudo sh "$0" "$@"
name=$1 mode=$2 offer=$3 answer=$4 pod=${5:-pod}
here=$(cd "$(dirname "$0")" && pwd)
out=$here/out/results/$name
rm -rf "$out"; mkdir -p "$out"

units() { systemctl list-units --all --plain --no-legend "$1*" | awk '{print $1}'; }
stop() {
	# The pod first: it holds a virtual controller that btvirt removes.
	for u in $(units pod-e2e) $(units btvirt-e2e); do
		systemctl stop "$u" 2>/dev/null
		systemctl reset-failed "$u" 2>/dev/null
	done
}
stop
run=$(date +%s)
# LE-only controllers: btdev reports legacy advertising, which gatt uses,
# only to a scanner that scans the legacy way, as the kernel does for an
# LE-only (Bluetooth 4) controller.
timeout 20 systemd-run --quiet --unit="btvirt-e2e-$run" /usr/local/bin/btvirt -L -l2
for i in $(seq 1 50); do [ -e /sys/class/bluetooth/hci1 ] && break; sleep 0.1; done
sleep 0.5
addr=$(hciconfig hci0 | awk '/BD Address/{print $3}')
echo "pod on hci0 $addr; phone on hci1 $(hciconfig hci1 | awk '/BD Address/{print $3}')" > "$out/summary.txt"

rm -f /tmp/pod-e2e.toml /tmp/pod-e2e.log
dmesg -C
timeout 20 systemd-run --quiet --unit="pod-e2e-$run" -p TimeoutStopSec=5 \
	-p StandardOutput=file:/tmp/pod-e2e.log -p StandardError=file:/tmp/pod-e2e.log \
	"$here/out/$pod" -mode "$mode" -fresh -v -state /tmp/pod-e2e.toml -api 127.0.0.1:8080
for i in $(seq 1 50); do grep -qa "Listening for commands" /tmp/pod-e2e.log 2>/dev/null && break; sleep 0.2; done
sleep 1

# The test turns on LE and power on hci1 itself, through the management socket.
env POD_ADDR="$addr" POD_MODE="$mode" PHONE_MTU="$offer" PHONE_SERVER_MTU="$answer" \
	timeout 150 "$here/out/pod_e2e.test" -test.run TestOverTheAir -test.v -test.timeout 120s > "$out/test.log" 2>&1
rc=$?
sleep 1
stop
cat /tmp/pod-e2e.log | tr -d '\000' | sed 's/\x1b\[[0-9;]*m//g' > "$out/pod.log"
{
	echo "scenario $name: pod=$pod mode=$mode phone offers=$offer answers=$answer -> test exit $rc"
	echo "kernel ACL reassembly errors: $(dmesg | grep -c 'Unexpected .* frame')"
	grep -E "ATT MTU|panic|ERRO|WARN|NACK|hanging up" "$out/pod.log" | head -20
	echo "--- test"
	grep -E "ble_e2e_linux_test|phone_test|^(---|ok|FAIL|PASS)" "$out/test.log" | head -30
} >> "$out/summary.txt"
cat "$out/summary.txt"
exit $rc
