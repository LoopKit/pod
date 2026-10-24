#!/bin/sh
# Builds the pod and the over-the-air test for Linux into scripts/ble-e2e/out,
# for the architecture of this machine (a Lima VM's matches its host's).
#   build.sh [GIT_REF]   with a ref, also builds that commit's pod as out/pod-REF
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) echo "unknown architecture $(uname -m)" >&2; exit 1 ;;
esac
mkdir -p "$here/out"
cd "$root"
GOOS=linux GOARCH=$arch go build -o "$here/out/pod" .
GOOS=linux GOARCH=$arch go test -c -tags ble_e2e -o "$here/out/pod_e2e.test" ./pkg/pod
echo "out/pod, out/pod_e2e.test (linux/$arch)"
if [ $# -gt 0 ]; then
	src=$(mktemp -d)
	git archive "$1" | tar -x -C "$src"
	(cd "$src" && GOOS=linux GOARCH=$arch go build -o "$here/out/pod-$1" .)
	rm -rf "$src"
	echo "out/pod-$1"
fi
