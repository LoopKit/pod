#!/bin/sh
# Runs each scenario of docs/BLE_E2E_TEST.md and checks it against what it
# should do; exits 1 if any does otherwise.
#   run-all.sh [POD_BINARY]   default out/pod
[ "$(id -u)" -eq 0 ] || exec sudo sh "$0" "$@"
here=$(cd "$(dirname "$0")" && pwd)
pod=${1:-pod}
bad=0

# check NAME MODE PHONE_MTU PHONE_SERVER_MTU pass|fail
check() {
	sh "$here/run-scenario.sh" "$1" "$2" "$3" "$4" "$pod" > /dev/null 2>&1
	rc=$?
	s=$here/out/results/$1/summary.txt
	got=pass
	[ $rc -eq 0 ] || got=fail
	mtu=$(grep -o "ATT MTU [0-9]*:" "$s" | head -1 | tr -d :)
	asked=$(grep -o "the pod asked for an MTU of [0-9]*" "$s" | head -1)
	acl=$(grep -o "reassembly errors: [0-9]*" "$s")
	verdict=ok
	[ "$got" = "$5" ] || { verdict=UNEXPECTED; bad=1; }
	if [ "$5" = fail ] && ! grep -q "WARN.*ATT MTU" "$s"; then
		verdict="UNEXPECTED (no MTU warning)"; bad=1
	fi
	# An ATT error must get no answer: the pod answering one is a bug.
	if grep -q "unasked error PDU" "$here/out/results/$1/test.log"; then
		verdict="UNEXPECTED (the pod answered an error)"; bad=1
	fi
	printf '%-16s %-4s want %-4s got %-4s %-11s %-32s %-22s %s\n' "$1" "$2" "$5" "$got" "${mtu:-?}" \
		"${asked:-the pod did not ask}" "$acl" "$verdict"
}

check o5-185-527    o5   185  527    pass # the pod asks for 256 and gets it
check o5-185-185    o5   185  185    fail # the phone will not go above 185
check o5-185-error  o5   185  error  fail # the phone refuses the exchange
check o5-185-ignore o5   185  ignore fail # the phone never answers it
check o5-527-527    o5   527  527    pass # 256 at once; the pod does not ask
check o5-none-527   o5   none 527    pass # no exchange from the phone; the pod asks
check dash-185-527  dash 185  527    pass # DASH packets fit 185; the pod does not ask
check dash-527-527  dash 527  527    pass
exit $bad
