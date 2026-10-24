#!/bin/sh
# Prepares an Ubuntu 24.04 machine (a VM) for the over-the-air test: the
# virtual HCI kernel module, BlueZ's btvirt controller emulator and hciconfig.
# Safe to run again. See docs/BLE_E2E_TEST.md.
set -eu
export DEBIAN_FRONTEND=noninteractive
# sudo looks up this host's name; a Lima VM's is not in /etc/hosts, so every
# sudo waited out a DNS timeout (15 s).
grep -qw "$(hostname)" /etc/hosts || echo "127.0.1.1 $(hostname)" | sudo tee -a /etc/hosts > /dev/null
sudo apt-get update -q
sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" bluez libbluetooth-dev build-essential \
	pkg-config libglib2.0-dev libdbus-1-dev libudev-dev libical-dev libreadline-dev python3-docutils wget xz-utils
# bluetoothd would take the virtual controllers.
sudo systemctl disable --now bluetooth.service 2>/dev/null || true
sudo systemctl mask bluetooth.service
sudo modprobe hci_vhci
echo hci_vhci | sudo tee /etc/modules-load.d/hci_vhci.conf > /dev/null

# btvirt from the BlueZ release Ubuntu ships (Ubuntu does not package it).
v=$(dpkg-query -W -f='${Version}' bluez | cut -d- -f1)
cd ~
[ -d "bluez-$v" ] || wget -q "https://www.kernel.org/pub/linux/bluetooth/bluez-$v.tar.xz" -O - | tar -xJ
cd "bluez-$v"
# btdev answers a command it does not implement with Command Status, and
# paypal/gatt panics on that: its reset sends BR/EDR commands such as Write
# Inquiry Scan Type (0x0c43). Answer them with success, as a real controller.
if ! grep -q "pod e2e" emulator/btdev.c; then
	perl -0pi -e 's{("Unsupported command 0x%4\.4x", opcode\);\n\n)\tcmd_status\(btdev, BT_HCI_ERR_UNKNOWN_COMMAND, opcode\);}{$1\t{\n\t\t/* pod e2e: succeed, as a real controller would */\n\t\tuint8_t ok = BT_HCI_ERR_SUCCESS;\n\t\tcmd_complete(btdev, opcode, &ok, sizeof(ok));\n\t}}' emulator/btdev.c
	grep -q "pod e2e" emulator/btdev.c || { echo "could not patch emulator/btdev.c of BlueZ $v" >&2; exit 1; }
fi
[ -f Makefile ] || ./configure -q --disable-systemd --disable-cups --disable-obex --disable-mesh \
	--disable-midi --disable-manpages --enable-testing --enable-experimental
make -s -j"$(nproc)" emulator/btvirt
sudo install -m 755 emulator/btvirt /usr/local/bin/btvirt
echo "ready: btvirt from BlueZ $v, hci_vhci loaded, bluetoothd masked"
