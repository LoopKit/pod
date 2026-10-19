//go:build !linux
// +build !linux

package bluetooth

import "errors"

func NewGattRadio(b *Ble, id []byte) (Radio, error) {
	return nil, errors.New("the Bluetooth transport needs Linux; use -transport impossible for the iOS Simulator")
}
