package bluetooth

import (
	"crypto/rand"
	"fmt"
)

// RandomStaticAddress makes a random static Bluetooth address, written most
// significant byte first, as in "C4:1F:22:9A:07:5E". Each fresh pod gets its
// own, as every real pod has its own address. A phone then treats a new pod as
// a new device, with nothing cached from the pod before it, which may have
// been the other kind with a different data characteristic.
func RandomStaticAddress() string {
	var a [6]byte
	for {
		rand.Read(a[:])
		// The two most significant bits of a static address are both 1.
		a[0] |= 0xC0
		// The rest of the address can be neither all 0s nor all 1s.
		rest := a
		rest[0] &^= 0xC0
		if rest != [6]byte{} && rest != [6]byte{0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} {
			break
		}
	}
	return formatAddress(a)
}

func formatAddress(a [6]byte) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", a[0], a[1], a[2], a[3], a[4], a[5])
}

// ParseStaticAddress reads an address written by RandomStaticAddress.
func ParseStaticAddress(s string) ([6]byte, error) {
	var a [6]byte
	if _, err := fmt.Sscanf(s, "%02X:%02X:%02X:%02X:%02X:%02X", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]); err != nil {
		return a, fmt.Errorf("Bluetooth address %q: %w", s, err)
	}
	if formatAddress(a) != s {
		return a, fmt.Errorf("Bluetooth address %q: want six hex bytes such as C4:1F:22:9A:07:5E", s)
	}
	if a[0]&0xC0 != 0xC0 {
		return a, fmt.Errorf("Bluetooth address %q is not a static random address: its first byte must be C0 or above", s)
	}
	return a, nil
}
