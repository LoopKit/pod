package crc

// Omnipod messages carry two checksums, and neither is a textbook one.

// crc16Table is the table OmnipodKit's crc16Table holds, built MSB-first
// from the polynomial 0x8005 but used by CRC16 LSB-first. The combination
// is what the pods do, so it is what the phone checks.
var crc16Table = func() [256]uint16 {
	var t [256]uint16
	for i := range t {
		c := uint16(i) << 8
		for bit := 0; bit < 8; bit++ {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x8005
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return t
}()

// CRC16Sum is the checksum of an Omnipod message body
// (OmnipodCommon/CRC16.swift, Sequence.crc16).
func CRC16Sum(data []byte) uint16 {
	var acc uint16
	for _, b := range data {
		acc = acc>>8 ^ crc16Table[(acc^uint16(b))&0xff]
	}
	return acc
}

// CRC16 is CRC16Sum big-endian, as it goes on the wire.
//
// Omnipod 5 pods compute this and the phone rejects a response whose value
// is wrong (BleMessageTransport.parseResponse checks it for an O5 pod and
// not for a DASH, whose own value the DASH PDM ignores).
func CRC16(data []byte) []byte {
	sum := CRC16Sum(data)
	return []byte{byte(sum >> 8), byte(sum)}
}

// XMODEM is CRC-16/XMODEM: the polynomial 0x1021 MSB-first from zero. The
// Omnipod 5 SPS0 pairing payload carries it (O5LTKExchanger.crc16XMODEM).
func XMODEM(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for bit := 0; bit < 8; bit++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
