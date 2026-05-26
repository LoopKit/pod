// Package testfixtures embeds real Omnipod 5 BLE captures from
// /Users/james/repos/Omnipod5APK/BTSNOOP for use in unit tests.
//
// All payloads are the post-StringLengthPrefixEncoding values, i.e. the bytes
// after the "SPS1=", "SPS2.1=", "SPS2=" length-prefixed key-value envelope.
//
//   - SPS1 payloads are 80 bytes = 64-byte P-256 public key (raw X||Y, no leading 0x04)
//     followed by a 16-byte nonce.
//   - SPS2.1 payloads are AES-CCM(conf, sps_nonce_write|read, 8-byte tag) of an
//     intermediate-CA cert DER. Phone->pod is 642 bytes (634 cert + 8 tag);
//     pod->phone is 641 bytes (633 cert + 8 tag).
//   - SPS2 payloads are AES-CCM of TLS_cert_DER || ECDSA_signature(64).
//
// The KDF inputs (pdmPublic/podPublic/pdmNonce/podNonce) are extractable but
// the corresponding private keys are not in the captures, so these fixtures
// cannot be used to KAT the SHA-256 KDF directly via decryption. They are
// useful for structural/parsing tests and for end-to-end replay against the
// simulator's pod side.
package testfixtures

import (
	"embed"
	"fmt"
)

//go:embed btsnoop1/*.bin btsnoop2/*.bin
var fs embed.FS

// SPS1Payload is the parsed SPS1 contents: a 64-byte raw P-256 public key
// (X||Y, no leading 0x04 prefix) and a 16-byte nonce.
type SPS1Payload struct {
	Public []byte // 64 bytes
	Nonce  []byte // 16 bytes
}

// PairingCapture bundles the SPS payloads for one captured pairing session.
// Any field may be nil if that direction was not captured.
type PairingCapture struct {
	Name string

	PDMSPS1 *SPS1Payload // phone -> pod
	PodSPS1 *SPS1Payload // pod -> phone

	PDMSPS21Ciphertext []byte // phone -> pod, AES-CCM
	PodSPS21Ciphertext []byte // pod -> phone, AES-CCM
	PDMSPS2Ciphertext  []byte // phone -> pod, AES-CCM
	PodSPS2Ciphertext  []byte // pod -> phone, AES-CCM
}

func mustRead(path string) []byte {
	b, err := fs.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("testfixtures: %v", err))
	}
	return b
}

func parseSPS1(b []byte) *SPS1Payload {
	if len(b) != 80 {
		panic(fmt.Sprintf("testfixtures: SPS1 expected 80 bytes, got %d", len(b)))
	}
	return &SPS1Payload{Public: b[0:64], Nonce: b[64:80]}
}

// Captures returns every pairing capture available, in deterministic order.
// btsnoop1 has two sessions; btsnoop2 has one.
func Captures() []*PairingCapture {
	return []*PairingCapture{
		{
			Name:               "btsnoop1/session1",
			PDMSPS1:            parseSPS1(mustRead("btsnoop1/SPS1_src__dst__1382.bin")),
			PodSPS1:            parseSPS1(mustRead("btsnoop1/SPS1_src__dst__1387.bin")),
			PDMSPS21Ciphertext: mustRead("btsnoop1/session1_SPS2.1_phone_to_pod.bin"),
			PodSPS21Ciphertext: mustRead("btsnoop1/session1_SPS2.1_pod_to_phone.bin"),
			PDMSPS2Ciphertext:  mustRead("btsnoop1/session1_SPS2_phone_to_pod.bin"),
			// session1 pod->phone SPS2 was not captured.
		},
		{
			Name:               "btsnoop1/session2",
			PDMSPS1:            parseSPS1(mustRead("btsnoop1/SPS1_src__dst__1590.bin")),
			PodSPS1:            parseSPS1(mustRead("btsnoop1/SPS1_src__dst__1598.bin")),
			PDMSPS21Ciphertext: mustRead("btsnoop1/session2_SPS2.1_phone_to_pod.bin"),
			PodSPS21Ciphertext: mustRead("btsnoop1/session2_SPS2.1_pod_to_phone.bin"),
			PDMSPS2Ciphertext:  mustRead("btsnoop1/session2_SPS2_phone_to_pod.bin"),
			PodSPS2Ciphertext:  mustRead("btsnoop1/session2_SPS2_pod_to_phone.bin"),
		},
		{
			Name:               "btsnoop2",
			PDMSPS1:            parseSPS1(mustRead("btsnoop2/SPS1_src__dst__1694.bin")),
			PodSPS1:            parseSPS1(mustRead("btsnoop2/SPS1_src__dst__1701.bin")),
			PDMSPS21Ciphertext: mustRead("btsnoop2/SPS2.1_phone_to_pod.bin"),
			PodSPS21Ciphertext: mustRead("btsnoop2/SPS2.1_pod_to_phone.bin"),
			PDMSPS2Ciphertext:  mustRead("btsnoop2/SPS2_phone_to_pod.bin"),
			PodSPS2Ciphertext:  mustRead("btsnoop2/SPS2_pod_to_phone.bin"),
		},
	}
}
