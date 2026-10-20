// o5keypair writes Omnipod 5 registration data for OmnipodKit to pair with
// the pod simulator: a P-256 signing key and self-signed certificates in
// the o5keypair JSON format its "Load custom certificate" import takes, or
// as a Swift file that compiles the same data into OmnipodKit.
//
// The simulator checks the key in the certificate against the SPS2
// signature but validates no certificate chain, as OmnipodKit does not
// validate the pod's, so self-signed certificates serve. This data pairs
// with the simulator only; a real Omnipod 5 refuses it.
//
//	go run ./cmd/o5keypair > o5keypair.json
//	go run ./cmd/o5keypair -swift > O5Data.swift
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"
)

type registration struct {
	ControllerID   uint32 `json:"controllerId"`
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	IntermediateCA string `json:"intermediateCA"`
	TLSCertificate string `json:"tlsCertificate"`
}

func selfSigned(key *ecdsa.PrivateKey, cn string, serial int64) ([]byte, error) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{Organization: []string{"pod simulator"}, CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// newRegistration makes registration data for controllerId.
func newRegistration(controllerID uint32) (*registration, error) {
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	intermediate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// The TLS certificate carries the signing key: the pod takes the
	// phone's key from it and verifies the SPS2 signature with it.
	tls, err := selfSigned(signing, fmt.Sprintf("pod simulator controller %08X", controllerID), 2)
	if err != nil {
		return nil, err
	}
	ca, err := selfSigned(intermediate, "pod simulator intermediate CA", 1)
	if err != nil {
		return nil, err
	}
	return &registration{
		ControllerID:   controllerID,
		PrivateKey:     hex.EncodeToString(pad32(signing.D.Bytes())),
		PublicKey:      hex.EncodeToString(append(pad32(signing.X.Bytes()), pad32(signing.Y.Bytes())...)),
		IntermediateCA: base64.StdEncoding.EncodeToString(ca),
		TLSCertificate: base64.StdEncoding.EncodeToString(tls),
	}, nil
}

// swiftSource is a file for OmnipodKit's own target. OmnipodKit looks up
// O5RegistrationDataInstall with dlsym at start and calls it, so this data
// is available before any pod is paired (O5CertificateStore.loadOptionalO5Data).
func swiftSource(r *registration) string {
	return fmt.Sprintf(`//
//  O5Data.swift
//  OmnipodKit
//
//  Registration data for the pod simulator (github.com/LoopKit/pod, -mode o5),
//  written by its cmd/o5keypair. Pairs with the simulator only.
//  OmnipodKit finds O5RegistrationDataInstall with dlsym and calls it at start.
//

import Foundation

@_cdecl("O5RegistrationDataInstall")
public func O5RegistrationDataInstall() {
    O5RegistrationData.install(O5RegistrationData(
        controllerId: 0x%08X,
        privateKeyHex: %q,
        publicKeyHex: %q,
        intermediateCABase64: %q,
        tlsCertificateBase64: %q
    ))
}
`, r.ControllerID, r.PrivateKey, r.PublicKey, r.IntermediateCA, r.TLSCertificate)
}

func main() {
	controller := flag.Uint("controller", 0x002A1C6C, "the controller id; its low two bits must be 0, the pod ids are the next three")
	swift := flag.Bool("swift", false, "write O5Data.swift for the OmnipodKit target instead of o5keypair JSON")
	flag.Parse()
	if *controller == 0 || *controller&0b11 != 0 || *controller > 0xFFFFFFFF {
		fmt.Fprintln(os.Stderr, "-controller: want a 32-bit id with its low two bits 0")
		os.Exit(2)
	}
	r, err := newRegistration(uint32(*controller))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *swift {
		fmt.Print(swiftSource(r))
		return
	}
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
}
