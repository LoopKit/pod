// Command o5keypair writes the Omnipod 5 registration data a phone needs
// before it will pair with the simulator.
//
// OmnipodKit will not start an Omnipod 5 pairing without a signing key and
// a certificate chain for the controller. On a phone it downloads them,
// which needs Apple's App Attest and so cannot work in the iOS Simulator.
// This makes a self-signed set instead. It pairs with this simulator
// because neither side validates the other's chain — the simulated pod
// reads the public key out of the certificate to check signatures, exactly
// as OmnipodKit does with the pod's — and it pairs with nothing else.
//
//	go run ./cmd/o5keypair -swift > O5Data.swift   # to build into OmnipodKit
//	go run ./cmd/o5keypair > o5keypair.json       # to import in the app
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
	"text/template"
	"time"
)

func main() {
	// 0x002A1C6C is a plausible controller id: a serial number shifted up
	// two bits, the way an Omnipod 5 controller forms its own.
	id := flag.Uint64("id", 0x002A1C6C, "the controller id to issue the data for")
	asSwift := flag.Bool("swift", false, "write a Swift file to build into OmnipodKit instead of JSON")
	flag.Parse()

	if *id == 0 || *id > 0xFFFFFFFF {
		fail(fmt.Errorf("the controller id must be between 1 and 0xFFFFFFFF, not 0x%X", *id))
	}
	controllerId := uint32(*id)

	reg, err := generate(controllerId)
	if err != nil {
		fail(err)
	}

	if *asSwift {
		if err := swiftTemplate.Execute(os.Stdout, reg); err != nil {
			fail(err)
		}
		return
	}
	out, err := json.MarshalIndent(reg.json(), "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(out))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "o5keypair: %s\n", err)
	os.Exit(1)
}

// registration is what OmnipodKit's O5RegistrationData holds.
type registration struct {
	ControllerId   uint32
	PrivateKeyHex  string
	PublicKeyHex   string
	IntermediateCA string // base64 DER
	TLSCertificate string // base64 DER
}

// ControllerIdHex is the id as the app prints it.
func (r registration) ControllerIdHex() string { return fmt.Sprintf("0x%08X", r.ControllerId) }

func (r registration) json() map[string]interface{} {
	return map[string]interface{}{
		"controllerId":   r.ControllerId,
		"privateKey":     r.PrivateKeyHex,
		"publicKey":      r.PublicKeyHex,
		"intermediateCA": r.IntermediateCA,
		"tlsCertificate": r.TLSCertificate,
	}
}

// generate makes the signing key and the two certificates. The signing
// key is what the phone signs pairing transcripts and insulin commands
// with, so the certificate it shows in SPS2 has to carry that same key:
// the pod checks the signature against the key in the certificate.
func generate(controllerId uint32) (registration, error) {
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return registration{}, fmt.Errorf("could not make the signing key: %w", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return registration{}, fmt.Errorf("could not make the issuing key: %w", err)
	}
	caDER, err := certificate(1, "pod simulator intermediate CA", &caKey.PublicKey, nil, caKey)
	if err != nil {
		return registration{}, fmt.Errorf("could not make the intermediate certificate: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return registration{}, err
	}

	leafDER, err := certificate(2, fmt.Sprintf("pod simulator controller %08X", controllerId), &signing.PublicKey, ca, caKey)
	if err != nil {
		return registration{}, fmt.Errorf("could not make the controller certificate: %w", err)
	}

	public := make([]byte, 64)
	signing.PublicKey.X.FillBytes(public[:32])
	signing.PublicKey.Y.FillBytes(public[32:])

	private := make([]byte, 32)
	signing.D.FillBytes(private)

	return registration{
		ControllerId:   controllerId,
		PrivateKeyHex:  hex.EncodeToString(private),
		PublicKeyHex:   hex.EncodeToString(public),
		IntermediateCA: base64.StdEncoding.EncodeToString(caDER),
		TLSCertificate: base64.StdEncoding.EncodeToString(leafDER),
	}, nil
}

// certificate issues one certificate, self-signed when parent is nil. The
// layout puts the public key in the standard P-256 SubjectPublicKeyInfo
// bytes, which is how both sides find it
// (O5CertificateStore.extractP256PublicKey).
func certificate(serial int64, commonName string, public *ecdsa.PublicKey, parent *x509.Certificate, signer *ecdsa.PrivateKey) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			Organization: []string{"pod simulator"},
			CommonName:   commonName,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:      true,
	}
	if parent == nil {
		parent = template
	}
	return x509.CreateCertificate(rand.Reader, template, parent, public, signer)
}

var swiftTemplate = template.Must(template.New("o5data").Parse(`//
//  O5Data.swift
//  OmnipodKit
//
//  Omnipod 5 registration data for the pod simulator
//  (github.com/LoopKit/pod, -mode o5), written by its cmd/o5keypair.
//  Self-signed: it pairs with that simulator and with nothing else, so
//  keep it out of git and out of any build meant for a real pod.
//
//  OmnipodKit looks this symbol up with dlsym at start and calls it, so
//  the data is in place before a pod is paired
//  (O5CertificateStore.loadOptionalO5Data).
//

import Foundation

@_cdecl("O5RegistrationDataInstall")
public func O5RegistrationDataInstall() {
    O5RegistrationData.install(O5RegistrationData(
        controllerId: {{ .ControllerIdHex }},
        privateKeyHex: "{{ .PrivateKeyHex }}",
        publicKeyHex: "{{ .PublicKeyHex }}",
        intermediateCABase64: "{{ .IntermediateCA }}",
        tlsCertificateBase64: "{{ .TLSCertificate }}"
    ))
}
`))
