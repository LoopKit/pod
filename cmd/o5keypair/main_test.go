package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
)

// The phone signs with the key in privateKey and shows tlsCertificate; the
// pod checks the signature against the key it reads out of that
// certificate, so the two have to be the same key, or every signed command
// would be refused.
func TestCertificateCarriesTheSigningKey(t *testing.T) {
	reg, err := generate(0x002A1C6C)
	if err != nil {
		t.Fatal(err)
	}

	der, err := base64.StdEncoding.DecodeString(reg.TLSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("the controller certificate does not parse: %v", err)
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		t.Fatal("the controller certificate does not carry a P-256 key")
	}

	want, err := hex.DecodeString(reg.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 64)
	public.X.FillBytes(got[:32])
	public.Y.FillBytes(got[32:])
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Error("the certificate's key is not the one in publicKey")
	}

	// publicKey must also be what privateKey derives to: OmnipodKit
	// refuses the registration otherwise (O5CertificateStore.init).
	scalar, err := hex.DecodeString(reg.PrivateKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(scalar) != 32 {
		t.Fatalf("privateKey is %d bytes, want 32", len(scalar))
	}
	d := new(big.Int).SetBytes(scalar)
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	derived := make([]byte, 64)
	x.FillBytes(derived[:32])
	y.FillBytes(derived[32:])
	if hex.EncodeToString(derived) != reg.PublicKeyHex {
		t.Error("publicKey is not what privateKey derives to")
	}
}

// The phone finds a key by looking for these exact SubjectPublicKeyInfo
// bytes in the certificate (O5CertificateStore.p256SPKIHeader), so both
// certificates have to be laid out that way.
func TestCertificatesHoldTheExpectedKeyLayout(t *testing.T) {
	spki, _ := hex.DecodeString("3059" + "3013" + "06072a8648ce3d0201" + "06082a8648ce3d030107" + "0342" + "00" + "04")

	reg, err := generate(0x002A1C6C)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string]string{
		"intermediate CA":        reg.IntermediateCA,
		"controller certificate": reg.TLSCertificate,
	} {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if !contains(der, spki) {
			t.Errorf("the %s does not hold the key layout the phone looks for", name)
		}
	}
}

func contains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// The app treats a controller id of 0 as no registration at all.
func TestControllerIdIsKept(t *testing.T) {
	reg, err := generate(0x00123456)
	if err != nil {
		t.Fatal(err)
	}
	if reg.ControllerId != 0x00123456 {
		t.Errorf("controller id is %08x, want 00123456", reg.ControllerId)
	}
	if reg.ControllerIdHex() != "0x00123456" {
		t.Errorf("ControllerIdHex = %s, want 0x00123456", reg.ControllerIdHex())
	}
}
