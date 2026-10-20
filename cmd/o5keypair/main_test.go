package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/avereha/pod/pkg/pair"
)

// The registration data is what OmnipodKit's O5CertificateStore checks: a
// 32-byte scalar whose public key is the 64-byte publicKey, and a TLS
// certificate the pod reads that same key from.
func TestRegistrationFitsOmnipodKit(t *testing.T) {
	r, err := newRegistration(0x002A1C6C)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := hex.DecodeString(r.PrivateKey)
	public, _ := hex.DecodeString(r.PublicKey)
	if len(private) != 32 || len(public) != 64 {
		t.Fatalf("key sizes %d and %d", len(private), len(public))
	}
	tls, err := base64.StdEncoding.DecodeString(r.TLSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	fromCert, err := pair.PublicKeyFromCert(tls)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromCert, public) {
		t.Fatal("the TLS certificate does not carry the signing key")
	}
	id, err := pair.LoadPodIdentity(private, tls)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id.PublicRaw(), public) {
		t.Fatal("publicKey is not the public key of privateKey")
	}
	ca, err := base64.StdEncoding.DecodeString(r.IntermediateCA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pair.PublicKeyFromCert(ca); err != nil {
		t.Fatal(err)
	}
	src := swiftSource(r)
	for _, want := range []string{`@_cdecl("O5RegistrationDataInstall")`, "controllerId: 0x002A1C6C", r.PrivateKey, r.TLSCertificate} {
		if !strings.Contains(src, want) {
			t.Errorf("Swift source lacks %q", want)
		}
	}
}
