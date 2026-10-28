package pair

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// The CA is fixed and in the repository so that an app can recognise a pod
// this simulator served, rather than merely failing to recognise it. A bad
// edit to either constant has to fail loudly.
func TestSimulatorCAIsSelfConsistent(t *testing.T) {
	if err := checkSimulatorCA(); err != nil {
		t.Fatalf("the embedded CA is inconsistent: %v", err)
	}
	_, cert, der := simulatorCA()
	if !cert.IsCA {
		t.Error("the simulator CA is not marked as a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("the simulator CA cannot sign certificates")
	}
	if got := SimulatorCACertificate(); hex.EncodeToString(got) != hex.EncodeToString(der) {
		t.Error("SimulatorCACertificate returned something other than the embedded DER")
	}
}

// Every pod this simulator serves must chain to that one CA, which is what
// lets an app report "simulated" positively. A real pod chains to Insulet's
// INS01PG1 instead.
func TestEveryPodChainsToTheSimulatorCA(t *testing.T) {
	_, caCert, caDER := simulatorCA()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemOf(caDER)) {
		t.Fatal("could not build a pool from the simulator CA")
	}

	var firstLeaf string
	for i := 0; i < 3; i++ {
		pod, err := NewO5()
		if err != nil {
			t.Fatal(err)
		}

		// SPS2.1 shows the CA, SPS2 the leaf — as the controller sends its
		// intermediate then its leaf.
		if hex.EncodeToString(pod.caDER) != hex.EncodeToString(caDER) {
			t.Fatal("the pod did not show the simulator CA in SPS2.1")
		}

		leaf, err := x509.ParseCertificate(pod.leafDER)
		if err != nil {
			t.Fatalf("the pod's leaf does not parse: %v", err)
		}
		// The chain must verify. Expiry is deliberately not part of this:
		// a real pod's leaf was found expired and still pairing, so an
		// authenticity check must not depend on validity dates.
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:       roots,
			CurrentTime: leaf.NotBefore.Add(1),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Fatalf("the pod's leaf does not chain to the simulator CA: %v", err)
		}
		if err := leaf.CheckSignatureFrom(caCert); err != nil {
			t.Errorf("the CA did not sign the pod's leaf: %v", err)
		}

		// The key the pod signs SPS2 with is the one in its leaf.
		leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("the pod's leaf carries no P-256 key")
		}
		if leafKey.X.Cmp(pod.identity.PublicKey.X) != 0 || leafKey.Y.Cmp(pod.identity.PublicKey.Y) != 0 {
			t.Error("the pod's leaf does not carry the key it signs with")
		}

		// Each pod is its own, so a leaf never identifies the simulator by
		// being identical to another's.
		if i == 0 {
			firstLeaf = hex.EncodeToString(pod.leafDER)
		} else if hex.EncodeToString(pod.leafDER) == firstLeaf {
			t.Error("two pods were served the same leaf certificate")
		}
	}
}

func pemOf(der []byte) []byte {
	out := []byte("-----BEGIN CERTIFICATE-----\n")
	b64 := base64Encode(der)
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		out = append(out, b64[i:end]...)
		out = append(out, '\n')
	}
	return append(out, []byte("-----END CERTIFICATE-----\n")...)
}
