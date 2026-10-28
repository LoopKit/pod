package pair

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
)

// The simulator signs every pod it serves with one fixed certificate
// authority, so that an app can tell a simulated pod from a real one rather
// than merely failing to recognise it.
//
// This mirrors what g7sim does for the G7: its CA is published so OmnipodKit's
// counterpart can report "simulated" positively. The private key below is in
// the repository on purpose — it is a development marker, not a secret, and
// its presence is what makes a pod identifiable as this simulator's. It
// proves nothing about authenticity and must never be treated as if it did.
//
// A pod shows this certificate in SPS2.1 and its own leaf, signed by this key,
// in SPS2 — the same shape the controller uses, where SPS2.1 carries the
// intermediate and SPS2 the leaf.
const simulatorCAKeyHex = "4a960ae2864081cb8407b78c963971bfda81f46df6abe14733a22a740d4dd8da"

var simulatorCACertHex = [...]string{
	"308201973082013da003020102020101300a06082a8648ce3d04030230333116",
	"3014060355040a130d706f642073696d756c61746f7231193017060355040313",
	"10706f642073696d756c61746f72204341301e170d3236303130313030303030",
	"305a170d3436303130313030303030305a303331163014060355040a130d706f",
	"642073696d756c61746f723119301706035504031310706f642073696d756c61",
	"746f722043413059301306072a8648ce3d020106082a8648ce3d030107034200",
	"0401653bc04b88ffebdc05d9d8bea3844edda6aa64241bf468cf85b503ce8108",
	"5a1f0f974e0a47bff7a6c999bb31e9cf78a3d10fbd1078452fbe8d3072c97988",
	"7ba3423040300e0603551d0f0101ff040403020284300f0603551d130101ff04",
	"0530030101ff301d0603551d0e0416041470d1e1f42826b71f50905e2a54bf54",
	"f78c984edd300a06082a8648ce3d0403020348003045022018e1132e0f591da2",
	"90c4897ed63350d50b5c500efdb8b646b2bbded837100ce00221009152ff20d4",
	"0f7ceb276180aa38a2d1a74911157b3c5f901ac79618effd8def38",
}

// simulatorCA is the authority every simulated pod's certificate chains to.
var simulatorCA = func() (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	scalar, err := hex.DecodeString(simulatorCAKeyHex)
	if err != nil {
		panic("pkg pair: the simulator CA key is not hex: " + err.Error())
	}
	key := new(ecdsa.PrivateKey)
	key.Curve = elliptic.P256()
	key.D = new(big.Int).SetBytes(scalar)
	key.PublicKey.X, key.PublicKey.Y = key.Curve.ScalarBaseMult(scalar)

	var joined string
	for _, part := range simulatorCACertHex {
		joined += part
	}
	der, err := hex.DecodeString(joined)
	if err != nil {
		panic("pkg pair: the simulator CA certificate is not hex: " + err.Error())
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic("pkg pair: the simulator CA certificate does not parse: " + err.Error())
	}
	return key, cert, der
}

// SimulatorCACertificate is the DER an app pins to recognise a pod served by
// this simulator.
func SimulatorCACertificate() []byte {
	_, _, der := simulatorCA()
	return append([]byte(nil), der...)
}

// checkSimulatorCA makes sure the embedded key really is the one that signed
// the embedded certificate, so a bad edit fails loudly rather than producing
// pods nothing can verify.
func checkSimulatorCA() error {
	key, cert, _ := simulatorCA()
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("the simulator CA certificate carries no P-256 key")
	}
	if pub.X.Cmp(key.PublicKey.X) != 0 || pub.Y.Cmp(key.PublicKey.Y) != 0 {
		return fmt.Errorf("the simulator CA key does not match its certificate")
	}
	return nil
}
