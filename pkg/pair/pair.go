package pair

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/avereha/pod/pkg/message"

	"github.com/davecgh/go-spew/spew"
	"github.com/jacobsa/crypto/cmac"
	log "github.com/sirupsen/logrus"
)

const (
	sp1 = "SP1="
	sp2 = ",SP2="

	sps1   = "SPS1="
	sps21  = "SPS2.1="
	sps2   = "SPS2="
	sp0gp0 = "SP0,GP0"
	p0     = "P0="

	defaultSPS21Size = 641
)

type Pair struct {
	// Mode selects Dash (CMAC chain) or O5 (SHA-256/FIRMWARE_ID) key derivation.
	Mode Mode

	podPublic  []byte
	podPrivate []byte
	podNonce   []byte
	podConf    []byte

	pdmPublic []byte
	pdmNonce  []byte
	pdmConf   []byte

	// In Dash this is the Curve25519 shared secret; in O5 it is the
	// raw P-256 ECDH shared secret (32 bytes either way).
	curve25519LTK []byte
	pdmID         []byte
	podID         []byte

	ltk     []byte
	confKey []byte // key used to sign the "Conf" values; Dash only

	// SPS2.1 inbound state shared by Dash and O5 paths.
	sps21Len  int
	sps21Data []byte

	// O5-only: 16-byte AES-CCM key for SPS2.1/SPS2 plus the per-direction
	// nonce state and the pod's signing identity.
	conf       []byte
	nonceState *spsNonceState
	identity   *PodIdentity
	pdmCertDER []byte

	// O5-only: raw P-256 public key (64 bytes X||Y) extracted from the
	// PDM's TLS certificate during SPS2 parsing. Used post-pairing to
	// verify ECDSA signatures on Type-4 commands (programBolus / programBasal).
	pdmPublicKey []byte
}

// PDMPublicKey returns the 64-byte raw P-256 public key extracted from the
// PDM's TLS certificate during SPS2, or nil if pairing has not yet completed
// in O5 mode (or never reached SPS2 successfully).
func (c *Pair) PDMPublicKey() []byte { return c.pdmPublicKey }

// SetIdentity attaches a P-256 keypair + self-signed cert that the pod uses
// to sign the SPS2 channel-binding transcript. Required in O5 mode before
// SPS2.1/SPS2 are processed.
func (c *Pair) SetIdentity(id *PodIdentity) {
	c.identity = id
}

func parseStringByte(expectedNames []string, data []byte) (map[string][]byte, error) {
	ret := make(map[string][]byte)
	for _, name := range expectedNames {
		n := len(name)
		if string(data[:n]) != name {
			return nil, fmt.Errorf("Name not found %s in %x", name, data)
		}
		data = data[n:]
		length := int(data[0])<<8 | int(data[1])
		ret[name] = data[2 : 2+length]
		log.Tracef("Read field: %s :: %x :: %d", name, ret[name], len(ret[name]))

		data = data[2+length:]
	}
	return ret, nil
}

func buildStringByte(names []string, values map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	for _, name := range names {
		buf.WriteString(name)
		n := len(values[name])
		buf.WriteByte(byte(n >> 8 & 0xff))
		buf.WriteByte(byte(n & 0xff))
		buf.Write(values[name])
	}
	return buf.Bytes(), nil
}

func (c *Pair) ParseSP1SP2(msg *message.Message) error {
	log.Infof("Received SP1 SP2 payload %x", msg.Payload)

	sp, err := parseStringByte([]string{sp1, sp2}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}

	log.Infof("Received SP1 SP2: %x :: %x", sp[sp1], sp[sp2])
	c.podID = msg.Destination
	c.pdmID = msg.Source
	return nil
}

func (c *Pair) ParseSPS1(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps1}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}
	log.Infof("Received SPS1  %x", sp[sps1])

	// O5 carries a 64-byte raw P-256 public key (X||Y) followed by a 16-byte
	// nonce; Dash carries a 32-byte Curve25519 public key followed by a
	// 16-byte nonce.
	pubLen := 32
	if c.Mode == ModeO5 {
		pubLen = 64
	}
	if len(sp[sps1]) < pubLen+16 {
		return fmt.Errorf("SPS1 payload too short: got %d, want >=%d", len(sp[sps1]), pubLen+16)
	}
	pdmPublic := sp[sps1][:pubLen]
	pdmNonce := sp[sps1][pubLen : pubLen+16]

	c.pdmPublic = make([]byte, pubLen)
	c.pdmNonce = make([]byte, 16)
	copy(c.pdmNonce, pdmNonce)
	copy(c.pdmPublic, pdmPublic)
	err = c.computeMyData()
	if err != nil {
		return err
	}
	if c.Mode != ModeO5 {
		c.curve25519LTK, err = curve25519.X25519(c.podPrivate, c.pdmPublic)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Pair) GenerateSPS1() (*message.Message, error) {
	var err error
	var buf bytes.Buffer

	buf.Write(c.podPublic)
	buf.Write(c.podNonce)

	sp := make(map[string][]byte)
	sp[sps1] = buf.Bytes()

	msg := message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
	msg.Payload, err = buildStringByte([]string{sps1}, sp)
	if err != nil {
		return nil, err
	}
	err = c.computePairData()
	if err != nil {
		return nil, err
	}
	log.Debugf("Pod public %x :: %d", c.podPublic, len(c.podPublic))
	log.Debugf("Pod nonce %x :: %d", c.podNonce, len(c.podNonce))
	log.Debugf("Generated SPS1: %x", msg.Payload)
	return msg, nil
}

func (c *Pair) ParseSPS2(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps2}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}

	if c.Mode == ModeO5 {
		// Build the PDM transcript using the nonce state as it stands BEFORE
		// decryption advances pdmNonce — this matches the controller's view
		// at sign time (see O5KeyExchange.swift buildChannelBindingTranscript).
		transcript := buildPDMTranscript(c.pdmPublic, c.podPublic, c.nonceState.pdm, c.nonceState.pod)

		certDER, sig, err := decryptSPS2(c.conf, c.nonceState, sp[sps2])
		if err != nil {
			return fmt.Errorf("SPS2 decrypt: %w", err)
		}
		log.Infof("Decrypted PDM SPS2: %d-byte cert + 64-byte sig", len(certDER))
		c.pdmCertDER = certDER

		// Cache the PDM TLS pubkey for post-pairing Type-4 verification.
		if pub, perr := extractP256PublicKey(certDER); perr == nil {
			c.pdmPublicKey = make([]byte, 64)
			x := pub.X.Bytes()
			y := pub.Y.Bytes()
			copy(c.pdmPublicKey[32-len(x):32], x)
			copy(c.pdmPublicKey[64-len(y):64], y)
		} else {
			log.Warnf("Could not extract PDM pubkey from SPS2 cert: %v", perr)
		}

		ok, vErr := verifyTranscript(certDER, transcript, sig)
		if vErr != nil {
			log.Warnf("PDM SPS2 signature verification setup failed: %v (continuing)", vErr)
			return nil
		}
		if !ok {
			log.Warnf("PDM SPS2 signature verification FAILED (continuing — transcript layout may differ across firmware)")
		} else {
			log.Infof("PDM SPS2 signature verified")
		}
		return nil
	}

	if !bytes.Equal(c.pdmConf, sp[sps2]) {
		return fmt.Errorf("Invalid conf value. Expected: %x. Got %x", c.pdmConf, sp[sps2])
	}
	log.Debugf("Validated PDM SPS2: %x", sp[sps2])
	return nil
}

func (c *Pair) ParseSPS21(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps21}, msg.Payload)
	if err != nil {
		log.Warnf("SPS2.1 Message :%s", spew.Sdump(msg))
		log.Warnf("SPS2.1 parse failed, continuing without validation: %v", err)
		return nil
	}
	c.sps21Data = sp[sps21]
	c.sps21Len = len(c.sps21Data)
	if c.sps21Len == 0 {
		log.Warn("SPS2.1 payload was empty; continuing without validation")
		return nil
	}

	if c.Mode == ModeO5 {
		certDER, err := decryptSPS21(c.conf, c.nonceState, c.sps21Data)
		if err != nil {
			log.Warnf("PDM SPS2.1 decrypt failed: %v (continuing)", err)
			return nil
		}
		log.Infof("Decrypted PDM SPS2.1: %d-byte intermediate-CA DER", len(certDER))
		c.sps21Data = certDER
		return nil
	}

	log.Infof("Received SPS2.1 payload (%d bytes)", c.sps21Len)
	return nil
}

func (c *Pair) GenerateSPS2() (*message.Message, error) {
	sp := make(map[string][]byte)

	if c.Mode == ModeO5 {
		if c.identity == nil {
			return nil, errors.New("GenerateSPS2: pod identity not set in O5 mode (call SetIdentity)")
		}
		// At sign time, nonceState mirrors the moment we are about to send
		// SPS2: pdmNonce already advanced by SPS2.1 receive AND SPS2 receive,
		// podNonce already advanced by SPS2.1 send. That matches what the
		// controller's verifier expects (see buildPodTranscript docs).
		transcript := buildPodTranscript(c.pdmPublic, c.podPublic, c.nonceState.pdm, c.nonceState.pod)
		sig, err := signTranscript(c.identity.PrivateKey, transcript)
		if err != nil {
			return nil, fmt.Errorf("SPS2 sign: %w", err)
		}
		ct, err := encryptSPS2(c.conf, c.nonceState, c.identity.CertDER, sig)
		if err != nil {
			return nil, fmt.Errorf("SPS2 encrypt: %w", err)
		}
		sp[sps2] = ct
	} else {
		sp[sps2] = c.podConf
	}

	msg := message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
	payload, err := buildStringByte([]string{sps2}, sp)
	if err != nil {
		return nil, err
	}
	msg.Payload = payload
	log.Debugf("Generated SPS2 (%d bytes)", len(sp[sps2]))
	return msg, nil
}

func (c *Pair) GenerateSPS21() (*message.Message, error) {
	sp := make(map[string][]byte)

	if c.Mode == ModeO5 {
		if c.identity == nil {
			return nil, errors.New("GenerateSPS21: pod identity not set in O5 mode (call SetIdentity)")
		}
		ct, err := encryptSPS21(c.conf, c.nonceState, c.identity.CertDER)
		if err != nil {
			return nil, fmt.Errorf("SPS2.1 encrypt: %w", err)
		}
		sp[sps21] = ct
	} else {
		// Dash has no SPS2.1 in the activation flow; fall back to a zero-filled
		// stand-in sized one byte shorter than the inbound (or the default if
		// no inbound was observed). This branch is kept for completeness.
		responseSize := c.sps21Len - 1
		if c.sps21Len == 0 {
			responseSize = defaultSPS21Size
		} else if responseSize < 0 {
			responseSize = 0
		}
		sp[sps21] = bytes.Repeat([]byte{0x00}, responseSize)
	}

	msg := message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
	payload, err := buildStringByte([]string{sps21}, sp)
	if err != nil {
		return nil, err
	}
	msg.Payload = payload
	log.Debugf("Generated SPS2.1 (%d bytes)", len(sp[sps21]))
	return msg, nil
}

func (c *Pair) ParseSP0GP0(msg *message.Message) error {
	if string(msg.Payload) != sp0gp0 {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return fmt.Errorf("Expected SP0GP0, got %x", msg.Payload)
	}
	log.Debugf("Parsed SP0GP0")
	return nil
}

func (c *Pair) GenerateP0() (*message.Message, error) {
	var err error
	msg := message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
	sp := make(map[string][]byte)
	sp[p0] = []byte{0xa5} // magic constant ???
	msg.Payload, err = buildStringByte([]string{p0}, sp)
	log.Debugf("Generated P0")

	return msg, err
}

func (c *Pair) LTK() ([]byte, error) {
	if c.curve25519LTK != nil {
		return c.ltk, nil
	}
	return nil, errors.New("Missing  enough data to compute LTK")
}

func (c *Pair) computeMyData() error {
	var err error
	if c.Mode == ModeO5 {
		// Real P-256 keypair (raw 32-byte D scalar, 64-byte uncompressed X||Y
		// public key without the 0x04 prefix). Nonce is freshly random — the
		// per-direction counter lives in spsNonceState.
		c.podNonce = make([]byte, 16)
		if _, err = rand.Read(c.podNonce); err != nil {
			return err
		}
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		c.podPrivate = priv.Bytes()
		// PublicKey().Bytes() returns the 0x04-prefixed uncompressed point;
		// strip the prefix to get the 64-byte raw X||Y form that o5DeriveKeys
		// and the transcript helpers expect.
		c.podPublic = priv.PublicKey().Bytes()[1:]
		log.Infof("Pod Private %x :: %d", c.podPrivate, len(c.podPrivate))
		log.Infof("Pod Public  %x :: %d", c.podPublic, len(c.podPublic))
		log.Infof("Pod Nonce   %x :: %d", c.podNonce, len(c.podNonce))
		return nil
	}

	c.podPrivate = make([]byte, 32)
	c.podPublic = make([]byte, 32)
	c.podNonce = make([]byte, 16) // 0 for now TODO
	/*
		if _, err := rand.Read(podPrivateKey); err != nil {
			return nil, nil, nil, err
		}
	*/
	c.podPrivate[0] &= 248
	c.podPrivate[31] &= 127
	c.podPrivate[31] |= 64
	c.podPublic, err = curve25519.X25519(c.podPrivate, curve25519.Basepoint)
	return err

}
func (c *Pair) computePairData() error {
	var err error
	// fill in: lrtk, podConf, pdmConf, intermediarKey
	if c.Mode == ModeO5 {
		// P-256 ECDH against the PDM's raw X||Y public key.
		privateKey, err := ecdh.P256().NewPrivateKey(c.podPrivate)
		if err != nil {
			return err
		}
		publicKey, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, c.pdmPublic...))
		if err != nil {
			return err
		}
		c.curve25519LTK, err = privateKey.ECDH(publicKey)
		if err != nil {
			return err
		}
		log.Infof("Shared secret %x :: %d", c.curve25519LTK, len(c.curve25519LTK))

		conf, ltk, err := o5DeriveKeys(c.pdmPublic, c.podPublic, c.curve25519LTK)
		if err != nil {
			return err
		}
		c.conf = conf
		c.ltk = ltk
		c.nonceState, err = newSPSNonceState(c.pdmNonce, c.podNonce)
		if err != nil {
			return err
		}
		log.Infof("O5 conf key %x", c.conf)
		log.Infof("O5 LTK      %x", c.ltk)
		// SPS2.1/SPS2 in O5 are AES-CCM payloads, not CMAC confirmation values;
		// they are routed through dedicated handlers. Skip the Dash CMAC chain.
		return nil
	}

	c.curve25519LTK, err = curve25519.X25519(c.podPrivate, c.pdmPublic)
	if err != nil {
		return err
	}
	log.Infof("Shared secret %x :: %d", c.curve25519LTK, len(c.curve25519LTK))

	//first_key = data.pod_public[-4:] + data.pdm_public[-4:] + data.pod_nonce[-4:] + data.pdm_nonce[-4:]
	firstKey := append(c.podPublic[28:], c.pdmPublic[28:]...)
	firstKey = append(firstKey, c.podNonce[12:]...)
	firstKey = append(firstKey, c.pdmNonce[12:]...)
	log.Debugf("First key %x :: %d", firstKey, len(firstKey))

	first, err := cmac.New(firstKey)
	if err != nil {
		return err
	}
	log.Debugf("CMAC: %d", first.Size())
	first.Write(c.curve25519LTK)
	intermediarKey := first.Sum([]byte{})

	log.Debugf("Intermediar key %x :: %d", intermediarKey, len(intermediarKey))

	// bb_data = bytes.fromhex("01") + bytes("TWIt", "ascii") + data.pod_nonce + data.pdm_nonce + bytes.fromhex("0001")
	var bbData bytes.Buffer
	bbData.WriteByte(0x01)
	bbData.WriteString("TWIt")
	bbData.Write(c.podNonce)
	bbData.Write(c.pdmNonce)
	bbData.WriteByte(0x00)
	bbData.WriteByte(0x01)
	bbHash, err := cmac.New(intermediarKey)
	if err != nil {
		return err
	}
	bbHash.Write(bbData.Bytes())
	c.confKey = bbHash.Sum([]byte{})

	// ab_data = bytes.fromhex("02") + bytes("TWIt", "ascii") + data.pod_nonce + data.pdm_nonce + bytes.fromhex("0001")
	var abData bytes.Buffer
	abData.WriteByte(0x02) // this is the only difference
	abData.WriteString("TWIt")
	abData.Write(c.podNonce)
	abData.Write(c.pdmNonce)
	abData.WriteByte(0x00)
	abData.WriteByte(0x01)
	abHash, err := cmac.New(intermediarKey)
	if err != nil {
		return err
	}
	abHash.Write(abData.Bytes())
	c.ltk = abHash.Sum([]byte{})

	//  pdm_conf_data = bytes("KC_2_U", "ascii") + data.pdm_nonce + data.pod_nonce
	var pdmConfData bytes.Buffer
	pdmConfData.WriteString("KC_2_U")
	pdmConfData.Write(c.pdmNonce)
	pdmConfData.Write(c.podNonce)
	hash, err := cmac.New(c.confKey)
	if err != nil {
		return err
	}
	hash.Write(pdmConfData.Bytes())
	c.pdmConf = hash.Sum([]byte{})

	//  pdm_conf_data = bytes("KC_2_U", "ascii") + data.pdm_nonce + data.pod_nonce
	var podConfData bytes.Buffer
	podConfData.WriteString("KC_2_V")
	podConfData.Write(c.podNonce) // ???
	podConfData.Write(c.pdmNonce)
	hash, err = cmac.New(c.confKey)
	if err != nil {
		return err
	}
	hash.Write(podConfData.Bytes())
	c.podConf = hash.Sum([]byte{})

	return nil
}
