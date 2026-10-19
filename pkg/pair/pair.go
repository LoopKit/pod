package pair

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/mode"

	"github.com/davecgh/go-spew/spew"
	"github.com/jacobsa/crypto/cmac"
	log "github.com/sirupsen/logrus"
)

const (
	sp1 = "SP1="
	sp2 = ",SP2="

	sps0   = "SPS0="
	sps1   = "SPS1="
	sps21  = "SPS2.1="
	sps2   = "SPS2="
	sp0gp0 = "SP0,GP0"
	p0     = "P0="
)

// Pair is one pairing with a phone. A DASH pod exchanges Curve25519 keys
// and CMAC confirmations; an Omnipod 5 exchanges P-256 keys and then
// certificates and signatures under a key both derive (OmnipodKit
// DashLTKExchanger, O5LTKExchanger).
type Pair struct {
	Mode mode.Mode

	podPublic  []byte
	podPrivate []byte
	podNonce   []byte
	podConf    []byte

	pdmPublic []byte
	pdmNonce  []byte
	pdmConf   []byte

	// sharedSecret is the Curve25519 or P-256 ECDH result.
	sharedSecret []byte
	pdmID        []byte
	podID        []byte
	assignedID   []byte // the id SP1 gives the pod

	ltk     []byte
	confKey []byte // DASH: key used to sign the "Conf" values

	// Omnipod 5 only.
	conf         []byte // the SPS2.1/SPS2 AES-CCM key
	nonces       *spsNonces
	identity     *PodIdentity
	pdmCertDER   []byte
	pdmPublicKey []byte // from the phone's SPS2 certificate; signs type 4 commands
}

// SetIdentity gives an Omnipod 5 pod the key and certificate it pairs with.
func (c *Pair) SetIdentity(id *PodIdentity) { c.identity = id }

// ControllerID is the phone's id, from the first pairing message.
func (c *Pair) ControllerID() []byte { return c.pdmID }

// AssignedPodID is the id the phone gave the pod in SP1.
func (c *Pair) AssignedPodID() []byte { return c.assignedID }

// PDMPublicKey is the phone's signing key, from its SPS2 certificate, or
// nil for a DASH pairing.
func (c *Pair) PDMPublicKey() []byte { return c.pdmPublicKey }

func parseStringByte(expectedNames []string, data []byte) (map[string][]byte, error) {
	ret := make(map[string][]byte)
	for _, name := range expectedNames {
		n := len(name)
		if len(data) < n+2 || string(data[:n]) != name {
			return nil, fmt.Errorf("Name not found %s in %x", name, data)
		}
		data = data[n:]
		length := int(data[0])<<8 | int(data[1])
		if len(data) < 2+length {
			return nil, fmt.Errorf("Field %s is %d bytes, %d announced", name, len(data)-2, length)
		}
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

func (c *Pair) newMessage() *message.Message {
	return message.NewMessage(message.MessageTypePairing, c.podID, c.pdmID)
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
	if len(sp[sp1]) == 4 {
		c.assignedID = append([]byte(nil), sp[sp1]...)
	}
	return nil
}

// ParseSPS0 reads the phone's SPS0, which an Omnipod 5 phone sends after
// SP1/SP2 to agree on the algorithm.
func (c *Pair) ParseSPS0(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps0}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}
	if err := parseSPS0(sp[sps0], true); err != nil {
		return err
	}
	log.Infof("Received SPS0 %x", sp[sps0])
	return nil
}

func (c *Pair) GenerateSPS0() (*message.Message, error) {
	msg := c.newMessage()
	var err error
	msg.Payload, err = buildStringByte([]string{sps0}, map[string][]byte{sps0: sps0Payload(false)})
	log.Debugf("Generated SPS0: %x", msg.Payload)
	return msg, err
}

func (c *Pair) ParseSPS1(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps1}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}
	log.Infof("Received SPS1  %x", sp[sps1])
	publicSize := 32 // Curve25519
	if c.Mode.IsO5() {
		publicSize = o5PublicKeySize
	}
	if len(sp[sps1]) != publicSize+o5NonceSize {
		return fmt.Errorf("SPS1 payload is %d bytes, want %d", len(sp[sps1]), publicSize+o5NonceSize)
	}
	c.pdmPublic = append([]byte(nil), sp[sps1][:publicSize]...)
	c.pdmNonce = append([]byte(nil), sp[sps1][publicSize:]...)
	err = c.computeMyData()
	if err != nil {
		return err
	}
	if !c.Mode.IsO5() {
		c.sharedSecret, err = curve25519.X25519(c.podPrivate, c.pdmPublic)
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

	msg := c.newMessage()
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

// ParseSPS21 reads the phone's SPS2.1: its intermediate CA certificate,
// encrypted under conf. The pod only needs to decrypt it.
func (c *Pair) ParseSPS21(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps21}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}
	if c.nonces == nil {
		return errors.New("SPS2.1 before SPS1")
	}
	cert, err := c.nonces.open(c.conf, spsPhoneToPod, sp[sps21])
	if err != nil {
		return fmt.Errorf("could not decrypt SPS2.1: %w", err)
	}
	log.Infof("Received SPS2.1: a %d-byte certificate", len(cert))
	return nil
}

// GenerateSPS21 answers with the pod's certificate, encrypted under conf.
func (c *Pair) GenerateSPS21() (*message.Message, error) {
	if c.identity == nil || c.nonces == nil {
		return nil, errors.New("SPS2.1 needs the pod identity and SPS1")
	}
	ct, err := c.nonces.seal(c.conf, spsPodToPhone, c.identity.CertDER)
	if err != nil {
		return nil, err
	}
	msg := c.newMessage()
	msg.Payload, err = buildStringByte([]string{sps21}, map[string][]byte{sps21: ct})
	log.Debugf("Generated SPS2.1 (%d bytes)", len(ct))
	return msg, err
}

func (c *Pair) ParseSPS2(msg *message.Message) error {
	sp, err := parseStringByte([]string{sps2}, msg.Payload)
	if err != nil {
		log.Debugf("Message :%s", spew.Sdump(msg))
		return err
	}

	if c.Mode.IsO5() {
		return c.parseO5SPS2(sp[sps2])
	}

	if !bytes.Equal(c.pdmConf, sp[sps2]) {
		return fmt.Errorf("Invalid conf value. Expected: %x. Got %x", c.pdmConf, sp[sps2])
	}
	log.Debugf("Validated PDM SPS2: %x", sp[sps2])
	return nil
}

// parseO5SPS2 reads the phone's certificate and its signature over the
// transcript, which the phone built before this message advanced any
// counter. The phone keeps only the public key of the pod's certificate,
// so the pod does the same with the phone's; a signature that does not
// verify is reported but, as in OmnipodKit, does not end the pairing.
func (c *Pair) parseO5SPS2(ciphertext []byte) error {
	if c.nonces == nil {
		return errors.New("SPS2 before SPS1")
	}
	transcript := phoneTranscript(c.pdmPublic, c.podPublic, c.nonces.pdm, c.nonces.pod)
	plain, err := c.nonces.open(c.conf, spsPhoneToPod, ciphertext)
	if err != nil {
		return fmt.Errorf("could not decrypt SPS2: %w", err)
	}
	if len(plain) <= o5SignatureSize {
		return fmt.Errorf("SPS2 of %d bytes has no certificate", len(plain))
	}
	c.pdmCertDER = plain[:len(plain)-o5SignatureSize]
	signature := plain[len(plain)-o5SignatureSize:]
	log.Infof("Received SPS2: a %d-byte certificate and a signature", len(c.pdmCertDER))

	c.pdmPublicKey, err = PublicKeyFromCert(c.pdmCertDER)
	if err != nil {
		return fmt.Errorf("the phone's SPS2 certificate: %w", err)
	}
	ok, err := verifyRaw(c.pdmPublicKey, transcript, signature)
	switch {
	case err != nil:
		log.Warnf("Could not check the phone's SPS2 signature: %s", err)
	case !ok:
		log.Warnf("The phone's SPS2 signature does not verify against its certificate")
	default:
		log.Infof("The phone's SPS2 signature verifies")
	}
	return nil
}

func (c *Pair) GenerateSPS2() (*message.Message, error) {
	var err error
	sp := make(map[string][]byte)

	if c.Mode.IsO5() {
		if c.identity == nil || c.nonces == nil {
			return nil, errors.New("SPS2 needs the pod identity and SPS1")
		}
		transcript := podTranscript(c.pdmPublic, c.podPublic, c.nonces.pdm, c.nonces.pod)
		signature, err := signRaw(c.identity.Key, transcript)
		if err != nil {
			return nil, err
		}
		sp[sps2], err = c.nonces.seal(c.conf, spsPodToPhone, append(append([]byte(nil), c.identity.CertDER...), signature...))
		if err != nil {
			return nil, err
		}
	} else {
		sp[sps2] = c.podConf
	}

	msg := c.newMessage()
	msg.Payload, err = buildStringByte([]string{sps2}, sp)
	if err != nil {
		return nil, err
	}
	log.Debugf("Generated SPS2 (%d bytes)", len(sp[sps2]))
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
	msg := c.newMessage()
	sp := make(map[string][]byte)
	sp[p0] = []byte{0xa5} // magic constant ???
	msg.Payload, err = buildStringByte([]string{p0}, sp)
	log.Debugf("Generated P0")

	return msg, err
}

func (c *Pair) LTK() ([]byte, error) {
	if c.sharedSecret != nil {
		return c.ltk, nil
	}
	return nil, errors.New("Missing  enough data to compute LTK")
}

func (c *Pair) computeMyData() error {
	var err error
	if c.Mode.IsO5() {
		// A P-256 key for the key agreement and a random nonce, which the
		// SPS nonce counters start from.
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		c.podPrivate = key.Bytes()
		c.podPublic = key.PublicKey().Bytes()[1:] // drop the 04
		c.podNonce = make([]byte, o5NonceSize)
		_, err = rand.Read(c.podNonce)
		return err
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
	if c.Mode.IsO5() {
		c.sharedSecret, err = o5ECDH(c.podPrivate, c.pdmPublic)
		if err != nil {
			return err
		}
		c.conf, c.ltk, err = o5DeriveKeys(c.pdmPublic, c.podPublic, c.sharedSecret)
		if err != nil {
			return err
		}
		c.nonces, err = newSPSNonces(c.pdmNonce, c.podNonce)
		log.Debugf("O5 conf %x", c.conf)
		return err
	}

	// fill in: lrtk, podConf, pdmConf, intermediarKey
	c.sharedSecret, err = curve25519.X25519(c.podPrivate, c.pdmPublic)
	if err != nil {
		return err
	}
	log.Debugf("Donna LTK: %x", c.sharedSecret)
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
	first.Write(c.sharedSecret)
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
