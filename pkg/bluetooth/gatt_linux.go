package bluetooth

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/paypal/gatt"
	"github.com/paypal/gatt/linux/cmd"
	log "github.com/sirupsen/logrus"
)

// gattRadio serves the pod from a Linux Bluetooth adapter.
type gattRadio struct {
	device  gatt.Device
	central gatt.Central
	profile Profile

	advertMtx sync.Mutex
	podId     []byte
	pdmId     uint32 // the controller an Omnipod 5 advertises once paired
	state     AdvertState

	cmdNotifier    gatt.Notifier
	cmdNotifierMtx sync.Mutex

	dataNotifier    gatt.Notifier
	dataNotifierMtx sync.Mutex

	mtuMtx  sync.Mutex
	linkMTU int // what reportMTU saw the phone settle on; 0 until it has
}

// ServerOptions is how the pod serves itself from adapter hci<n>, or from
// the first one with LE support when n is negative.
func ServerOptions(hci int) []gatt.Option {
	return []gatt.Option{
		gatt.LnxMaxConnections(1),
		gatt.LnxDeviceID(hci, true),
		gatt.LnxSetAdvertisingParameters(&cmd.LESetAdvertisingParameters{
			AdvertisingIntervalMin: 0x00f4,
			AdvertisingIntervalMax: 0x00f4,
			AdvertisingChannelMap:  0x7,
		}),
	}
}

// NewGattRadio serves the pod from Bluetooth adapter hci<hci>, or from the
// first one with LE support when hci is negative. Which adapter matters:
// an Omnipod 5 needs a 247-byte ATT MTU, which a phone asks for only of a
// Bluetooth 4.2 or later radio, so a Pi 3B's own 4.1 radio will not do and
// a dongle has to be named here rather than left to chance.
func NewGattRadio(b *Ble, podId []byte, hci int) (Radio, error) {
	d, err := gatt.NewDevice(ServerOptions(hci)...)
	if err != nil {
		log.Fatalf("pkg bluetooth; failed to open device, err: %s", err)
	}
	r := &gattRadio{device: d, profile: b.profile, podId: podId}

	d.Handle(
		gatt.CentralConnected(func(c gatt.Central) {
			fmt.Println("pkg bluetooth; ** New connection from: ", c.ID())
			r.central = c
			// The phone drives the ATT MTU exchange and the pod answers with
			// its own maximum; record what they settled on, since an Omnipod 5
			// packet needs 247 and a smaller one truncates pairing.
			r.setLinkMTU(0)
			go r.reportMTU(c)
			b.Connected()
		}),
		gatt.CentralDisconnected(func(c gatt.Central) {
			log.Tracef("pkg bluetooth; ** disconnect: %s", c.ID())
			b.Disconnected()
		}),
	)

	// A mandatory handler for monitoring device state.
	onStateChanged := func(d gatt.Device, s gatt.State) {
		fmt.Printf("state: %s\n", s)
		switch s {
		case gatt.StatePoweredOn:
			var serviceUUID = gatt.MustParseUUID(r.profile.ServiceUUID)
			var cmdCharUUID = gatt.MustParseUUID(r.profile.CmdCharUUID)
			var dataCharUUID = gatt.MustParseUUID(r.profile.DataCharUUID)

			s := gatt.NewService(serviceUUID)

			cmdCharacteristic := s.AddCharacteristic(cmdCharUUID)
			cmdCharacteristic.HandleWriteFunc(
				func(r gatt.Request, data []byte) (status byte) {
					log.Tracef("received CMD,  %x", data)
					b.CmdWritten(data)
					return 0
				})

			cmdCharacteristic.HandleNotifyFunc(
				func(req gatt.Request, n gatt.Notifier) {
					r.cmdNotifierMtx.Lock()
					r.cmdNotifier = n
					r.cmdNotifierMtx.Unlock()
					log.Infof("pkg bluetooth; handling CMD notifications on new connection from:  %s", req.Central.ID())
				})

			dataCharacteristic := s.AddCharacteristic(dataCharUUID)
			dataCharacteristic.HandleNotifyFunc(
				func(req gatt.Request, n gatt.Notifier) {
					r.dataNotifierMtx.Lock()
					r.dataNotifier = n
					r.dataNotifierMtx.Unlock()
					log.Infof("pkg bluetooth; handling DATA notifications on new connection from: %s", req.Central.ID())
					log.Infof("     *** OK to send commands from the phone app ***")
				})

			dataCharacteristic.HandleWriteFunc(
				func(r gatt.Request, data []byte) (status byte) {
					log.Tracef("pkg bluetooth; received DATA,%x, -- %d", data, len(data))
					b.DataWritten(data)
					return 0
				})

			err = d.AddService(s)
			if err != nil {
				log.Fatalf("pkg bluetooth; could not add service: %s", err)
			}

			if err := r.advertise(); err != nil {
				log.Fatalf("pkg bluetooth; could not advertise: %s", err)
			}
		default:
		}
	}
	err = d.Init(onStateChanged)
	if err != nil {
		log.Fatalf("pkg bluetooth; could not init bluetooth: %s", err)
	}
	return r, nil
}

func (r *gattRadio) advertise() error {
	r.advertMtx.Lock()
	podId, pdmId, state := r.podId, r.pdmId, r.state
	r.advertMtx.Unlock()

	// paypal/gatt advertises no manufacturer data. A DASH advertises nine
	// 16-bit service UUIDs; an Omnipod 5 advertises one 128-bit UUID, which
	// fills the packet, so its name goes in the scan response.
	var uuids []gatt.UUID
	for _, s := range r.profile.AdvertisedServiceUUIDs(podId, pdmId, state) {
		u, err := gatt.ParseUUID(s)
		if err != nil {
			return fmt.Errorf("could not parse the advertised UUID %s: %w", s, err)
		}
		uuids = append(uuids, u)
	}
	return r.device.AdvertiseNameAndServices(r.profile.AdvertisedName(pdmId), uuids)
}

// reportMTU records and logs the ATT MTU once the phone has negotiated one.
// gatt starts a connection at the 23-byte default and raises it when the
// phone asks, so this waits briefly for the exchange. A link too small to
// carry a packet only fails later, when the pod refuses to pair over it,
// so say so here too: this is the first moment it is knowable.
func (r *gattRadio) reportMTU(c gatt.Central) {
	needed := r.profile.Layout.MaxPayloadSize + 3 // the 3-byte ATT write header
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		mtu := c.MTU()
		if mtu <= 23 {
			continue
		}
		r.setLinkMTU(mtu)
		if mtu < needed {
			log.Errorf("pkg bluetooth; the phone negotiated an ATT MTU of %d, below the %d an %s packet needs; the pod will refuse to pair over it", mtu, needed, r.profile.Mode.Description())
		} else {
			log.Infof("pkg bluetooth; the phone negotiated an ATT MTU of %d", mtu)
		}
		return
	}
	r.setLinkMTU(c.MTU())
	log.Warnf("pkg bluetooth; the phone never raised the ATT MTU above the 23-byte default")
}

func (r *gattRadio) setLinkMTU(mtu int) {
	r.mtuMtx.Lock()
	r.linkMTU = mtu
	r.mtuMtx.Unlock()
}

// LinkMTU is what the phone negotiated, or 0 before it has.
func (r *gattRadio) LinkMTU() int {
	r.mtuMtx.Lock()
	defer r.mtuMtx.Unlock()
	return r.linkMTU
}

// Advertise updates the advertisement; paypal/gatt needs no StopAdvertising first.
func (r *gattRadio) Advertise(podId []byte, pdmId uint32) error {
	r.advertMtx.Lock()
	r.podId = podId
	if pdmId != 0 {
		r.pdmId = pdmId
	}
	r.advertMtx.Unlock()
	err := r.advertise()
	if err != nil {
		log.Infof("pkg bluetooth; could not re-advertise: %s", err)
	}
	return err
}

func (r *gattRadio) AdvertiseState(state AdvertState) error {
	r.advertMtx.Lock()
	changed := r.state != state
	r.state = state
	r.advertMtx.Unlock()
	if !changed {
		return nil
	}
	err := r.advertise()
	if err != nil {
		log.Infof("pkg bluetooth; could not re-advertise: %s", err)
	}
	return err
}

func (r *gattRadio) NotifyCmd(packet Packet) error {
	r.cmdNotifierMtx.Lock()
	defer r.cmdNotifierMtx.Unlock()
	if r.cmdNotifier.Done() {
		log.Fatalf("pkg bluetooth; CMD closed")
	}
	ret, err := r.cmdNotifier.Write(packet)
	log.Tracef("pkg bluetooth; CMD notification return: %d/%s", ret, hex.EncodeToString(packet))
	if err != nil {
		log.Fatalf("pkg bluetooth; error writing CMD: %s", err)
	}
	return nil
}

func (r *gattRadio) NotifyData(packet Packet) error {
	r.dataNotifierMtx.Lock()
	defer r.dataNotifierMtx.Unlock()
	if r.dataNotifier.Done() {
		log.Fatalf("pkg bluetooth; DATA closed")
	}
	ret, err := r.dataNotifier.Write(packet)
	log.Tracef("pkg bluetooth; DATA notification return: %d/%s", ret, hex.EncodeToString(packet))
	if err != nil {
		log.Fatalf("pkg bluetooth; error writing DATA: %s ", err)
	}
	return nil
}

func (r *gattRadio) Disconnect() {
	r.central.Close()
}
