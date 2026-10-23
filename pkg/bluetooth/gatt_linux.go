package bluetooth

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/paypal/gatt"
	"github.com/paypal/gatt/linux/cmd"
	log "github.com/sirupsen/logrus"
)

// gattRadio serves the pod from a Linux Bluetooth adapter.
type gattRadio struct {
	ble     *Ble
	device  gatt.Device
	central gatt.Central

	advertMtx sync.Mutex
	id        []byte
	state     AdvertState

	cmdNotifier    gatt.Notifier
	cmdNotifierMtx sync.Mutex

	dataNotifier    gatt.Notifier
	dataNotifierMtx sync.Mutex

	mtuMtx sync.Mutex
	mtu    int // the ATT MTU last reported for this connection
}

var DefaultServerOptions = []gatt.Option{
	gatt.LnxMaxConnections(1),
	gatt.LnxDeviceID(-1, true),
	gatt.LnxSetAdvertisingParameters(&cmd.LESetAdvertisingParameters{
		AdvertisingIntervalMin: 0x00f4,
		AdvertisingIntervalMax: 0x00f4,
		AdvertisingChannelMap:  0x7,
	}),
}

// NewGattRadio serves the pod from the first Bluetooth adapter, advertising
// id (see Radio.Advertise).
func NewGattRadio(b *Ble, id []byte) (Radio, error) {
	d, err := gatt.NewDevice(DefaultServerOptions...)
	if err != nil {
		log.Fatalf("pkg bluetooth; failed to open device, err: %s", err)
	}
	r := &gattRadio{ble: b, device: d, id: id}

	d.Handle(
		gatt.CentralConnected(func(c gatt.Central) {
			fmt.Println("pkg bluetooth; ** New connection from: ", c.ID())
			r.central = c
			r.mtuMtx.Lock()
			r.mtu = 0
			r.mtuMtx.Unlock()
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
			s := gatt.NewService(gatt.MustParseUUID(podServiceUUID))

			cmdCharacteristic := s.AddCharacteristic(gatt.MustParseUUID(cmdCharUUID))
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

			dataCharacteristic := s.AddCharacteristic(gatt.MustParseUUID(DataCharUUID(b.Mode())))
			dataCharacteristic.HandleNotifyFunc(
				func(req gatt.Request, n gatt.Notifier) {
					r.dataNotifierMtx.Lock()
					r.dataNotifier = n
					r.dataNotifierMtx.Unlock()
					log.Infof("pkg bluetooth; handling DATA notifications on new connection from: %s", req.Central.ID())
					r.reportMTU(req.Central)
					log.Infof("     *** OK to send commands from the phone app ***")
				})

			dataCharacteristic.HandleWriteFunc(
				func(req gatt.Request, data []byte) (status byte) {
					log.Tracef("pkg bluetooth; received DATA,%x, -- %d", data, len(data))
					r.reportMTU(req.Central)
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

// reportMTU logs the ATT MTU the phone negotiated when it changes on this
// connection. The phone proposes it and paypal/gatt accepts up to 256, so
// the pod cannot raise it; an Omnipod 5 needs 247 for its 244-byte packets,
// and below that the phone's longer messages never arrive whole.
func (r *gattRadio) reportMTU(c gatt.Central) {
	mtu := c.MTU()
	r.mtuMtx.Lock()
	changed := mtu != r.mtu
	r.mtu = mtu
	r.mtuMtx.Unlock()
	if !changed {
		return
	}
	if need := r.ble.MinMTU(); mtu < need {
		log.Warnf("pkg bluetooth; the phone negotiated an ATT MTU of %d, but an %s pod's packets need %d: messages longer than one packet will not get through",
			mtu, r.ble.Mode().Describe(), need)
		return
	}
	log.Infof("pkg bluetooth; the phone negotiated an ATT MTU of %d", mtu)
}

func (r *gattRadio) advertise() error {
	r.advertMtx.Lock()
	id, state := r.id, r.state
	r.advertMtx.Unlock()
	m := r.ble.Mode()
	var uuids []gatt.UUID
	for _, u := range AdvertisedServices(m, id, state) {
		uuids = append(uuids, gatt.MustParseUUID(u.String()))
	}
	if m.IsO5() {
		// The 128-bit UUID and the manufacturer data fit the 31 bytes; the
		// name goes in the scan response.
		return r.device.AdvertiseNameServicesMfgData(AdvertisedName(m, id), uuids, ManufacturerData(m, state))
	}
	// A DASH pod's nine UUIDs fill the packet; paypal/gatt advertises no
	// manufacturer data for it.
	return r.device.AdvertiseNameAndServices(AdvertisedName(m, id), uuids)
}

// Advertise updates the advertisement; paypal/gatt needs no StopAdvertising first.
func (r *gattRadio) Advertise(id []byte) error {
	r.advertMtx.Lock()
	r.id = id
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
