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
	device  gatt.Device
	central gatt.Central

	cmdNotifier    gatt.Notifier
	cmdNotifierMtx sync.Mutex

	dataNotifier    gatt.Notifier
	dataNotifierMtx sync.Mutex
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

// NewGattRadio serves the pod from the first Bluetooth adapter.
func NewGattRadio(b *Ble, podId []byte) (Radio, error) {
	d, err := gatt.NewDevice(DefaultServerOptions...)
	if err != nil {
		log.Fatalf("pkg bluetooth; failed to open device, err: %s", err)
	}
	r := &gattRadio{device: d}

	d.Handle(
		gatt.CentralConnected(func(c gatt.Central) {
			fmt.Println("pkg bluetooth; ** New connection from: ", c.ID())
			r.central = c
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
			var serviceUUID = gatt.MustParseUUID("1a7e-4024-e3ed-4464-8b7e-751e03d0dc5f")
			var cmdCharUUID = gatt.MustParseUUID("1a7e-2441-e3ed-4464-8b7e-751e03d0dc5f")
			var dataCharUUID = gatt.MustParseUUID("1a7e-2442-e3ed-4464-8b7e-751e03d0dc5f")

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

			if err := r.advertise(podId); err != nil {
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

func (r *gattRadio) advertise(podId []byte) error {
	var uuids []gatt.UUID
	for _, u := range AdvertisedServices(podId) {
		uuids = append(uuids, gatt.UUID16(u))
	}
	return r.device.AdvertiseNameAndServices(AdvertisedName, uuids)
}

// Advertise updates the advertisement; paypal/gatt needs no StopAdvertising first.
func (r *gattRadio) Advertise(podId []byte) error {
	err := r.advertise(podId)
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
