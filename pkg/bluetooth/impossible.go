package bluetooth

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// simRadio serves the pod to an app in the iOS Simulator through ImpossiBLE
// (github.com/mickeyl/ImpossiBLE) instead of a Bluetooth adapter. The app
// links ImpossiBLE, whose CoreBluetooth shims speak newline-delimited JSON
// over a Unix socket; the pod takes the provider's end of that socket, in
// place of ImpossiBLE's menu bar app. Like that app it serves one client, and
// a new connection takes over from the old one.
type simRadio struct {
	ble *Ble
	id  string // the peripheral identifier the app sees

	mu           sync.Mutex
	client       *simClient
	scanning     bool
	connected    bool
	advertisedID []byte // see Radio.Advertise
	state        AdvertState
	notifying    map[string]bool // characteristic ids
	delayed      *time.Timer     // a connect held for its start delay
}

type simClient struct {
	conn   net.Conn
	bundle string
	mu     sync.Mutex
	closed bool
}

func (c *simClient) send(msg map[string]interface{}) {
	b, err := json.Marshal(msg)
	if err != nil {
		log.Warnf("pkg bluetooth; simulator: encoding %v: %v", msg["type"], err)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Write(append(b, '\n')); err != nil {
		log.Warnf("pkg bluetooth; simulator: send %v: %v", msg["type"], err)
	}
}

func (c *simClient) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.conn.Close()
}

const (
	propWriteNoResponse = 0x04
	propWrite           = 0x08
	propNotify          = 0x10
)

// dataCharUUID is the data characteristic of the pod this radio serves.
func (r *simRadio) dataCharUUID() string { return DataCharUUID(r.ble.Mode()) }

// NewSimRadio serves the pod on ImpossiBLE's socket at path, as the
// peripheral with identifier id, advertising advertisedID (see
// Radio.Advertise). ImpossiBLE tells the app it may write 512 bytes at a
// time, so an Omnipod 5's 244-byte packets need no MTU exchange.
func NewSimRadio(b *Ble, path, id string, advertisedID []byte) (Radio, error) {
	// A live provider (ImpossiBLE's app, g7sim, another pod) answers on the
	// socket; a stale file from one that died does not.
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return nil, fmt.Errorf("%s is served by another provider; quit it (ImpossiBLE's menu bar app?) first", path)
	}
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	r := &simRadio{ble: b, id: id, advertisedID: advertisedID, notifying: map[string]bool{}}
	log.Infof("pkg bluetooth; serving the iOS Simulator on %s as peripheral %s", path, id)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Fatalf("pkg bluetooth; simulator: accept: %v", err)
			}
			go r.serve(&simClient{conn: conn})
		}
	}()
	return r, nil
}

func (r *simRadio) serve(c *simClient) {
	sc := bufio.NewScanner(c.conn)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var msg map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
			log.Warnf("pkg bluetooth; simulator: bad message: %v", err)
			continue
		}
		r.handle(c, msg)
	}
	r.dropClient(c)
}

// dropClient forgets an app that went away; its connection ends with it.
func (r *simRadio) dropClient(c *simClient) {
	r.mu.Lock()
	wasConnected := false
	if r.client == c {
		r.client = nil
		r.scanning = false
		r.stopDelayedConnect()
		wasConnected = r.connected
		r.connected = false
	}
	r.mu.Unlock()
	if wasConnected {
		log.Infof("pkg bluetooth; simulator: %s went away", c.bundle)
		r.ble.Disconnected()
	}
	c.close()
}

func str(msg map[string]interface{}, key string) string {
	s, _ := msg[key].(string)
	return s
}

func (r *simRadio) current(c *simClient) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.client == c
}

func startDelay(msg map[string]interface{}) time.Duration {
	options, _ := msg["options"].(map[string]interface{})
	seconds, _ := options["kCBConnectOptionStartDelay"].(float64)
	return time.Duration(seconds * float64(time.Second))
}

func (r *simRadio) stopDelayedConnect() {
	if r.delayed != nil {
		r.delayed.Stop()
		r.delayed = nil
	}
}

// connect completes the app's connect; the pod is always connectable.
func (r *simRadio) connect(c *simClient) {
	r.mu.Lock()
	if r.client != c {
		r.mu.Unlock()
		return
	}
	r.delayed = nil
	already := r.connected
	if !already {
		r.connected = true
		r.notifying = map[string]bool{}
	}
	r.mu.Unlock()
	if !already {
		log.Infof("pkg bluetooth; ** New connection from: %s", c.bundle)
		r.ble.Connected()
	}
	c.send(map[string]interface{}{"type": "didConnect", "id": r.id})
}

func (r *simRadio) serviceID() string { return r.id + ":" + podServiceUUID }

func (r *simRadio) charID(uuid string) string { return r.serviceID() + ":" + uuid }

func (r *simRadio) handle(c *simClient, msg map[string]interface{}) {
	t := str(msg, "type")
	if t == "hello" {
		c.bundle = str(msg, "bundleId")
		log.Infof("pkg bluetooth; simulator: %s (ImpossiBLE %s, pid %v) connected", c.bundle, str(msg, "clientVersion"), msg["pid"])
		r.mu.Lock()
		old := r.client
		r.client = c
		r.mu.Unlock()
		if old != nil {
			log.Infof("pkg bluetooth; simulator: a new app connected; dropping the previous one")
			old.send(map[string]interface{}{"type": "connectionRejected", "code": "clientBusy",
				"message": "another app connected to the pod simulator"})
			r.dropClient(old)
		}
		return
	}
	if !r.current(c) {
		return
	}
	id := str(msg, "id")
	switch t {
	case "scan":
		r.mu.Lock()
		r.scanning = true
		r.mu.Unlock()
		r.discovered()
	case "stopScan":
		r.mu.Lock()
		r.scanning = false
		r.mu.Unlock()
	case "connect":
		if id != r.id {
			c.send(map[string]interface{}{"type": "didFailConnect", "id": id, "error": "unknown peripheral"})
			return
		}
		r.mu.Lock()
		r.stopDelayedConnect()
		if delay := startDelay(msg); delay > 0 && !r.connected {
			// iOS holds the request this long before it starts to connect.
			log.Infof("pkg bluetooth; holding the app's connect for its %v start delay", delay)
			r.delayed = time.AfterFunc(delay, func() { r.connect(c) })
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()
		r.connect(c)
	case "cancel":
		r.mu.Lock()
		r.stopDelayedConnect()
		r.mu.Unlock()
		r.disconnect(c, "app")
	case "discoverServices":
		c.send(map[string]interface{}{"type": "didDiscoverServices", "id": id, "error": "",
			"services": []map[string]interface{}{{"id": r.serviceID(), "uuid": podServiceUUID, "primary": true}}})
	case "discoverCharacteristics":
		serviceID := str(msg, "serviceId")
		chars := []map[string]interface{}{}
		if serviceID == r.serviceID() {
			for _, u := range []string{cmdCharUUID, r.dataCharUUID()} {
				chars = append(chars, map[string]interface{}{"id": r.charID(u), "uuid": u,
					"properties": propWrite | propWriteNoResponse | propNotify})
			}
		}
		c.send(map[string]interface{}{"type": "didDiscoverCharacteristics", "id": id,
			"serviceId": serviceID, "characteristics": chars, "error": ""})
	case "discoverDescriptors":
		c.send(map[string]interface{}{"type": "didDiscoverDescriptors", "id": id,
			"characteristicId": str(msg, "characteristicId"), "descriptors": []interface{}{}, "error": ""})
	case "discoverIncludedServices":
		c.send(map[string]interface{}{"type": "didDiscoverIncludedServices", "id": id,
			"serviceId": str(msg, "serviceId"), "includedServices": []interface{}{}, "error": ""})
	case "read":
		c.send(map[string]interface{}{"type": "didUpdateValue", "id": id,
			"characteristicId": str(msg, "characteristicId"), "value": "", "error": ""})
	case "write":
		r.write(c, msg)
	case "setNotify":
		r.setNotify(c, msg)
	case "readRSSI":
		c.send(map[string]interface{}{"type": "didReadRSSI", "id": id, "rssi": -60, "error": ""})
	case "registerForConnectionEvents", "clearMockConfiguration":
	case "setMockConfiguration":
		c.send(map[string]interface{}{"type": "didSetMockConfiguration", "ok": false,
			"error": "the pod simulator serves its own pod and takes no mock configuration"})
	case "openL2CAP":
		c.send(map[string]interface{}{"type": "didOpenL2CAP", "id": id, "channelId": "", "psm": msg["psm"],
			"error": "the pod has no L2CAP channels"})
	default:
		log.Debugf("pkg bluetooth; simulator: ignoring %s", t)
	}
}

// discovered reports the advertisement to a scanning app while the pod is
// advertising, which it does whenever it has no connection.
func (r *simRadio) discovered() {
	r.mu.Lock()
	c, scanning, connected, id, state := r.client, r.scanning, r.connected, r.advertisedID, r.state
	r.mu.Unlock()
	if c == nil || !scanning || connected {
		return
	}
	m := r.ble.Mode()
	var uuids []string
	for _, u := range AdvertisedServices(m, id, state) {
		uuids = append(uuids, u.String())
	}
	name := AdvertisedName(m, id)
	c.send(map[string]interface{}{"type": "didDiscover", "id": r.id, "name": name, "rssi": -60,
		"adv": map[string]interface{}{
			"kCBAdvDataLocalName":        name,
			"kCBAdvDataIsConnectable":    true,
			"kCBAdvDataServiceUUIDs":     uuids,
			"kCBAdvDataManufacturerData": base64.StdEncoding.EncodeToString(ManufacturerData(m, state)),
		}})
}

func (r *simRadio) write(c *simClient, msg map[string]interface{}) {
	id, charID := str(msg, "id"), str(msg, "characteristicId")
	data, err := base64.StdEncoding.DecodeString(str(msg, "value"))
	r.mu.Lock()
	connected := r.connected
	r.mu.Unlock()
	reply := map[string]interface{}{"type": "didWriteValue", "id": id, "characteristicId": charID, "error": ""}
	switch {
	case err != nil:
		reply["error"] = "bad value"
	case charID != r.charID(cmdCharUUID) && charID != r.charID(r.dataCharUUID()):
		reply["error"] = "unknown characteristic"
	case !connected:
		reply["error"] = "not connected"
	}
	if wt, _ := msg["writeType"].(float64); wt == 0 {
		c.send(reply)
	}
	if reply["error"] != "" {
		return
	}
	if charID == r.charID(cmdCharUUID) {
		log.Tracef("received CMD,  %x", data)
		r.ble.CmdWritten(data)
	} else {
		log.Tracef("pkg bluetooth; received DATA,%x, -- %d", data, len(data))
		r.ble.DataWritten(data)
	}
}

func (r *simRadio) setNotify(c *simClient, msg map[string]interface{}) {
	id, charID := str(msg, "id"), str(msg, "characteristicId")
	enabled, _ := msg["enabled"].(bool)
	if n, ok := msg["enabled"].(float64); ok {
		enabled = n != 0
	}
	reply := map[string]interface{}{"type": "didUpdateNotification", "id": id, "characteristicId": charID,
		"enabled": enabled, "error": ""}
	r.mu.Lock()
	switch {
	case charID != r.charID(cmdCharUUID) && charID != r.charID(r.dataCharUUID()):
		reply["error"] = "unknown characteristic"
	case !r.connected:
		reply["error"] = "not connected"
	default:
		r.notifying[charID] = enabled
	}
	r.mu.Unlock()
	if reply["error"] != "" {
		reply["enabled"] = false
	}
	c.send(reply)
	if enabled && charID == r.charID(r.dataCharUUID()) && reply["error"] == "" {
		log.Infof("     *** OK to send commands from the phone app ***")
	}
}

func (r *simRadio) notify(uuid string, packet Packet) error {
	charID := r.charID(uuid)
	r.mu.Lock()
	c, connected, subscribed := r.client, r.connected, r.notifying[charID]
	r.mu.Unlock()
	switch {
	case c == nil || !connected:
		return errors.New("not connected")
	case !subscribed:
		return errors.New("not subscribed")
	}
	c.send(map[string]interface{}{"type": "didUpdateValue", "id": r.id, "characteristicId": charID,
		"value": base64.StdEncoding.EncodeToString(packet), "error": ""})
	return nil
}

func (r *simRadio) NotifyCmd(packet Packet) error { return r.notify(cmdCharUUID, packet) }

func (r *simRadio) NotifyData(packet Packet) error { return r.notify(r.dataCharUUID(), packet) }

func (r *simRadio) Advertise(id []byte) error {
	r.mu.Lock()
	r.advertisedID = id
	r.mu.Unlock()
	r.discovered()
	return nil
}

func (r *simRadio) AdvertiseState(state AdvertState) error {
	r.mu.Lock()
	changed := r.state != state
	r.state = state
	r.mu.Unlock()
	if changed {
		r.discovered()
	}
	return nil
}

// Disconnect is the pod hanging up.
func (r *simRadio) Disconnect() {
	r.mu.Lock()
	c := r.client
	r.mu.Unlock()
	r.disconnect(c, "pod")
}

func (r *simRadio) disconnect(c *simClient, by string) {
	r.mu.Lock()
	was := r.connected && c != nil && r.client == c
	if was {
		r.connected = false
	}
	r.mu.Unlock()
	if c != nil {
		c.send(map[string]interface{}{"type": "didDisconnect", "id": r.id, "error": "",
			"timestamp": float64(time.Now().UnixNano())/1e9 - 978307200, "isReconnecting": false})
	}
	if was {
		log.Infof("pkg bluetooth; ** disconnected by the %s", by)
		r.ble.Disconnected()
		r.discovered()
	}
}

// PeripheralID makes a random identifier in the form iOS uses.
func PeripheralID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	x := strings.ToUpper(fmt.Sprintf("%x", b))
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}
