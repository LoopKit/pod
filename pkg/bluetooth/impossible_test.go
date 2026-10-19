package bluetooth

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avereha/pod/pkg/mode"
)

type fakeApp struct {
	t    *testing.T
	conn net.Conn
	in   *bufio.Scanner
}

func (a *fakeApp) send(msg map[string]interface{}) {
	b, _ := json.Marshal(msg)
	if _, err := a.conn.Write(append(b, '\n')); err != nil {
		a.t.Fatal(err)
	}
}

func (a *fakeApp) expect(typ string) map[string]interface{} {
	a.t.Helper()
	a.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for a.in.Scan() {
		var msg map[string]interface{}
		if err := json.Unmarshal(a.in.Bytes(), &msg); err != nil {
			a.t.Fatal(err)
		}
		if msg["type"] == typ {
			return msg
		}
	}
	a.t.Fatalf("no %s: %v", typ, a.in.Err())
	return nil
}

func TestSimRadioPairsAndCarriesBothCharacteristics(t *testing.T) {
	// Unix socket paths are short; $TMPDIR on macOS is too long for one.
	dir, err := ioutil.TempDir("/tmp", "podsim")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "impossible.sock")
	const id = "11111111-2222-4333-8444-555555555555"
	b, err := New(mode.Dash, func(b *Ble) (Radio, error) { return NewSimRadio(b, path, id, nil) })
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	app := &fakeApp{t: t, conn: conn, in: bufio.NewScanner(conn)}

	app.send(map[string]interface{}{"type": "hello", "bundleId": "org.loopkit.Loop", "pid": 0})
	app.send(map[string]interface{}{"type": "scan"})
	adv := app.expect("didDiscover")["adv"].(map[string]interface{})
	uuids := adv["kCBAdvDataServiceUUIDs"].([]interface{})
	if len(uuids) != 9 || uuids[0] != "4024" || uuids[1] != "2470" || uuids[2] != "000A" || uuids[3] != "FFFF" || uuids[4] != "FFFE" {
		t.Fatalf("an unpaired pod advertises %v", uuids)
	}

	app.send(map[string]interface{}{"type": "connect", "id": id})
	app.expect("didConnect")
	if !b.IsConnected() {
		t.Fatal("not connected")
	}
	app.send(map[string]interface{}{"type": "discoverServices", "id": id})
	svc := app.expect("didDiscoverServices")["services"].([]interface{})[0].(map[string]interface{})
	app.send(map[string]interface{}{"type": "discoverCharacteristics", "id": id, "serviceId": svc["id"]})
	chars := app.expect("didDiscoverCharacteristics")["characteristics"].([]interface{})
	if len(chars) != 2 {
		t.Fatalf("characteristics %v", chars)
	}
	cmdChar := chars[0].(map[string]interface{})["id"]
	dataChar := chars[1].(map[string]interface{})["id"]

	// Before the app subscribes, the pod cannot notify.
	if err := b.radio.NotifyCmd(CmdCTS); err == nil {
		t.Fatal("notified an unsubscribed characteristic")
	}
	for _, c := range []interface{}{cmdChar, dataChar} {
		app.send(map[string]interface{}{"type": "setNotify", "id": id, "characteristicId": c, "enabled": true})
		if n := app.expect("didUpdateNotification"); n["enabled"] != true || n["error"] != "" {
			t.Fatalf("subscribing: %v", n)
		}
	}

	app.send(map[string]interface{}{"type": "write", "id": id, "characteristicId": cmdChar, "writeType": 0,
		"value": base64.StdEncoding.EncodeToString(CmdRTS)})
	app.expect("didWriteValue")
	if p, _ := b.ReadCmd(); string(p) != string(CmdRTS) {
		t.Fatalf("command characteristic carried %x", p)
	}
	app.send(map[string]interface{}{"type": "write", "id": id, "characteristicId": dataChar, "writeType": 1,
		"value": base64.StdEncoding.EncodeToString([]byte{0, 1, 2})})
	if p, _ := b.ReadData(); string(p) != "\x00\x01\x02" {
		t.Fatalf("data characteristic carried %x", p)
	}

	b.WriteCmd(CmdCTS)
	v := app.expect("didUpdateValue")
	if v["characteristicId"] != cmdChar || v["value"] != base64.StdEncoding.EncodeToString(CmdCTS) {
		t.Fatalf("pod notified %v", v)
	}

	// After pairing the pod advertises its new id; a hang-up tells the app
	// and the pod advertises again.
	if err := b.RefreshAdvertisingWithSpecifiedId([]byte{0x17, 0x0d, 0x2a, 0x40}); err != nil {
		t.Fatal(err)
	}
	b.ShutdownConnection()
	app.expect("didDisconnect")
	if b.IsConnected() {
		t.Fatal("still connected")
	}
	uuids = app.expect("didDiscover")["adv"].(map[string]interface{})["kCBAdvDataServiceUUIDs"].([]interface{})
	if uuids[1] != "C001" || uuids[3] != "170D" || uuids[4] != "2A40" {
		t.Fatalf("a paired pod advertises %v", uuids)
	}

	// A fault changes the advertisement, which wakes a suspended app.
	b.SetAdvertisedState(AdvertState{Fault: 0x14})
	adv = app.expect("didDiscover")["adv"].(map[string]interface{})
	uuids = adv["kCBAdvDataServiceUUIDs"].([]interface{})
	mfg, _ := base64.StdEncoding.DecodeString(adv["kCBAdvDataManufacturerData"].(string))
	if uuids[1] != "C00A" || len(mfg) < 8 || !bytes.Equal(mfg[len(mfg)-7:len(mfg)-3], []byte{0x00, 0x14, 0x14, 0x00}) {
		t.Fatalf("a pod with an occlusion advertises %v, %x", uuids, mfg)
	}
}

func TestSimRadioHoldsAConnectForItsStartDelay(t *testing.T) {
	dir, err := ioutil.TempDir("/tmp", "podsim")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "impossible.sock")
	const id = "11111111-2222-4333-8444-555555555555"
	b, err := New(mode.Dash, func(b *Ble) (Radio, error) { return NewSimRadio(b, path, id, nil) })
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	app := &fakeApp{t: t, conn: conn, in: bufio.NewScanner(conn)}
	app.send(map[string]interface{}{"type": "hello", "bundleId": "org.loopkit.Loop", "pid": 0})

	delayed := map[string]interface{}{"type": "connect", "id": id,
		"options": map[string]interface{}{"kCBConnectOptionStartDelay": 0.3}}
	app.send(delayed)
	time.Sleep(100 * time.Millisecond)
	if b.IsConnected() {
		t.Fatal("connected before the start delay")
	}
	app.expect("didConnect")
	if !b.IsConnected() {
		t.Fatal("not connected")
	}

	// A cancel during the delay withdraws the connect.
	app.send(map[string]interface{}{"type": "cancel", "id": id})
	app.expect("didDisconnect")
	app.send(delayed)
	app.send(map[string]interface{}{"type": "cancel", "id": id})
	app.expect("didDisconnect")
	time.Sleep(400 * time.Millisecond)
	if b.IsConnected() {
		t.Fatal("a cancelled connect completed")
	}
}
