
package bluetooth

import (
  "github.com/bettercap/gatt"
)

var DefaultServerOptions = []gatt.Option{
	gatt.MacDeviceRole(gatt.PeripheralManager),
}
