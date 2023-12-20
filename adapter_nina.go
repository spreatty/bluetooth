//go:build nina || nano_rp2040

package bluetooth

import (
	"machine"

	"time"
)

// Adapter is a dummy adapter: it represents the connection to the NINA fw.
type Adapter struct {
	hci *hci

	isDefault bool
	scanning  bool

	connectHandler func(device Address, connected bool)
}

// DefaultAdapter is the default adapter on the current system.
//
// Make sure to call Enable() before using it to initialize the adapter.
var DefaultAdapter = &Adapter{isDefault: true,
	connectHandler: func(device Address, connected bool) {
		return
	}}

// Enable configures the BLE stack. It must be called before any
// Bluetooth-related calls (unless otherwise indicated).
func (a *Adapter) Enable() error {
	// reset the NINA in BLE mode
	machine.NINA_CS.Configure(machine.PinConfig{Mode: machine.PinOutput})
	machine.NINA_RESETN.Configure(machine.PinConfig{Mode: machine.PinOutput})
	machine.NINA_CS.Low()

	// inverted reset on arduino boards
	machine.NINA_RESETN.Low()
	time.Sleep(100 * time.Millisecond)
	machine.NINA_RESETN.High()
	time.Sleep(1000 * time.Millisecond)

	// serial port for nina chip
	uart := machine.UART1
	uart.Configure(machine.UARTConfig{
		TX:       machine.NINA_TX,
		RX:       machine.NINA_RX,
		BaudRate: 115200,
		CTS:      machine.NINA_CTS,
		RTS:      machine.NINA_RTS,
	})

	a.hci = newHCI(uart)
	a.hci.start()

	if err := a.hci.reset(); err != nil {
		return err
	}

	time.Sleep(150 * time.Millisecond)

	if err := a.hci.setEventMask(0x3FFFFFFFFFFFFFFF); err != nil {
		return err
	}

	if err := a.hci.setLeEventMask(0x00000000000003FF); err != nil {
		return err
	}

	return nil
}

func (a *Adapter) Address() (MACAddress, error) {
	if err := a.hci.readBdAddr(); err != nil {
		return MACAddress{}, err
	}

	return MACAddress{MAC: makeAddress(a.hci.address)}, nil
}

// Convert a NINA MAC address into a Go MAC address.
func makeAddress(mac [6]uint8) MAC {
	return MAC{
		uint8(mac[0]),
		uint8(mac[1]),
		uint8(mac[2]),
		uint8(mac[3]),
		uint8(mac[4]),
		uint8(mac[5]),
	}
}

// Convert a Go MAC address into a NINA MAC Address.
func makeNINAAddress(mac MAC) [6]uint8 {
	return [6]uint8{
		uint8(mac[0]),
		uint8(mac[1]),
		uint8(mac[2]),
		uint8(mac[3]),
		uint8(mac[4]),
		uint8(mac[5]),
	}
}
