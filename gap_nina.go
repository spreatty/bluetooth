//go:build nina || nano_rp2040

package bluetooth

import (
	"errors"
	"time"
)

var (
	ErrConnect = errors.New("could not connect")
)

// Scan starts a BLE scan.
func (a *Adapter) Scan(callback func(*Adapter, ScanResult)) error {
	if a.scanning {
		return errScanning
	}

	if err := a.hci.leSetScanEnable(false, true); err != nil {
		return err
	}

	if err := a.hci.leSetScanParameters(0x01, 0x0020, 0x0020, 0x00, 0x00); err != nil {
		return err
	}

	a.scanning = true

	if err := a.hci.leSetScanEnable(true, false); err != nil {
		return err
	}

	for {
		if err := a.hci.poll(); err != nil {
			return err
		}

		switch {
		case a.hci.advData.reported:
			if a.hci.advData.typ != 0x04 {
				a.hci.clearAdvData()
				continue
			}

			adf := AdvertisementFields{}
			if a.hci.advData.eirLength > 64 {
				if _debug {
					println("eirLength too long")
				}

				a.hci.clearAdvData()
				continue
			}

			for i := 0; i < int(a.hci.advData.eirLength); {
				l, t := int(a.hci.advData.eirData[i]), a.hci.advData.eirData[i+1]
				if l < 1 {
					break
				}

				switch t {
				case 0x02, 0x03:
					// 16-bit Service Class UUID
				case 0x06, 0x07:
					// 128-bit Service Class UUID
				case 0x08, 0x09:
					if _debug {
						println("local name", string(a.hci.advData.eirData[i+2:i+2+l]))
					}

					adf.LocalName = string(a.hci.advData.eirData[i+2 : i+2+l])
				case 0xFF:
					// Manufacturer Specific Data
				}

				i += l + 1
			}

			callback(a, ScanResult{
				Address: Address{MACAddress{MAC: makeAddress(a.hci.advData.peerBdaddr)},
					a.hci.advData.peerBdaddrType},
				RSSI: int16(a.hci.advData.rssi),
				AdvertisementPayload: &advertisementFields{
					AdvertisementFields: adf,
				},
			})

			a.hci.clearAdvData()

		default:
			if !a.scanning {
				return nil
			}

			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil
}

func (a *Adapter) StopScan() error {
	if !a.scanning {
		return errNotScanning
	}

	if err := a.hci.leSetScanEnable(false, false); err != nil {
		return err
	}

	a.scanning = false

	return nil
}

// Address contains a Bluetooth MAC address.
type Address struct {
	MACAddress

	typ uint8
}

// Connect starts a connection attempt to the given peripheral device address.
func (a *Adapter) Connect(address Address, params ConnectionParams) (*Device, error) {
	if err := a.hci.leCreateConn(0x0060, 0x0030, 0x00,
		address.typ, makeNINAAddress(address.MAC),
		0x00, 0x0006, 0x000c, 0x0000, 0x00c8, 0x0004, 0x0006); err != nil {
		return nil, err
	}

	// are we connected?
	start := time.Now().UnixNano()
	for {
		if err := a.hci.poll(); err != nil {
			return nil, err
		}

		switch {
		case a.hci.connectData.connected:
			defer a.hci.clearConnectData()
			return &Device{adaptor: a,
				handle: a.hci.connectData.handle,
				Address: Address{MACAddress{MAC: makeAddress(a.hci.connectData.peerBdaddr)},
					a.hci.connectData.peerBdaddrType},
			}, nil

		default:
			// check for timeout
			if (time.Now().UnixNano()-start)/int64(time.Second) > 5 {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
	}

	if err := a.hci.leCancelConn(); err != nil {
		return nil, err
	}

	return nil, ErrConnect
}

// Device is a connection to a remote peripheral.
type Device struct {
	adaptor *Adapter
	Address Address
	handle  uint16
}

// Disconnect from the BLE device.
func (d *Device) Disconnect() error {
	return d.adaptor.hci.disconnect(d.handle)
}
