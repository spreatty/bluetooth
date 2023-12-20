//go:build nina || nano_rp2040

package bluetooth

import "time"

type leAdvertisingReport struct {
	status, typ, peerBdaddrType uint8
	peerBdaddr                  [6]uint8
	eirLength                   uint8
	eirData                     [31]uint8
	rssi                        int8
}

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
		case len(a.hci.advData) > 0:
			d := leAdvertisingReport{
				status:         a.hci.advData[0],
				typ:            a.hci.advData[1],
				peerBdaddrType: a.hci.advData[2],
				eirLength:      a.hci.advData[9],
			}
			copy(d.peerBdaddr[:], a.hci.advData[3:9])
			copy(d.eirData[:], a.hci.advData[10:10+d.eirLength+1])

			if d.status == 0x01 {
				d.rssi = int8(d.eirData[d.eirLength])
			}

			callback(a, ScanResult{
				Address: Address{MACAddress{MAC: makeAddress(d.peerBdaddr)}},
				RSSI:    int16(d.rssi),
				AdvertisementPayload: &advertisementFields{
					AdvertisementFields{},
				},
			})

			a.hci.advData = append(a.hci.advData[:0], a.hci.advData[:0]...)

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
}
