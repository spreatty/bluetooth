//go:build nina || nano_rp2040

package bluetooth

import (
	"encoding/binary"
	"errors"
	"machine"
	"time"
)

const (
	OGF_LINK_CTL     = 0x01
	OGF_HOST_CTL     = 0x03
	OGF_INFO_PARAM   = 0x04
	OGF_STATUS_PARAM = 0x05
	OGF_LE_CTL       = 0x08

	LE_COMMAND_ENCRYPT                      = 0x0017
	LE_COMMAND_RANDOM                       = 0x0018
	LE_COMMAND_LONG_TERM_KEY_REPLY          = 0x001A
	LE_COMMAND_LONG_TERM_KEY_NEGATIVE_REPLY = 0x001B
	LE_COMMAND_READ_LOCAL_P256              = 0x0025
	LE_COMMAND_GENERATE_DH_KEY_V1           = 0x0026
	LE_COMMAND_GENERATE_DH_KEY_V2           = 0x005E

	LE_META_EVENT_CONN_COMPLETE            = 0x01
	LE_META_EVENT_ADVERTISING_REPORT       = 0x02
	LE_META_EVENT_LONG_TERM_KEY_REQUEST    = 0x05
	LE_META_EVENT_REMOTE_CONN_PARAM_REQ    = 0x06
	LE_META_EVENT_READ_LOCAL_P256_COMPLETE = 0x08
	LE_META_EVENT_GENERATE_DH_KEY_COMPLETE = 0x09

	HCI_COMMAND_PKT  = 0x01
	HCI_ACLDATA_PKT  = 0x02
	HCI_EVENT_PKT    = 0x04
	HCI_SECURITY_PKT = 0x06

	EVT_DISCONN_COMPLETE  = 0x05
	EVT_ENCRYPTION_CHANGE = 0x08
	EVT_CMD_COMPLETE      = 0x0e
	EVT_CMD_STATUS        = 0x0f
	EVT_NUM_COMP_PKTS     = 0x13
	EVT_RETURN_LINK_KEYS  = 0x15
	EVT_UNKNOWN           = 0x10
	EVT_LE_META_EVENT     = 0x3e

	EVT_LE_CONN_COMPLETE      = 0x01
	EVT_LE_ADVERTISING_REPORT = 0x02

	// OGF_LINK_CTL
	OCF_DISCONNECT = 0x0006

	// OGF_HOST_CTL
	OCF_SET_EVENT_MASK = 0x0001
	OCF_RESET          = 0x0003

	// OGF_INFO_PARAM
	OCF_READ_LOCAL_VERSION = 0x0001
	OCF_READ_BD_ADDR       = 0x0009

	// OGF_STATUS_PARAM
	OCF_READ_RSSI = 0x0005

	// OGF_LE_CTL
	OCF_LE_READ_BUFFER_SIZE           = 0x0002
	OCF_LE_SET_RANDOM_ADDRESS         = 0x0005
	OCF_LE_SET_ADVERTISING_PARAMETERS = 0x0006
	OCF_LE_SET_ADVERTISING_DATA       = 0x0008
	OCF_LE_SET_SCAN_RESPONSE_DATA     = 0x0009
	OCF_LE_SET_ADVERTISE_ENABLE       = 0x000a
	OCF_LE_SET_SCAN_PARAMETERS        = 0x000b
	OCF_LE_SET_SCAN_ENABLE            = 0x000c
	OCF_LE_CREATE_CONN                = 0x000d
	OCF_LE_CANCEL_CONN                = 0x000e
	OCF_LE_CONN_UPDATE                = 0x0013

	HCI_OE_USER_ENDED_CONNECTION = 0x13
)

const (
	HCIACLHeaderLen = 5
	HCIEvtHeaderLen = 3
)

var (
	ErrHCITimeout      = errors.New("HCI timeout")
	ErrHCIUnknownEvent = errors.New("HCI unknown event")
	ErrHCIUnknown      = errors.New("HCI unknown error")
)

type hci struct {
	uart              *machine.UART
	buf               []byte
	address           [6]byte
	cmdCompleteOpcode uint16
	cmdCompleteStatus uint8
	cmdResponse       []byte
	scanning          bool
	advData           []byte
}

func newHCI(uart *machine.UART) *hci {
	return &hci{uart: uart,
		buf: make([]byte, 256),
	}
}

func (h *hci) start() error {
	return nil
}

func (h *hci) stop() error {
	return nil
}

func (h *hci) reset() error {
	return h.sendCommand(OGF_HOST_CTL<<10 | OCF_RESET)
}

func (h *hci) poll() error {
	i := byte(0)
	for h.uart.Buffered() > 0 {
		data, _ := h.uart.ReadByte()
		h.buf[i] = data
		i++

		switch h.buf[0] {
		case HCI_ACLDATA_PKT:
			if i > HCIACLHeaderLen &&
				i >= (HCIACLHeaderLen+(h.buf[3]+(h.buf[4]<<8))) {

				return h.handleACLData(h.buf[1:i])
			}

		case HCI_EVENT_PKT:
			if i > HCIEvtHeaderLen {
				if i >= (HCIEvtHeaderLen + h.buf[2]) {
					return h.handleEventData(h.buf[1:i])
				}
			}

		case 0xff:
			// leftovers in buffer, clear it
			i = 0
		default:
			println("unknown packet type:", h.buf[0])
			return ErrHCIUnknown
		}

		time.Sleep(1 * time.Millisecond)
	}

	return nil
}

func (h *hci) readBdAddr() error {
	if err := h.sendCommand(OGF_INFO_PARAM<<10 | OCF_READ_BD_ADDR); err != nil {
		return err
	}

	copy(h.address[:], h.cmdResponse[:7])

	return nil
}

func (h *hci) setEventMask(eventMask uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], eventMask)
	return h.sendCommandWithParams((OGF_HOST_CTL<<10)|OCF_SET_EVENT_MASK, b[:])
}

func (h *hci) setLeEventMask(eventMask uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], eventMask)
	return h.sendCommandWithParams(OGF_LE_CTL<<10|0x01, b[:])
}

func (h *hci) leSetScanEnable(enabled, duplicates bool) error {
	h.scanning = enabled

	var data [2]byte
	if enabled {
		data[0] = 1
	}
	if duplicates {
		data[1] = 1
	}

	return h.sendCommandWithParams(OGF_LE_CTL<<10|OCF_LE_SET_SCAN_ENABLE, data[:])
}

func (h *hci) leSetScanParameters(typ uint8, interval, window uint16, ownBdaddrType, filter uint8) error {
	var data [7]byte
	data[0] = typ
	data[1] = byte(interval & 0xff)
	data[2] = byte(interval >> 8)
	data[3] = byte(window & 0xff)
	data[4] = byte(window >> 8)
	data[5] = ownBdaddrType
	data[6] = filter

	return h.sendCommandWithParams(OGF_LE_CTL<<10|OCF_LE_SET_SCAN_PARAMETERS, data[:])
}

func (h *hci) leSetAdvertiseEnable(enabled bool) error {
	var data [1]byte
	if enabled {
		data[0] = 1
	}

	return h.sendCommandWithParams(OGF_LE_CTL<<10|OCF_LE_SET_ADVERTISE_ENABLE, data[:])
}

func (h *hci) sendCommand(opcode uint16) error {
	return h.sendCommandWithParams(opcode, []byte{})
}

func (h *hci) sendCommandWithParams(opcode uint16, params []byte) error {
	h.buf[0] = HCI_COMMAND_PKT
	h.buf[1] = byte(opcode & 0xff)
	h.buf[2] = byte(opcode >> 8)
	h.buf[3] = byte(len(params))
	copy(h.buf[4:], params)

	if _, err := h.uart.Write(h.buf[:4+len(params)]); err != nil {
		return err
	}

	h.cmdCompleteOpcode = 0xffff
	h.cmdCompleteStatus = 0xff

	start := time.Now().UnixNano()
	for h.cmdCompleteOpcode != opcode {
		if err := h.poll(); err != nil {
			return err
		}

		if (time.Now().UnixNano()-start)/int64(time.Second) > 3 {
			return ErrHCITimeout
		}
	}

	return nil
}

func (h *hci) handleACLData(buf []byte) error {
	return nil
}

func (h *hci) handleEventData(buf []byte) error {
	evt := buf[0]
	plen := buf[1]

	switch evt {
	case EVT_DISCONN_COMPLETE:
		// TODO: something with this data?
		// status := buf[2]
		// handle := buf[3] | (buf[4] << 8)
		// reason := buf[5]
		// ATT.removeConnection(disconnComplete->handle, disconnComplete->reason);
		// L2CAPSignaling.removeConnection(disconnComplete->handle, disconnComplete->reason);

		return h.leSetAdvertiseEnable(true)

	case EVT_ENCRYPTION_CHANGE:

	case EVT_CMD_COMPLETE:
		h.cmdCompleteOpcode = uint16(buf[3]) | (uint16(buf[4]) << 8)
		h.cmdCompleteStatus = buf[5]
		if plen > 0 {
			h.cmdResponse = buf[1 : plen+2]
		} else {
			h.cmdResponse = buf[:0]
		}

		return nil

	case EVT_CMD_STATUS:
		h.cmdCompleteOpcode = uint16(buf[4]) | uint16(buf[5]<<8)
		h.cmdCompleteStatus = buf[2]
		h.cmdResponse = buf[:0]

		return nil

	case EVT_NUM_COMP_PKTS:

	case EVT_LE_META_EVENT:
		switch buf[2] {
		case 0x0A:
			// EvtLeConnectionComplete

		case LE_META_EVENT_CONN_COMPLETE:

		case LE_META_EVENT_ADVERTISING_REPORT:
			h.advData = append(buf[:0:0], buf[3:plen+3]...)

			return nil

		case LE_META_EVENT_LONG_TERM_KEY_REQUEST:

		case LE_META_EVENT_REMOTE_CONN_PARAM_REQ:

		case LE_META_EVENT_READ_LOCAL_P256_COMPLETE:

		case LE_META_EVENT_GENERATE_DH_KEY_COMPLETE:

		default:
			// error unhandled metaevent
		}
	case EVT_UNKNOWN:
		return ErrHCIUnknownEvent
	}

	return nil
}
