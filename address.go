package godivert

import (
	"fmt"
)

// Represents a WinDivertAddress struct
//
// See : https://reqrypt.org/windivert-doc.html#divert_address
type WinDivertAddress struct {
	Timestamp int64
	Flags     uint64
	Data      [64]byte
}

func (w *WinDivertAddress) String() string {
	return fmt.Sprintf("{Timestamp: %d, Layer: %s, Event: %s, Direction: %s, Loopback: %v, IPv6: %v}\n",
		w.Timestamp, w.Layer(), w.Event(), w.Direction(), w.Loopback(), w.IPv6())
}

func (w *WinDivertAddress) UDPChecksumValid() bool {
	return w.Flags&0x08000000 > 0
}

func (w *WinDivertAddress) TCPChecksumValid() bool {
	return w.Flags&0x04000000 > 0
}

func (w *WinDivertAddress) IPChecksumValid() bool {
	return w.Flags&0x02000000 > 0
}

func (w *WinDivertAddress) IPv6() bool {
	return w.Flags&0x01000000 > 0
}

func (w *WinDivertAddress) Impostor() bool {
	return w.Flags&0x00800000 > 0
}

func (w *WinDivertAddress) Loopback() bool {
	return w.Flags&0x00400000 > 0
}

func (w *WinDivertAddress) Outbound() bool {
	return w.Flags&0x00200000 > 0
}

func (w *WinDivertAddress) Sniffed() bool {
	return w.Flags&0x00100000 > 0
}

func (w *WinDivertAddress) Event() Event {
	return Event(w.Flags & 0xff)
}

func (w *WinDivertAddress) Layer() Layer {
	return Layer((w.Flags >> 8) & 0xff)
}

// Direction returns the direction of the packet
func (w *WinDivertAddress) Direction() Direction {
	if w.Outbound() {
		return WinDivertDirectionOutbound
	}
	return WinDivertDirectionInbound
}
