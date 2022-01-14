package godivert

import "fmt"

type Direction int

func (d Direction) String() string {
	if d == WinDivertDirectionInbound {
		return "Inbound"
	}
	return "Outbound"
}

const (
	PacketBufferSize   = 1500
	PacketChanCapacity = 256

	WinDivertDirectionOutbound Direction = 1
	WinDivertDirectionInbound  Direction = 0
)

type OpenFlag uint8

const (
	OpenFlagNone        OpenFlag = 0x00
	OpenFlagSniff       OpenFlag = 0x01
	OpenFlagDrop        OpenFlag = 0x02
	OpenFlagReceiveOnly OpenFlag = 0x04
	OpenFlagSendOnly    OpenFlag = 0x08
	OpenFlagNoInstall   OpenFlag = 0x10
	OpenFlagFragments   OpenFlag = 0x20
)

type Layer int

const (
	// Network packets to/from the local machine.
	LayerNetwork Layer = iota
	// Network packets passing through the local machine.
	LayerForward
	// Network flow established/deleted events.
	LayerFlow
	// Socket operation events.
	LayerSocket
	// WinDivert handle events.
	LayerReflect
)

func (l Layer) String() string {
	switch l {
	case LayerNetwork:
		return "Network"
	case LayerForward:
		return "Forward"
	case LayerFlow:
		return "Flow"
	case LayerSocket:
		return "Socket"
	case LayerReflect:
		return "Reflect"
	default:
		return fmt.Sprintf("InvalidLayer(%d)", int(l))
	}
}

type Priority int16

const (
	// The highest priority a handle can have.
	PriorityMax = 30000
	// The default handle priority.
	//
	// Note that multiple handles should not have the same priority.
	PriorityDefault = 0
	// The lowest priority a handle can have.
	PriorityLowest = -PriorityMax
)

type ChecksumFlag int64

const (
	ChecksumAll      = 0x00
	ChecksumNoIP     = 0x01
	ChecksumNoICMP   = 0x02
	ChecksumNoICMPv6 = 0x04
	ChecksumNoTCP    = 0x08
	ChecksumNoUDP    = 0x10
)

type Event int

const (
	EventNetworkPacket Event = iota
	EventFlowEstablished
	EventFlowDeleted
	EventSocketBind
	EventSocketConnect
	EventSocketListen
	EventSocketAccept
	EventSocketClose
	EventReflectOpen
	EventReflectClose
)

func (e Event) String() string {
	switch e {
	case EventNetworkPacket:
		return "NetworkPacket"
	case EventFlowEstablished:
		return "FlowEstablished"
	case EventFlowDeleted:
		return "FlowDeleted"
	case EventSocketBind:
		return "SocketBind"
	case EventSocketConnect:
		return "SocketConnect"
	case EventSocketListen:
		return "SocketListen"
	case EventSocketAccept:
		return "SocketAccept"
	case EventSocketClose:
		return "SocketClose"
	case EventReflectOpen:
		return "ReflectOpen"
	case EventReflectClose:
		return "ReflectClose"
	default:
		return "InvalidEvent"
	}
}
