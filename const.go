package godivert

type Direction bool

const (
	PacketBufferSize   = 1500
	PacketChanCapacity = 256

	WinDivertDirectionOutbound Direction = false
	WinDivertDirectionInbound  Direction = true
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

func (d Direction) String() string {
	if bool(d) {
		return "Inbound"
	}
	return "Outbound"
}
