package crush

import (
	"encoding/binary"
	"log"
	"net"

	"crumble/logs"
)

type Crumb struct {
	UID uint32
	FID uint64

	From  uint16
	To    uint16
	Full  uint16
	Parts uint8

	Payload []byte
}

type Header struct {
	Temp       []byte
	Payload    []byte
	Connection *net.UDPConn

	UID uint32
	FID uint64

	Parts  uint16
	One    uint16
	Bypass bool
}

func Crush(Header Header) []byte {
	RealFull := uint16(len(Header.Payload))
	FullSize := Header.Parts * Header.One
	Extra := false

	if RealFull < 20 {
		return Header.Payload
	}

	if RealFull-FullSize != 0 {
		Header.Parts += 1
		Extra = true
	} else {
		Extra = false
	}

	for i := range Header.Parts {
		From := (i * Header.One)
		To := (i + 1) * Header.One

		if Extra && i == (Header.Parts-1) {
			From = FullSize
			To = RealFull
		}

		binary.LittleEndian.PutUint32(Header.Temp[0:4], Header.UID)
		binary.LittleEndian.PutUint64(Header.Temp[4:12], Header.FID)
		binary.LittleEndian.PutUint16(Header.Temp[13:15], From)
		binary.LittleEndian.PutUint16(Header.Temp[15:17], To)
		binary.LittleEndian.PutUint16(Header.Temp[17:19], RealFull)

		Header.Temp[12] = uint8(Header.Parts)
		copy(Header.Temp[19:], Header.Payload[From:To])

		if Header.Bypass {
			binary.LittleEndian.PutUint16(Header.Temp[13:15], 0)
			binary.LittleEndian.PutUint16(Header.Temp[15:17], 0)
		}

		w, err := Header.Connection.Write(Header.Temp)
		if err != nil {
			log.Fatalln("Connection error! Can't send data to client", err)
		}

		logs.AddTX(w / 10)
	}

	return Header.Payload
}
