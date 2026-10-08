package collect

import (
	"encoding/binary"
	"time"

	"crumble/crush"
	"crumble/encryption"
)

var (
	Flows map[FlowKey]Service
	Hash  [32]byte
	flow  Service
	Exist bool
)

type FlowKey struct {
	UID uint32
	FID uint64
}

type Ready struct {
	Pkt  []byte
	Add  []byte
	Flag bool
}

type Service struct {
	Buf        []byte
	Mask       uint64
	TargetMask uint64
	LastUpdate int64
}

func Start(MaxUsers uint16) {
	Flows = make(map[FlowKey]Service, MaxUsers)
}

func Sort(pkt []byte, add []byte) Ready {
	crumb := crush.Crumb{
		UID:     binary.LittleEndian.Uint32(pkt[:4]),
		FID:     binary.LittleEndian.Uint64(pkt[4:12]),
		From:    binary.LittleEndian.Uint16(pkt[13:15]),
		To:      binary.LittleEndian.Uint16(pkt[15:17]),
		Full:    binary.LittleEndian.Uint16(pkt[17:19]),
		Parts:   pkt[12],
		Payload: pkt[19:],
	}

	key := FlowKey{crumb.UID, crumb.FID}
	flow, Exist = Flows[key]

	if !Exist {
		binary.LittleEndian.PutUint32(add[:4], crumb.UID)
		binary.LittleEndian.PutUint64(add[4:12], crumb.FID)

		flow = Service{
			Buf:        add[12:],
			Mask:       0,
			TargetMask: 0 | (1 << crumb.Parts) - 1,
			LastUpdate: 0,
		}
	}

	var index uint8
	if crumb.To == crumb.Full {
		index = crumb.Parts - 1
	} else {
		index = uint8(crumb.From / (crumb.To - crumb.From))
	}

	copy(flow.Buf[12+crumb.From:12+crumb.To], crumb.Payload)
	flow.Mask = flow.Mask | (1 << index)
	flow.LastUpdate = time.Now().UnixNano()
	Flows[key] = flow

	for key, flow := range Flows {
		if flow.LastUpdate < time.Now().UnixNano()-int64(2*time.Second) {
			flow.Buf = flow.Buf[:cap(flow.Buf)]
			r := Ready{
				Pkt:  pkt,
				Add:  flow.Buf,
				Flag: false,
			}

			delete(Flows, key)
			return r
		}
	}

	if flow.Mask == flow.TargetMask {
		encryption.Encrypt(flow.Buf, flow.Buf, Hash, flow.Buf[:12])
		flow.Buf = flow.Buf[:cap(flow.Buf)]
		r := Ready{
			Pkt:  pkt,
			Add:  flow.Buf,
			Flag: true,
		}

		delete(Flows, key)
		return r
	}

	r := Ready{
		Pkt:  pkt,
		Add:  nil,
		Flag: false,
	}

	return r
}
