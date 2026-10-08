package collect

import (
	"time"
)

type FlowKey struct {
	UID uint32
	FID uint64
}

type Service struct {
	Buf        []byte
	Mask       uint64
	TargetMask uint64
	LastUpdate int64
}

type Call struct {
	Payload []byte
	Flow    Service
	Key     FlowKey
	Parts   uint8
	From    uint16
	To      uint16
	Full    uint16
}

func Sort(Call Call) FlowKey {
	var index uint8
	if Call.To == Call.Full {
		index = Call.Parts - 1
	} else {
		index = uint8(Call.From / (Call.To - Call.From))
	}

	copy(Call.Flow.Buf[Call.From:Call.To], Call.Payload)
	Call.Flow.Mask = Call.Flow.Mask | (1 << index)
	Call.Flow.LastUpdate = time.Now().UnixNano()

	if Call.Flow.Mask == Call.Flow.TargetMask {
		return Call.Key
	}

	r := Call
	r.Key.UID = 0
	return r.Key
}
