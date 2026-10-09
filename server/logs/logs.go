package logs

import (
	"fmt"
	"sync/atomic"
	"time"
)

type Metrics struct {
	RXPkts  uint64
	TXPkts  uint64
	RXBytes uint64
	TXBytes uint64
	RXDrops uint64
	TXDrops uint64
	Err     error
}

var Stat Metrics

func AddRX(bytes int) {
	atomic.AddUint64(&Stat.RXBytes, uint64(bytes))
	atomic.AddUint64(&Stat.RXPkts, 1)
}

func AddTX(bytes int) {
	atomic.AddUint64(&Stat.TXBytes, uint64(bytes))
	atomic.AddUint64(&Stat.TXPkts, 1)
}

func Drop(RX bool, ERR error) {
	if RX {
		atomic.AddUint64(&Stat.RXDrops, 1)
	} else {
		atomic.AddUint64(&Stat.TXDrops, 1)
	}

	Stat.Err = ERR
}

func Print(timeout int) {
	var PrevRX uint64
	var PrevTX uint64
	var CurrRX uint64
	var CurrTX uint64
	var firstTick bool

	for {
		time.Sleep(time.Duration(timeout) * time.Second)
		sec := float64(timeout)

		if !firstTick {
			fmt.Print("\033[2A") // Move cursor up 2 lines (to ERR)
		}
		firstTick = false

		ts := time.Now().Format("15:04:05")

		CurrRX = atomic.LoadUint64(&Stat.RXBytes)
		CurrTX = atomic.LoadUint64(&Stat.TXBytes)

		// Line 1: ERR
		errText := Stat.Err
		fmt.Printf("\r\033[2K  \033[90m%s\033[0m  \033[1;33mWR\033[0m: %s\n", ts, errText)

		// Line 2: RX
		fmt.Printf("\r\033[2K  \033[90m%s\033[0m  \033[1;32mRX\033[0m   %7.2fMB \033[90m(%6.2fMbps)\033[0m\n",
			ts,
			float64(CurrRX)/(1024*1024),
			float64(CurrRX-PrevRX)/(125000*sec),
		)

		// Line 3: TX
		fmt.Printf("\r\033[2K  \033[90m%s\033[0m  \033[1;36mTX\033[0m   %7.2fMB \033[90m(%6.2fMbps)\033[0m",
			ts,
			float64(CurrTX)/(1024*1024),
			float64(CurrTX-PrevTX)/(125000*sec),
		)

		PrevRX = atomic.LoadUint64(&Stat.RXBytes)
		PrevTX = atomic.LoadUint64(&Stat.TXBytes)

	}
}
