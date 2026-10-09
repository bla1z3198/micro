package tunnels

import (
	"errors"
	"fmt"
	"os"

	"github.com/songgao/water"
)

var (
	gp = errors.New("TUN: Garbage packet")
	sm = errors.New("TUN: Subnet mismatch")
	n4 = errors.New("TUN: Not IPv4 packet")
)

type Tun struct {
	SUB  uint8
	Pkt  []byte
	Ifce *water.Interface
}

func Read(Tun Tun) (int, error) {
	// Read from TUN
	n, err := Tun.Ifce.Read(Tun.Pkt)
	// Check read error
	if err != nil {
		fmt.Println("Can't read from TUN:", err)
		fmt.Println("Are you super user?")
		os.Exit(1)
	}

	// Check packet validity
	if Tun.Pkt[0] == 69 {
		Tun.Pkt = Tun.Pkt[:n]
	} else {
		return 0, gp
	}

	// Check destination subnet
	if Tun.Pkt[16] == Tun.SUB {
		return n, nil
	} else {
		return 0, sm
	}
}

func Write(Tun Tun) error {
	// Check packet validity
	if Tun.Pkt[0] == 69 {
		_, err := Tun.Ifce.Write(Tun.Pkt)
		if err != nil {
			return errors.New(string("TUN: Dropped: " + err.Error()))
		}
	} else {
		return n4
	}

	return nil
}
