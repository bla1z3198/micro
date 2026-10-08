package tunnels

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/songgao/water"
)

const (
	ipv4 = 69
	v4   = 0
	min  = 20

	s1 = 2
	s2 = 4

	s3 = 12
	s4 = 16
	s5 = 20
)

var (
	gp = errors.New("TUN: Dropped: Garbage packet")
	sm = errors.New("TUN: Dropped: Subnet mismatch")
	n4 = errors.New("TUN: Dropped: Not IPv4 packet")
)

type Tun struct {
	SUB  uint8
	Pkt  []byte
	Ifce *water.Interface
}

func Read(Tun Tun) ([]byte, error) {
	// Read from TUN
	n, err := Tun.Ifce.Read(Tun.Pkt)
	size := binary.BigEndian.Uint16(Tun.Pkt[s1:s2])

	// Check read error
	if err != nil {
		fmt.Println("Can't read from TUN:", err)
		fmt.Println("Are you super user?")
		os.Exit(1)
	}

	// Check packet validity
	if Tun.Pkt[v4] == ipv4 && size > min && n >= int(size) {
		Tun.Pkt = Tun.Pkt[:size]
	} else {
		return Tun.Pkt, gp
	}

	if Tun.Pkt[s4] == Tun.SUB {
		return Tun.Pkt, nil
	} else {
		return Tun.Pkt, sm
	}
}

func Write(Tun Tun) ([]byte, error) {
	// Check packet validity
	if Tun.Pkt[v4] == ipv4 {
		_, err := Tun.Ifce.Write(Tun.Pkt)
		if err != nil {
			src := string(binary.BigEndian.Uint16(Tun.Pkt[s3:s4]))
			dst := string(binary.BigEndian.Uint16(Tun.Pkt[s4:s5]))
			return Tun.Pkt, errors.New(string("Dropped: " + src + " -> " + dst))
		}
	} else {
		return Tun.Pkt, n4
	}

	return Tun.Pkt, nil
}
