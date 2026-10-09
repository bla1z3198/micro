package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"crumble/encryption"
	"crumble/logs"
	"crumble/tunnels"

	"github.com/songgao/water"
)

const (
	uid     = 4
	connBuf = 26214400
	header  = 19

	s1 = 13
	s2 = 15
	s3 = 17
	s4 = 16
	s5 = 20

	nonce = 12
)

var (
	Info  Server
	Route Routing

	Conn    *net.UDPConn
	Connerr error

	Hash [32]byte
	CPU  = runtime.NumCPU()

	Mu sync.Mutex
)

type Server struct {
	Network Network `json:"network"`
	Tunnel  Tunnel  `json:"tunnel"`
	Auth    Auth    `json:"auth"`
}

type Network struct {
	IP     string `json:"ip"`
	Port   string `json:"port"`
	Logger uint16 `json:"logger"`
}

type Tunnel struct {
	IP        string `json:"ip"`
	MTU       uint16 `json:"mtu"`
	QueueSize uint16 `json:"queueSize"`
}

type Auth struct {
	MaxUsers uint16 `json:"maxUsers"`
	SubnetID uint8  `json:"subnetId"`
	Password string `json:"password"`
}

type Routing struct {
	LAN map[[4]byte]uint32
	WAN []atomic.Pointer[net.UDPAddr]
}

func Start() {
	start := time.Now()

	Server, ServerLoadError := os.Open("cfg/server.json")
	if ServerLoadError != nil {
		log.Fatalln("Can't load cfg file:", ServerLoadError)
	}

	ServerBuf, ServerReadError := io.ReadAll(Server)
	if ServerReadError != nil {
		log.Fatalln("Can't read cfg file:", ServerReadError)
	}

	ServerJSONError := json.Unmarshal(ServerBuf, &Info)
	if ServerJSONError != nil {
		log.Fatalln("Can't parse cfg json:", ServerJSONError)
	}

	Iptable, IptableLoadError := os.Open("cfg/iptable.json")
	if IptableLoadError != nil {
		log.Fatalln("Can't load iptable file")
	}

	IptableBuf, IptableReadError := io.ReadAll(Iptable)
	if IptableReadError != nil {
		log.Fatalln("Can't read iptable file:", IptableReadError)
	}

	temp := make(map[string]uint32, Info.Auth.MaxUsers)
	IptableJSONError := json.Unmarshal(IptableBuf, &temp)
	if IptableJSONError != nil {
		log.Fatalln("Can't parse iptable json:", IptableJSONError)
	}

	Hash = encryption.Secret(Info.Auth.Password)
	Route.WAN = make([]atomic.Pointer[net.UDPAddr], Info.Auth.MaxUsers+1)
	Route.LAN = make(map[[4]byte]uint32, Info.Auth.MaxUsers+1)

	for ip, uid := range temp {
		rawIP := net.ParseIP(ip)
		if rawIP == nil {
			continue
		}

		ipv4 := [4]byte(rawIP.To4())
		Route.LAN[ipv4] = uid
	}

	config := water.Config{
		DeviceType: water.TUN,
	}

	config.Name = "SS2"
	config.MultiQueue = true

	Tun, err := water.New(config)
	if err != nil {
		log.Fatalln("Can't create TUN:", err)
	}

	cmd := exec.Command("ethtool", "-K", config.Name, "tx", "off")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Could not disable TX offload: %v\n", err)
	}

	mtu := strconv.Itoa(int(Info.Tunnel.MTU))
	queue := strconv.Itoa(int(Info.Tunnel.QueueSize))

	c1 := exec.Command(
		"ip", "link", "set", "dev", config.Name, "up").Run()
	if c1 != nil {
		log.Fatalln("Can't set ip for TUN:", c1)
	}
	c2 := exec.Command(
		"ip", "addr", "add", Info.Tunnel.IP, "dev", config.Name).Run()
	if c2 != nil {
		log.Fatalln("Can't up TUN interface:", c2)
	}
	c3 := exec.Command(
		"ip", "link", "set", "dev", config.Name, "txqueuelen", queue).Run()
	if c3 != nil {
		log.Fatalln("Can't extend TUN interface:", c3)
	}
	c4 := exec.Command(
		"ip", "link", "set", "dev", config.Name, "mtu", mtu).Run()
	if c4 != nil {
		log.Fatalln("Can't set MTU for TUN:", c4)
	}

	laddr, _ := net.ResolveUDPAddr("udp", Info.Network.IP+Info.Network.Port)
	Conn, Connerr = net.ListenUDP("udp", laddr)
	if Connerr != nil {
		panic(Connerr)
	}

	RBError := Conn.SetReadBuffer(connBuf)
	if RBError != nil {
		log.Fatalln("Can't extend connection buffer for read:", RBError)
	}

	WBError := Conn.SetWriteBuffer(connBuf)
	if WBError != nil {
		log.Fatalln("Can't extend connection buffer for write:", WBError)
	}

	for range 1 {
		go Receive(Tun, Conn)
		go Transmit(Tun, Conn)
	}

	go logs.Print(int(Info.Network.Logger))

	Banner(
		"v1",
		Info.Network.IP+Info.Network.Port,
		Info.Tunnel.IP,
		Info.Tunnel.MTU,
		start,
	)
}

func Receive(Tun *water.Interface, Conn *net.UDPConn) {
	pkt := make([]byte, Info.Tunnel.MTU+12)

	for {
		// Read packet from network
		n, addr, err := Conn.ReadFromUDP(pkt)
		// Check packet validity
		if err != nil {
			logs.Drop(true, err)
			continue
		}

		if n < 20 {
			logs.Drop(true, errors.New("Too small: "+strconv.Itoa(n)+" bytes"))
			continue
		}

		// Add RX
		logs.AddRX(n)

		// Check NAT
		uid := binary.LittleEndian.Uint32(pkt[:4])
		if Route.WAN[uid].Load() == nil {
			if Route.WAN[uid].CompareAndSwap(nil, addr) {
				logs.Drop(true, errors.New("New user -> "+addr.String()))
			}
		}

		// Unencrypt packet
		encryption.Encrypt(pkt[12:n], pkt[12:n], Hash, pkt[:12])

		// Write to TUN
		TUNerr := tunnels.Write(
			tunnels.Tun{
				SUB:  Info.Auth.SubnetID,
				Pkt:  pkt[12:n],
				Ifce: Tun,
			},
		)

		// Check error
		if TUNerr != nil {
			logs.Drop(true, TUNerr)
		}
	}
}

func Transmit(Tun *water.Interface, Conn *net.UDPConn) {
	var FID uint64 = 1
	var UID uint32 = 4294967295
	pkt := make([]byte, Info.Tunnel.MTU+12)

	LAN := make(map[[4]byte]uint32)
	maps.Copy(LAN, Route.LAN)

	for {
		// Add UID and FID
		binary.LittleEndian.PutUint32(pkt[0:4], UID)
		binary.LittleEndian.PutUint64(pkt[4:12], FID)

		// Read from TUN
		k, err := tunnels.Read(tunnels.Tun{
			SUB:  Info.Auth.SubnetID,
			Pkt:  pkt[12:],
			Ifce: Tun,
		})
		// Check error
		if err != nil {
			logs.Drop(false, err)
			continue
		}

		// Get WAN
		WAN := Route.WAN[LAN[[4]byte(pkt[28:32])]].Load()
		if WAN == nil {
			continue
		}

		// Encrypt data
		// fmt.Println("TX:")
		// fmt.Println(pkt[12 : 12+len(back)])
		// fmt.Println("")

		encryption.Encrypt(pkt[12:12+k], pkt[12:12+k], Hash, pkt[:12])

		// Send to network
		n, err := Conn.WriteToUDP(pkt[:12+k], WAN)
		if err != nil {
			logs.Drop(false, err)
			continue
		} else {
			// Add TX
			logs.AddTX(n)

			// Increase FID
			FID++
			UID--
		}
	}
}

func ListenReuseUDP(addr string) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1)
			})
		},
	}

	conn, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

func Banner(vrs, adr, lan string, mtu uint16, startTime time.Time) {
	const (
		whiteBold = "\033[1;37m"
		bold      = "\033[1m"
		gray      = "\033[90m"
		reset     = "\033[0m"
	)

	// Bold white detailed slant logo
	banner := `
   ________  (_)_____________ 
  / __ ___ \/ / ___/ ___/ __ \
 / / / / / / / /__/ /  / /_/ /
/_/ /_/ /_/_/\___/_/   \____/
`
	elapsed := time.Since(startTime).Round(time.Microsecond)

	fmt.Println(whiteBold + banner + reset)
	fmt.Printf("\n    %sVRS%s  %s%s%s %s(started in %s%s%s)%s\n",
		bold, reset, whiteBold, vrs, reset, gray, whiteBold, elapsed, gray, reset)
	fmt.Printf("    %sADR%s  %s%s%s\n", bold, reset, whiteBold, adr, reset)
	fmt.Printf("    %sLAN%s  %s%s%s\n", bold, reset, whiteBold, lan, reset)
	fmt.Printf("    %sMTU%s  %s%d%s\n\n", bold, reset, whiteBold, mtu, reset)
	fmt.Println("")
	fmt.Println("")
}

func main() {
	Start()
	select {}
}
