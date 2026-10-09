package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"crumble/encryption"
	"crumble/logs"
	"crumble/tunnels"

	"github.com/songgao/water"
)

var (
	Info Client
	Hash [32]byte

	Connection      *net.UDPConn
	ConnectionError error

	CPU = runtime.NumCPU()
)

type Client struct {
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
	UID      uint32 `json:"uid"`
	MaxUsers uint16 `json:"maxUsers"`
	SubnetID uint8  `json:"subnetId"`
	Password string `json:"password"`
}

func Start() {
	start := time.Now()

	Client, ClientLoadError := os.Open("cfg/connector.json")
	if ClientLoadError != nil {
		log.Fatalln("Can't load cfg file:", ClientLoadError)
	}

	ClientBuf, ClientReadError := io.ReadAll(Client)
	if ClientReadError != nil {
		log.Fatalln("Can't read cfg file:", ClientReadError)
	}

	ClientJSONError := json.Unmarshal(ClientBuf, &Info)
	if ClientJSONError != nil {
		log.Fatalln("Can't parse cfg json:", ClientJSONError)
	}

	Hash = encryption.Secret(Info.Auth.Password)

	config := water.Config{
		DeviceType: water.TUN,
	}

	config.Name = "SS"
	config.MultiQueue = true

	Tun, err := water.New(config)
	if err != nil {
		log.Fatalln("Can't create TUN:", err)
	}

	mtu := strconv.Itoa(int(Info.Tunnel.MTU))
	queue := strconv.Itoa(int(Info.Tunnel.QueueSize))

	c1 := exec.Command(
		"sudo", "ip", "addr", "add", Info.Tunnel.IP, "dev", config.Name).Run()
	if c1 != nil {
		log.Fatalln("Can't up TUN:", c1)
	}
	c2 := exec.Command(
		"sudo", "ip", "link", "set", "dev", config.Name, "up").Run()
	if c2 != nil {
		log.Fatalln("Can't link TUN:", c2)
	}
	c3 := exec.Command(
		"sudo", "ip", "route", "add", "0.0.0.0/1", "dev", config.Name).Run()
	if c3 != nil {
		log.Fatalln("Can't route traffic to TUN:", c3)
	}
	c4 := exec.Command(
		"sudo", "ip", "route", "add", "128.0.0.0/1", "dev", config.Name).Run()
	if c4 != nil {
		log.Fatalln("Can't route traffic to TUN:", c4)
	}
	c5 := exec.Command(
		"sudo", "ip", "link", "set", "dev", config.Name, "txqueuelen", queue).Run()
	if c5 != nil {
		log.Fatalln("Can't set queue for TUN:", c5)
	}
	c6 := exec.Command(
		"sudo", "ip", "link", "set", "dev", config.Name, "mtu", mtu).Run()
	if c6 != nil {
		log.Fatalln("Can't set MTU for TUN:", c6)
	}

	raddr, _ := net.ResolveUDPAddr(
		"udp",
		Info.Network.IP+Info.Network.Port)

	Connection, ConnectionError = net.DialUDP("udp", nil, raddr)

	if ConnectionError != nil {
		fmt.Println("Can't connect to", raddr.String(), ConnectionError)
		os.Exit(0)
	}

	RBError := Connection.SetReadBuffer(26214400)
	if RBError != nil {
		log.Fatalln("Can't extend connection buffer for read:", RBError)
	}

	WBError := Connection.SetWriteBuffer(26214400)
	if WBError != nil {
		log.Fatalln("Can't extend connection buffer for write:", WBError)
	}

	for range CPU / 2 {
		go Receive(Tun)
		go Transmit(Tun)
	}

	go logs.Print(int(Info.Network.Logger))

	Banner(
		"v1",
		Info.Network.IP+":"+Info.Network.Port,
		Info.Tunnel.IP,
		Info.Tunnel.MTU,
		start,
	)
}

func Receive(Tun *water.Interface) {
	pkt := make([]byte, Info.Tunnel.MTU+12)

	for {
		// Read packet from network
		n, err := Connection.Read(pkt)
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
			logs.Drop(true, err)
		}
	}
}

func Transmit(Tun *water.Interface) {
	var FID uint64 = 1
	UID := Info.Auth.UID
	pkt := make([]byte, Info.Tunnel.MTU+12)

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

		// Encrypt data
		encryption.Encrypt(pkt[12:12+k], pkt[12:12+k], Hash, pkt[:12])

		// Send to network
		n, err := Connection.Write(pkt[:12+k])
		if err != nil {
			logs.Drop(false, err)
		}

		// Add TX
		logs.AddTX(n)

		// Increase FID
		FID++
	}
}

func Banner(vrs, adr, lan string, mtu uint16, startTime time.Time) {
	const (
		whiteBold = "\033[1;37m"
		bold      = "\033[1m"
		gray      = "\033[90m"
		reset     = "\033[0m"
	)

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
