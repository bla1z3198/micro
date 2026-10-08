package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"crumble/collect"
	"crumble/crush"
	"crumble/encryption"
	"crumble/logs"
	"crumble/random"
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
	Info Client
	Hash [32]byte

	Connection      *net.UDPConn
	ConnectionError error

	CPU    = runtime.NumCPU()
	RXPool chan []byte
	TXPool chan []byte
	CXPool chan []byte
)

type Client struct {
	Network Network `json:"network"`
	Tunnel  Tunnel  `json:"tunnel"`
	Sizes   Sizes   `json:"sizes"`
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

type Sizes struct {
	PoolSize        uint16 `json:"poolSize"`
	BypassThreshold uint16 `json:"bypassThreshold"`
	MaxFlows        uint16 `json:"maxFlows"`
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

	RXPool = make(chan []byte, Info.Sizes.PoolSize*4)
	TXPool = make(chan []byte, Info.Sizes.PoolSize)
	CXPool = make(chan []byte, Info.Sizes.PoolSize)

	for range cap(RXPool) {
		RXPool <- make([]byte, (Info.Tunnel.MTU/4)+19)
	}

	for range cap(TXPool) {
		TXPool <- make([]byte, Info.Tunnel.MTU)
	}

	for range cap(CXPool) {
		CXPool <- make([]byte, Info.Tunnel.MTU+12)
	}

	config := water.Config{
		DeviceType: water.TUN,
	}

	config.Name = "microTUN"
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

	collect.Start(Info.Auth.MaxUsers)

	raddr, _ := net.ResolveUDPAddr(
		"udp",
		Info.Network.IP+Info.Network.Port)

	Connection, ConnectionError = net.DialUDP("udp", nil, raddr)

	if ConnectionError != nil {
		fmt.Println("Can't connect to", raddr.String(), ConnectionError)
		os.Exit(0)
	}

	RBError := Connection.SetReadBuffer(connBuf)
	if RBError != nil {
		log.Fatalln("Can't extend connection buffer for read:", RBError)
	}
	WBError := Connection.SetWriteBuffer(connBuf)
	if WBError != nil {
		log.Fatalln("Can't extend connection buffer for write:", WBError)
	}

	for range CPU {
		go Receive(Tun)
		go Transmit(Tun)
	}

	//go logs.Print(int(Info.Network.Logger))

	Banner(
		"v1",
		Info.Network.IP+":"+Info.Network.Port,
		Info.Tunnel.IP,
		Info.Tunnel.MTU,
		start,
	)
}

func Receive(Tun *water.Interface) {
	result := collect.Ready{}

	for {
		// Get memory from pool
		pkt := <-RXPool

		// Read packet from network
		n, _, err := Connection.ReadFromUDP(pkt)
		if err != nil {
			log.Fatalln("Can't read from connection:", err)
		}

		// Check packet validity
		if n < 20 {
			RXPool <- pkt
			continue
		}

		// Set packet bounds, parse header
		pkt = pkt[:n]
		from := binary.LittleEndian.Uint16(pkt[s1:s2])
		to := binary.LittleEndian.Uint16(pkt[s2:s3])

		// Fast path for bypass packets
		if from == to {
			encryption.Encrypt(pkt[header:], pkt[header:], Hash, pkt[:nonce])
			pkt = pkt[header:]

			// Write to TUN
			back, err := tunnels.Write(
				tunnels.Tun{
					SUB:  Info.Auth.SubnetID,
					Pkt:  pkt,
					Ifce: Tun,
				},
			)
			if err != nil {
				logs.Drop(true, err)
			}

			logs.AddRX(len(back))
			RXPool <- back[:cap(back)]

			// Normal path for direct packets
		} else {
			if collect.Exist {
				result = collect.Sort(pkt, nil)
			} else {
				result = collect.Sort(pkt, <-CXPool)
			}

			// Handle collect results
			if result.Add != nil {
				if result.Flag {
					// Write to TUN
					back, err := tunnels.Write(
						tunnels.Tun{
							SUB:  Info.Auth.SubnetID,
							Pkt:  result.Add[12:],
							Ifce: Tun,
						},
					)
					if err != nil {
						logs.Drop(true, err)
					}

					logs.AddRX(len(back))
					CXPool <- back[:cap(back)]
				} else {
					logs.Drop(true, nil)
					CXPool <- result.Add[:cap(result.Add)]
				}
			}

			// Put memory back
			RXPool <- result.Pkt[:cap(result.Pkt)]
		}
	}
}

func Transmit(Tun *water.Interface) {
	// Init FID, nonce, temp array for crushing and Header
	var FID uint64 = 1
	nonce := make([]byte, 12)
	temp := make([]byte, Info.Tunnel.MTU+19)
	Header := crush.Header{}

	for {
		// Get memory from pool
		pkt := <-TXPool

		// Read from TUN
		back, err := tunnels.Read(tunnels.Tun{
			SUB:  Info.Auth.SubnetID,
			Pkt:  pkt,
			Ifce: Tun,
		})
		// Check error
		if err != nil {
			logs.Drop(false, err)
			TXPool <- back[:cap(back)]
			continue
		} else {
			fmt.Println(back)
		}

		// Encrypt data
		binary.LittleEndian.PutUint32(nonce[:4], 1)
		binary.LittleEndian.PutUint64(nonce[4:], FID)
		encryption.Encrypt(back, back, Hash, nonce)

		// Full Header for crush package
		Header = crush.Header{
			Temp:       temp,
			Payload:    back,
			Connection: Connection,
			UID:        Info.Auth.UID,
			FID:        FID,
		}

		// Bypass or Direct packet?
		if len(back) < int(Info.Sizes.BypassThreshold) {
			Header.Parts = 1
			Header.One = uint16(len(back))
			Header.Bypass = true
		} else {
			rand := random.Random(len(back))
			Header.Parts = rand.Parts
			Header.One = rand.One
			Header.Bypass = false
		}

		worked := crush.Crush(Header)
		TXPool <- worked[:cap(worked)]

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
