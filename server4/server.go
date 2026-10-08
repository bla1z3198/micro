package main

import (
	"context"
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
	"sync"
	"syscall"
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
	Info  Server
	Route Routing

	Hash [32]byte
	CPU  = runtime.NumCPU()

	RXPool chan []byte
	TXPool chan []byte
	CXPool chan []byte

	Flows map[collect.FlowKey]collect.Service
)

type Server struct {
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
	DebugMode bool   `json:"debugMode"`
}

type Sizes struct {
	PoolSize        uint16 `json:"poolSize"`
	BypassThreshold uint16 `json:"bypassThreshold"`
	MaxFlows        uint16 `json:"maxFlows"`
}

type Auth struct {
	MaxUsers uint16 `json:"maxUsers"`
	SubnetID uint8  `json:"subnetId"`
	Password string `json:"password"`
}

type Routing struct {
	LanUID sync.Map
	UIDWan sync.Map
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
	Flows = make(map[collect.FlowKey]collect.Service, Info.Auth.MaxUsers)

	RXPool = make(chan []byte, Info.Sizes.PoolSize*4)
	TXPool = make(chan []byte, Info.Sizes.PoolSize)
	CXPool = make(chan []byte, Info.Sizes.PoolSize)

	for ip, uid := range temp {
		rawIP := net.ParseIP(ip)
		if rawIP == nil {
			continue
		}
		ipv4 := [4]byte(rawIP.To4())
		Route.LanUID.Store(ipv4, uid)
	}

	for range cap(RXPool) {
		RXPool <- make([]byte, (Info.Tunnel.MTU/4)+19)
	}

	for range cap(TXPool) {
		TXPool <- make([]byte, Info.Tunnel.MTU+19)
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

	for range CPU {
		Conn, err := ListenReuseUDP(Info.Network.IP + Info.Network.Port)
		if err != nil {
			panic(err)
		}

		RBError := Conn.SetReadBuffer(connBuf)
		if RBError != nil {
			log.Fatalln("Can't extend connection buffer for read:", RBError)
		}

		WBError := Conn.SetWriteBuffer(connBuf)
		if WBError != nil {
			log.Fatalln("Can't extend connection buffer for write:", WBError)
		}

		go Receive(Tun, Conn)
		go Transmit(Tun, Conn)
	}

	//go logs.Print(int(Info.Network.Logger))

	Banner(
		"v1",
		Info.Network.IP+Info.Network.Port,
		Info.Tunnel.IP,
		Info.Tunnel.MTU,
		start,
	)
}

func Receive(Tun *water.Interface, Conn *net.UDPConn) {
	result := collect.FlowKey{}
	ticker := time.NewTicker(time.Second * 3)

	for {
		// Get memory from pool
		pkt := <-RXPool

		// Read packet from network
		n, addr, err := Conn.ReadFromUDP(pkt)
		logs.AddRX(n)

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
		uid := binary.LittleEndian.Uint32(pkt[0:4])
		fid := binary.LittleEndian.Uint64(pkt[4:12])

		parts := uint8(pkt[12])
		from := binary.LittleEndian.Uint16(pkt[13:15])
		to := binary.LittleEndian.Uint16(pkt[15:17])
		full := binary.LittleEndian.Uint16(pkt[17:19])

		// Check NAT record
		_, loaded := Route.UIDWan.LoadOrStore(uid, addr.String())
		if !loaded {
			logs.Drop(true, errors.New("New user -> "+addr.String()))
		}

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

			RXPool <- back[:cap(back)]

			// Normal path for direct packets
		} else {
			key := collect.FlowKey{UID: uid, FID: fid}
			flow, exist := Flows[key]

			// Check flow existance
			if !exist {
				flow = collect.Service{
					Buf:        <-CXPool,
					Mask:       0,
					TargetMask: 0 | (1 << parts) - 1,
					LastUpdate: 0,
				}
			}

			// Call Sort function
			result = collect.Sort(collect.Call{
				Payload: pkt[19:],
				Flow:    flow,
				Key:     key,
				Parts:   parts,
				From:    from,
				To:      to,
				Full:    full,
			})

			// Get return from Sort
			ready := Flows[result]

			// Check Sort return
			if result.UID != 0 {
				encryption.Encrypt(ready.Buf, ready.Buf, Hash, ready.Buf[:12])

				// Write to TUN
				back, err := tunnels.Write(
					tunnels.Tun{
						SUB:  Info.Auth.SubnetID,
						Pkt:  ready.Buf[12:],
						Ifce: Tun,
					},
				)
				if err != nil {
					logs.Drop(true, err)
				}

				// Put memory back
				CXPool <- back[:cap(back)]
				delete(Flows, result)
			} else {
				// Put memory back
				RXPool <- pkt[:cap(pkt)]
			}
		}

		// Clean up "dead" packets
		select {
		case <-ticker.C:
			for key, flow := range Flows {
				if flow.LastUpdate < time.Now().UnixNano()-int64(2*time.Second) {
					delete(Flows, key)
				}
			}

		default:
			continue
		}
	}
}

func Transmit(Tun *water.Interface, Conn *net.UDPConn) {
	// Init FID, nonce, temp array for crushing and Header
	var FID uint64 = 1
	nonce := make([]byte, 12)
	temp := make([]byte, Info.Tunnel.MTU)
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
		}

		lanIP := [4]byte(back[s4:s5])

		// Look up UID by LAN address
		uidVal, existUID := Route.LanUID.Load(lanIP)
		if !existUID {
			logs.Drop(false, err)
			TXPool <- back[:cap(back)]
			continue
		}
		targetUID := uidVal.(uint32)

		// Look up WAN address by UID
		wanVal, existWan := Route.UIDWan.Load(targetUID)
		if !existWan {
			logs.Drop(false, err)
			TXPool <- back[:cap(back)]
			continue
		}

		WanIP := wanVal.(string)

		// Init client address
		raddr, _ := net.ResolveUDPAddr("udp", WanIP)
		logs.AddTX(len(back))

		// Encrypt data
		binary.LittleEndian.PutUint32(nonce[:4], 1)
		binary.LittleEndian.PutUint64(nonce[4:], FID)
		encryption.Encrypt(back, back, Hash, nonce)

		// Full Header for crush package
		Header = crush.Header{
			Temp:       temp,
			Payload:    back,
			Connection: Conn,
			Raddr:      raddr,
			UID:        1,
			FID:        FID,
		}

		// Bypass or Direct packet?
		if len(pkt) < int(Info.Sizes.BypassThreshold) {
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
