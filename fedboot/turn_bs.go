//go:build turn

package fedboot

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/envsh/toxera/fedkey"
	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

////////////

type Turn struct {

}

var _ = regme(&Turn{})

func (o *Turn) Start() error {
	return nil
}

func (o *Turn) Stop() error {
	return nil
}

func (o *Turn) Info() string {
	return "{}"
}

func MainTurn() {
	mainTurn()
}

//////


type Config struct {
	KeyFile  string
	StunAddr string
	Server   string
	Username string
	Password string
}

var (
	startTime    = time.Now()
	healthMu     sync.RWMutex
	udpHealthy   = false
	tcpHealthy   = false
	lastRecvUnix int64
)

func mainTurn() {
	stunFlag := flag.String("stun", "stun.relay.metered.ca:80,stun.cloudflare.com:3478", "comma-separated STUN server addresses (randomly selected)")
	serverFlag := flag.String("s", "standard.relay.metered.ca:80", "comma-separated TURN server addresses (randomly selected)")
	user := flag.String("u", "foo", "TURN username")
	pass := flag.String("p", "bar", "TURN password")
	keyFile := flag.String("k", "key.txt", "key file (seed=...)")
	showHelp := flag.Bool("h", false, "show help")
	flag.Parse()

	if *showHelp {
		fmt.Println("Usage: turn_bs [options]")
		fmt.Println()
		fmt.Println("Options:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("At startup, one STUN and one TURN server are randomly selected")
		fmt.Println("from each comma-separated list.")
		fmt.Println()
		fmt.Println("Free TURN servers:")
		fmt.Println("  standard.relay.metered.ca:80       (Metered.ca free relay, UDP+TCP)")
		fmt.Println("  stun.relay.metered.ca:80           (STUN via Metered.ca)")
		fmt.Println("  stun.cloudflare.com:3478           (STUN via Cloudflare)")
		return
	}

	cfg := Config{
		KeyFile:  *keyFile,
		StunAddr: *stunFlag,
		Server:   *serverFlag,
		Username: *user,
		Password: *pass,
	}

	if err := bootstrap(cfg); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}

func bootstrap(cfg Config) error {
	stunList := strings.Split(cfg.StunAddr, ",")
	turnList := strings.Split(cfg.Server, ",")
	chosenStun := strings.TrimSpace(stunList[rand.Intn(len(stunList))])
	chosenTurn := strings.TrimSpace(turnList[rand.Intn(len(turnList))])
	fmt.Printf("[*] STUN server: %s\n", chosenStun)
	fmt.Printf("[*] TURN server: %s\n", chosenTurn)

	fmt.Println("=== Phase 1: Key Loading ===")
	_, err := fedkey.LoadKeyRing(cfg.KeyFile, true)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}
	seedHex, err := readSeed(cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("read seed: %w", err)
	}
	fmt.Printf("[+] Loaded key from: %s\n", cfg.KeyFile)
	fmt.Printf("    Node ID: %s\n", seedHex)
	fmt.Println()

	fmt.Println("=== Phase 2A: UDP TURN ===")
	udpConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("udp listen: %w", err)
	}

	udpClient, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: "stun.relay.metered.ca:80",
		TURNServerAddr: chosenTurn,
		Conn:           udpConn,
		Username:       cfg.Username,
		Password:       cfg.Password,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		return fmt.Errorf("udp client: %w", err)
	}

	if err := udpClient.Listen(); err != nil {
		return fmt.Errorf("udp client listen: %w", err)
	}

	publicAddr, err := udpClient.SendBindingRequest()
	if err != nil {
		return fmt.Errorf("stun binding: %w", err)
	}
	udpClient.CreatePermission(publicAddr)
	fmt.Printf("[*] UDP transport: %s → %s\n", udpConn.LocalAddr(), chosenTurn)
	fmt.Printf("    [STUN] Public address: %s\n", publicAddr)

	udpRelay, err := udpClient.Allocate()
	if err != nil {
		return fmt.Errorf("udp allocate: %w", err)
	}
	fmt.Printf("    [Relay] UDP relay:      %s\n", udpRelay.LocalAddr())
	fmt.Println()

	fmt.Println("=== Phase 2B: TCP TURN ===")
	tcpRaw, err := net.Dial("tcp", "standard.relay.metered.ca:80")
	if err != nil {
		return fmt.Errorf("tcp dial: %w", err)
	}

	tcpClient, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: "stun.relay.metered.ca:80",
		TURNServerAddr: "standard.relay.metered.ca:80",
		Conn:           turn.NewSTUNConn(tcpRaw),
		Username:       cfg.Username,
		Password:       cfg.Password,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		return fmt.Errorf("tcp client: %w", err)
	}

	if err := tcpClient.Listen(); err != nil {
		return fmt.Errorf("tcp client listen: %w", err)
	}

	tcpAlloc, err := tcpClient.AllocateTCP()
	if err != nil {
		return fmt.Errorf("tcp allocate: %w", err)
	}

	fmt.Printf("[*] TCP transport: %s → %s\n", tcpRaw.LocalAddr(), chosenTurn)
	fmt.Printf("    [Relay] TCP relay:      %s\n", tcpAlloc.Addr())
	fmt.Println()

	fmt.Println("=== Phase 3: Background Services ===")

	go udpReadLoop(udpRelay, seedHex)
	fmt.Println("[*] UDP read loop started")

	go func() {
		for {
			conn, err := tcpAlloc.AcceptTCP()
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				log.Printf("[TCP] New connection from %s", c.RemoteAddr())
				c.Write([]byte("turn_bs: NodeID=" + seedHex + "\n"))
				time.Sleep(3 * time.Second)
			}(conn)
		}
	}()
	fmt.Println("[*] TCP accept loop started")

	go udpHealthLoop(udpClient, udpRelay, publicAddr, seedHex)
	fmt.Println("[*] UDP health check (10s)")

	tcpHealthLoop := func() {
		dummy := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		fails := 0
		for {
			time.Sleep(10 * time.Second)
			err = tcpClient.CreatePermission(dummy)
			_, cerr := tcpAlloc.Dial("tcp", dummy.String())
			if cerr != nil && !strings.Contains(cerr.Error(), "447") {
				fails++
				log.Printf("[!] TCP health check failed (%d/3): %v", fails, cerr)
				if fails >= 3 {
				}
				setTCPHealthy(false)
				continue
			}
			fails = 0
			setTCPHealthy(true)
		}
	}
	go tcpHealthLoop()
	fmt.Println("[*] TCP health check (30s)")
	fmt.Println()

	printStatus(seedHex, chosenStun, chosenTurn, publicAddr, udpRelay.LocalAddr(), tcpAlloc.Addr())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\n[*] Shutting down...")
	udpClient.Close()
	tcpClient.Close()
	return nil
}

func udpReadLoop(relay net.PacketConn, nodeID string) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := relay.ReadFrom(buf)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		atomic.StoreInt64(&lastRecvUnix, time.Now().Unix())
		log.Printf("<< [UDP] %s → %s", addr, string(buf[:n]))
		relay.WriteTo([]byte("turn_bs: NodeID="+nodeID+"\n"), addr)
	}
}

func udpHealthLoop(udpClient *turn.Client, relay net.PacketConn, publicAddr net.Addr, nodeID string) {
	peerConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Fatalf("[FATAL] udp health peer conn: %v", err)
	}
	defer peerConn.Close()

	relayAddr := relay.LocalAddr()
	ping := []byte("hb:" + nodeID)
	fails := 0

	for i := 0; ; i++ {
		err = udpClient.CreatePermission(publicAddr)

		time.Sleep(1 * time.Second)
		d := []byte(string(ping[:16]) + fmt.Sprintf("+%v", i))
		peerConn.WriteTo(d, relayAddr)

		time.Sleep(10 * time.Second)
		if time.Since(time.Unix(atomic.LoadInt64(&lastRecvUnix), 0)) < 30*time.Second {
			fails = 0
			setUDPHealthy(true)
			continue
		}

		fails++
		log.Printf("[!] UDP health check failed (%d/3): no data received over relay", fails)
		if fails >= 3 {
		}
		setUDPHealthy(false)
	}
}

func setUDPHealthy(v bool) {
	healthMu.Lock()
	udpHealthy = v
	healthMu.Unlock()
}

func setTCPHealthy(v bool) {
	healthMu.Lock()
	tcpHealthy = v
	healthMu.Unlock()
}

func getHealth() (bool, bool) {
	healthMu.RLock()
	defer healthMu.RUnlock()
	return udpHealthy, tcpHealthy
}

func printStatus(nodeID, stunAddr, turnAddr string, public, udpRelay, tcpRelay net.Addr) {
	uh, th := getHealth()
	uptime := time.Since(startTime).Round(time.Second)

	fmt.Println("========================================")
	fmt.Println("  ✅ TURN BOOTSTRAP ONLINE")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Printf("  Node ID:       %s\n", nodeID)
	fmt.Printf("  STUN Server:   %s\n", stunAddr)
	fmt.Printf("  TURN Server:   %s\n", turnAddr)
	fmt.Println()
	fmt.Printf("  📡 STUN Public:   %s\n", public)
	fmt.Printf("  📡 UDP Relay:     %s\n", udpRelay)
	fmt.Printf("  🔗 TCP Relay:     %s\n", tcpRelay)
	fmt.Println()

	udpStatus := "✓"
	if !uh {
		udpStatus = "✗"
	}
	tcpStatus := "✓"
	if !th {
		tcpStatus = "✗"
	}
	fmt.Printf("  💚 Health         UDP %s  TCP %s\n", udpStatus, tcpStatus)
	fmt.Printf("  🕒 Uptime         %s\n", uptime)
	fmt.Printf("  ✅ STATUS         ONLINE\n")
	fmt.Println("========================================")
}

func readSeed(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "seed=") {
			return strings.TrimSpace(line[5:]), nil
		}
	}
	return "", fmt.Errorf("no seed= line in %s", path)
}
