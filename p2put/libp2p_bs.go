////go:build libp2p

package p2put

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	// "strings"

	"github.com/envsh/toxera/fedkey"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	// "github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	discovery "github.com/libp2p/go-libp2p/p2p/discovery/util"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	// madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/multiformats/go-multiaddr"
)

////////////

type Libp2p struct {

}

// var _ = regme(&Libp2p{})

func (o *Libp2p) Start() error {
	return nil
}

func (o *Libp2p) Stop() error {
	return nil
}

func (o *Libp2p) Info() string {
	return "{}"
}

func MainLibp2p() {
	mainLibp2p()
}

//////


const (
	defaultListenPort = 9000
	p2pServiceNode    = 1
	p2pServiceChat    = 1 << 24

	RelayHopProtocol  = protocol.ID("/libp2p/circuit/relay/0.2.0/hop")
	RelayStopProtocol = protocol.ID("/libp2p/circuit/relay/0.2.0/stop")
)

type NATReachability int

const (
	NATUnknown NATReachability = iota
	NATPublic
	NATPrivate
)

func (n NATReachability) String() string {
	switch n {
	case NATPublic:
		return "Public"
	case NATPrivate:
		return "Private"
	default:
		return "Unknown"
	}
}

type Libp2pRelayStatus struct {
	StaticCandidates    int
	ConnectedSupporting int
	ListeningAddrs      int
	TargetRelays        int
	MinCandidates       int
	BootDelay           time.Duration
}

type Libp2pAddrInfo struct {
	Addr        multiaddr.Multiaddr
	IsRelay     bool
	IsPrivateIP bool
	IP          net.IP
}

type Libp2pFullStatus struct {
	NATStatus        NATReachability
	NATIndication    string
	AutoNATStatus    network.Reachability
	AutoNATReady     bool
	Relay            Libp2pRelayStatus
	HolePunching     bool
	PeerID           peer.ID
	PubkeyHex        string
	ActivePeers      int
	Discovered       int
	BootTime         time.Duration
	ListeningAddrs   []Libp2pAddrInfo
}

var libp2pBootstrap = []string{
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
	"/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
}


type Libp2pSeedResult struct {
	Addr    multiaddr.Multiaddr
	PeerID  peer.ID
	Success bool
	Err     string
}

type Libp2pBsPeerInfo struct {
	Addr          string
	PeerID        peer.ID
	Conn          network.Conn
	SupportsRelay bool
}

type Libp2pBootConfig struct {
	KeyFile    string
	ListenPort int
	Timeout    time.Duration
}

type Libp2pBootResult struct {
	Host          host.Host
	DHT           *dht.IpfsDHT
	PeerID        peer.ID
	PubkeyHex     string
	BootstrapOK   []Libp2pBsPeerInfo
	BootstrapNOK  []string
	RelayCount    int
	Discovered    int
	BootTime      time.Duration
	FullStatus    Libp2pFullStatus
}


func mainLibp2p() {
	resolveAllDNSAddrsInit()
	fmt.Println("=== DNSADDR 解析结果汇总 ===")
	fmt.Printf("[*] 原始 bootstrap 地址: %d 个\n", len(libp2pBootstrap))
	fmt.Printf("[*] 解析后的额外地址: %d 个\n", len(extraStaticRelays))
	fmt.Printf("[*] 总候选地址: %d 个\n", len(allStaticRelays))
	fmt.Println()

	if len(extraStaticRelays) > 0 {
		fmt.Println("[*] 解析后的地址列表:")
		for i, addr := range extraStaticRelays {
			fmt.Printf("  [%02d] %s\n", i+1, addr)
		}
	}
	fmt.Println()

	fs := flag.NewFlagSet("libp2p", flag.ContinueOnError)
	keyFile := fs.String("k", "key.txt", "keyring file")
	port := fs.Int("l", defaultListenPort, "TCP listen port")
	timeoutSec := fs.Int("t", 120, "bootstrap timeout (seconds)")
	fs.Parse(os.Args[1:])

	cfg := Libp2pBootConfig{
		KeyFile:    *keyFile,
		ListenPort: *port,
		Timeout:    time.Duration(*timeoutSec) * time.Second,
	}

	res, err := Libp2pBootstrap(context.Background(), cfg)
	if err != nil {
		panic(err)
	}

	printFullStatus(res.FullStatus)

	select {}
}


func Libp2pBootstrap(ctx context.Context, cfg Libp2pBootConfig) (*Libp2pBootResult, error) {
	start := time.Now()

	fmt.Println("=== Phase 1: Key Loading ===")
	kr, err := fedkey.LoadKeyRing(cfg.KeyFile, true)
	if err != nil {
		return nil, fmt.Errorf("load keyring: %w", err)
	}
	fmt.Println("[+] Loaded key from:", cfg.KeyFile)

	edPriv := kr.BTDHTKey()
	pubKey := edPriv.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pubKey)
	fmt.Printf("    My pubkey: %s...\n\n", pubHex[:32])

	bootCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	libp2pPriv, err := crypto.UnmarshalEd25519PrivateKey(edPriv)
	if err != nil {
		return nil, fmt.Errorf("unmarshal privkey: %w", err)
	}

	staticRelays := parseStaticRelays()
	fmt.Printf("[+] Parsed %d static relay candidates\n", len(staticRelays))

	listenAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", cfg.ListenPort))

	fmt.Println("=== Phase 1.5: Creating Host with Relay/AutoRelay/HolePunching ===")

	h, err := libp2p.New(
		libp2p.Identity(libp2pPriv),
		libp2p.ListenAddrs(listenAddr),
		libp2p.ResourceManager(myResourceManager()),

		libp2p.EnableRelay(),

		libp2p.EnableAutoRelayWithStaticRelays(
			staticRelays,
			autorelay.WithNumRelays(5),
			autorelay.WithMinCandidates(5),
			autorelay.WithBootDelay(60*time.Second),
		),

		libp2p.EnableHolePunching(),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.UserAgent("universal-connectivity/go-peer"),
	)
	if err != nil {
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}

	myID := h.ID()
	fmt.Printf("[+] Host created, Peer ID: %s\n", myID.String())
	fmt.Println("    [Relay]           Enabled")
	fmt.Println("    [AutoRelay]       Enabled (5 relays, 5 candidates, 60s boot delay)")
	fmt.Println("    [HolePunching]    Enabled")
	for _, addr := range h.Addrs() {
		fmt.Printf("    Listening: %s/p2p/%s\n", addr, myID)
	}
	fmt.Println()

	fmt.Println("=== Phase 2: Bootstrap Node Resolution ===")
	fmt.Printf("[*] Resolving %d bootstrap nodes...\n", len(libp2pBootstrap))

	bootstrapInfos := make([]peer.AddrInfo, 0, len(libp2pBootstrap))
	for _, addrStr := range libp2pBootstrap {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			fmt.Printf("  ✗ invalid multiaddr: %s\n", addrStr)
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			fmt.Printf("  ✗ failed to parse: %s\n", addrStr)
			continue
		}
		bootstrapInfos = append(bootstrapInfos, *ai)
		fmt.Printf("  ✓ %s → %s\n", ai.ID.ShortString(), ai.Addrs[0])
	}
	fmt.Printf("[+] %d bootstrap peers ready\n\n", len(bootstrapInfos))

	if len(bootstrapInfos) == 0 {
		return nil, fmt.Errorf("no valid bootstrap nodes")
	}

	fmt.Println("=== Phase 3: Connecting to Bootstrap Peers ===")
	fmt.Printf("[*] Connecting to %d bootstrap peers...\n", len(bootstrapInfos))

	var (
		oks   []Libp2pBsPeerInfo
		noks  []string
	)

	fmt.Println("=== Phase 4: DHT Bootstrap ===")
	fmt.Println("[*] Starting Kademlia DHT in server mode...")

	kadDHT, err := dht.New(bootCtx, h,
		dht.Mode(dht.ModeClient),
		dht.BootstrapPeers(bootstrapInfos...),
	)
	if err != nil {
		return nil, fmt.Errorf("create DHT: %w", err)
	}

	if err := kadDHT.Bootstrap(bootCtx); err != nil {
		fmt.Printf("  [!] DHT bootstrap warning: %v\n", err)
	}

	fmt.Println("[*] Waiting for DHT routing table to populate...")
	testCID := "libp2p-bootstrap-test"
	routingDiscovery := routing.NewRoutingDiscovery(kadDHT)
	discovery.Advertise(ctx, routingDiscovery, testCID)
	discoveredSet := make(map[peer.ID]struct{})
	var discoveredMu sync.Mutex

	if kadDHT.RoutingTable().Size() >= 3 {
	}

	findCtx, findCancel := context.WithTimeout(bootCtx, 10*time.Second)
	defer findCancel()
	peerChan, err := routingDiscovery.FindPeers(findCtx, testCID)
	if err == nil {
		for p := range peerChan {
			if p.ID == myID || p.ID == "" {
				continue
			}
			discoveredMu.Lock()
			discoveredSet[p.ID] = struct{}{}
			discoveredMu.Unlock()
		}
	}

	for _, conn := range h.Network().Conns() {
		discoveredSet[conn.RemotePeer()] = struct{}{}
	}

	discoveredCount := len(discoveredSet)
	fmt.Printf("[+] Total discovered: %d unique peers\n\n", discoveredCount)

	if false {
		pingService := ping.NewPingService(h)
		_ = pingService
	}

	relayAddrCount := 0
	fmt.Println("=== Phase 5: Go Online ===")
	fmt.Printf("[*] Node is now online. Press Ctrl+C to exit.\n")
	fmt.Printf("[*] Listening on:\n")
	for _, addr := range h.Addrs() {
		addrStr := addr.String()
		isRelay := false
		for _, proto := range addr.Protocols() {
			if proto.Name == "p2p-circuit" {
				isRelay = true
				break
			}
		}
		if isRelay {
			relayAddrCount++
			fmt.Printf("    [RELAY] %s/p2p/%s\n", addrStr, myID)
		} else {
			fmt.Printf("            %s/p2p/%s\n", addrStr, myID)
		}
	}
	fmt.Println()

	fmt.Printf("[*] Connected peers:\n")
	for i, p := range oks {
		short := p.PeerID.ShortString()
		relayMark := ""
		if p.SupportsRelay {
			relayMark = " [RELAY]"
		}
		fmt.Printf("  [%02d] %s  %s%s\n", i+1, short, p.Addr, relayMark)
	}
	fmt.Println()

	fmt.Println("=== Phase 5.5: Waiting for AutoNAT ===")
	fmt.Println("[*] Waiting for AutoNAT to detect NAT status...")

	autoNATStatus := network.ReachabilityUnknown
	autoNATReady := false

	fmt.Println("    [AutoNAT] Waiting up to 60 seconds for reachability detection...")
	autoNATStatus, autoNATReady = waitForAutoNAT(h, 60*time.Second)
	if autoNATReady {
		fmt.Printf("    [AutoNAT] Detected: %s\n", autoNATStatus)
	} else {
		fmt.Printf("    [AutoNAT] Timeout, current status: %s\n", autoNATStatus)
	}
	fmt.Println()

	natStatus, natIndication := detectNATReachability(h)
	relayStatus := collectRelayStatus(h, oks)
	listeningAddrs := collectListeningAddrs(h)

	fullStatus := Libp2pFullStatus{
		NATStatus:        natStatus,
		NATIndication:    natIndication,
		AutoNATStatus:    autoNATStatus,
		AutoNATReady:     autoNATReady,
		Relay:            relayStatus,
		HolePunching:     true,
		PeerID:           myID,
		PubkeyHex:        pubHex,
		ActivePeers:      len(oks),
		Discovered:       discoveredCount,
		BootTime:         time.Since(start),
		ListeningAddrs:   listeningAddrs,
	}

	return &Libp2pBootResult{
		Host:         h,
		DHT:          kadDHT,
		PeerID:       myID,
		PubkeyHex:    pubHex,
		BootstrapOK:  oks,
		BootstrapNOK: noks,
		RelayCount:   0,
		Discovered:   discoveredCount,
		BootTime:     time.Since(start),
		FullStatus:   fullStatus,
	}, nil
}
