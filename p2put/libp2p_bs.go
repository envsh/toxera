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
	"log"
	// "sync"
	"time"
	// "strings"
	// "reflect"

	"github.com/envsh/toxera/fedkey"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/libp2p/go-libp2p/core/metrics"
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
	defaultListenPort = 4001
	p2pServiceNode    = 1
	p2pServiceChat    = 1 << 24

	RelayHopProtocol  = protocol.ID("/libp2p/circuit/relay/0.2.0/hop")
	RelayStopProtocol = protocol.ID("/libp2p/circuit/relay/0.2.0/stop")
)

type Libp2pAddrInfo struct {
	Addr        multiaddr.Multiaddr
	IsRelay     bool
	IsPrivateIP bool
	IP          net.IP
}


var libp2pBootstrap = []string{
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
	"/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
}

func init() {
	if len(libp2pBootstrap) != len(dht.DefaultBootstrapPeers) {
		log.Println("Need update bootstrap data")
	}
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
}

type Libp2pBootResult struct {
	Host          host.Host
	DHT           *dht.IpfsDHT
	Bwc           metrics.Reporter
	PeerID        peer.ID
	PubkeyHex     string
	BootTime      time.Duration

	NATStatus        network.Reachability
}


func mainLibp2p() {
	fmt.Println("=== DNSADDR 解析结果汇总 ===")
	fmt.Printf("[*] 原始 bootstrap 地址: %d 个\n", len(libp2pBootstrap))
	resolveAllDNSAddrsInit()
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
	port := fs.Int("l", 0, "TCP listen port - 4001 or random")
	fs.Parse(os.Args[1:])

	cfg := Libp2pBootConfig{
		KeyFile:    *keyFile,
		ListenPort: *port,
	}

	res, err := Libp2pBootstrap(context.Background(), cfg)
	if err != nil {
		panic(err)
	}

	myDumpBoot(res.Host, res.DHT)
	bootres = res

	select {}
}

// []string => []peer.AddrInfo
// use for DHT
func filterConvertBootstrapInfos() []peer.AddrInfo {
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
	return bootstrapInfos
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

	libp2pPriv, err := crypto.UnmarshalEd25519PrivateKey(edPriv)
	if err != nil {
		return nil, fmt.Errorf("unmarshal privkey: %w", err)
	}

	staticRelays := parseStaticRelays()
	fmt.Printf("[+] Parsed %d static relay candidates\n", len(staticRelays))

	listenAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", cfg.ListenPort))

	fmt.Println("=== Phase 1.5: Creating Host with Relay/AutoRelay/HolePunching ===")

	bwc := metrics.NewBandwidthCounter()

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

		libp2p.BandwidthReporter(bwc),
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

	bootstrapInfos := filterConvertBootstrapInfos()

	fmt.Printf("[+] %d bootstrap peers ready\n\n", len(bootstrapInfos))
	if len(bootstrapInfos) == 0 {
		return nil, fmt.Errorf("no valid bootstrap nodes")
	}

	fmt.Println("=== Phase 3: DHT Bootstrap ===")
	fmt.Println("[*] Starting Kademlia DHT in client mode...")

	bootCtx, cancel := context.WithTimeout(ctx, 123*time.Second)
	defer cancel()
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
	routingDiscovery := routing.NewRoutingDiscovery(kadDHT)
	testCID := "libp2p-bootstrap-test"
	discovery.Advertise(ctx, routingDiscovery, testCID) // broadcast self

	if false {
		pingService := ping.NewPingService(h)
		_ = pingService
	}

	fmt.Println("=== Phase 4: Go Online ===")
	fmt.Printf("[*] Node is now online. Press Ctrl+C to exit.\n")

	myEventSuber(h, new(event.EvtLocalReachabilityChanged),
		new(event.EvtPeerConnectednessChanged))

	fmt.Println("=== Phase 4.5: Waiting for AutoNAT ===")

	log.Println("bootstrap ret...")
	return &Libp2pBootResult{
		Host:         h,
		DHT:          kadDHT,
		Bwc:          bwc,
		PeerID:       myID,
		PubkeyHex:    pubHex,
		BootTime:     time.Since(start),
	}, nil
}

func myDiscoveryV1 (bootCtx context.Context, routingDiscovery *routing.RoutingDiscovery, testCID string, myID peer.ID) (discoveredSet map[peer.ID]struct{}) {
	findCtx, findCancel := context.WithTimeout(bootCtx, 10*time.Second)
	defer findCancel()
	peerChan, err := routingDiscovery.FindPeers(findCtx, testCID)
	if err == nil {
		for p := range peerChan {
			if p.ID == myID || p.ID == "" {
				continue
			}
			discoveredSet[p.ID] = struct{}{}
		}
	} else {
		log.Println(err)
	}
	return
}

// new(event.EvtLocalReachabilityChanged)...
func myEventSuber(h host.Host, evts ...any) {
	// sub, err := h.EventBus().Subscribe(new(event.EvtLocalReachabilityChanged))
	sub, err := h.EventBus().Subscribe(evts)
	if err != nil { panic(err) }
	go func() {
		for evt := range sub.Out() {
			log.Printf("<< %+v %v\n", evt, "") // reflect.TypeOf(evt)
			switch e := evt.(type) {
			case event.EvtLocalReachabilityChanged:
				// evt.Reachability: network.Reachability
				switch e.Reachability {
				case network.ReachabilityPublic:   // 公网可达
				case network.ReachabilityPrivate:  // NAT 后面
				case network.ReachabilityUnknown:  // 未知（探测中）
				}
				bootres.NATStatus = e.Reachability
			case event.EvtPeerConnectednessChanged:

			}
		}
	}()
}

func myDumpBoot(h host.Host, dht *dht.IpfsDHT) {

	dhtsz := dht.RoutingTable().Size()
	conns := GetCurrConns(h)

	log.Printf("conns %v, dht %v", len(conns), dhtsz)
	log.Println()
}

func GetCurrConns (h host.Host) (discoveredSet map[peer.ID]struct{}) {
	for _, conn := range h.Network().Conns() {
		discoveredSet[conn.RemotePeer()] = struct{}{}
	}
	return discoveredSet
}
