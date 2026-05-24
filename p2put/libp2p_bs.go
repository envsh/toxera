////go:build libp2p

package p2put

import (
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	// "flag"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/envsh/toxera/fedkey"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	discovery2 "github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/libp2p/go-libp2p/core/metrics"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
	discovery "github.com/libp2p/go-libp2p/p2p/discovery/util"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p-pubsub"
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

func MainLibp2p(cfg Config) {
	mainLibp2p(cfg)
}

//////


const (
	defaultListenPort = 4001
	p2pServiceNode    = 1
	p2pServiceChat    = 1 << 24

	RelayHopProtocol  = protocol.ID("/libp2p/circuit/relay/0.2.0/hop")
	RelayStopProtocol = protocol.ID("/libp2p/circuit/relay/0.2.0/stop")

	minPeerCount = 16
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

var peerstorePath = "/tmp/libp2p_peerstore.json"
var savedPeerstoreSum string

func init() {
	log.SetFlags((log.Flags() | log.Lshortfile | log.Ltime) &^ log.Ldate)
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

type Libp2pBootResult struct {
	Host          host.Host
	DHT           *dht.IpfsDHT
	PSO           *pubsub.PubSub
	Bwc           metrics.Reporter
	PeerID        peer.ID
	PubkeyHex     string
	BootTime      time.Duration
	NATStatus     network.Reachability
	Discovery     *routing.RoutingDiscovery
}

// 缓存文件格式: map[string][]string (原始地址 → 解析后的地址列表)
var dnsaddrsResultFile = "/tmp/libp2p_bootstrap_dnsaddrs.json"
var dnsaddrsCacheDur = 4*3600*time.Second

func loadOrResolveAllDNSAddrs() {
	if data, err := os.ReadFile(dnsaddrsResultFile); err == nil {
		var info os.FileInfo
		info, err = os.Stat(dnsaddrsResultFile)
		if err == nil && time.Since(info.ModTime()) < dnsaddrsCacheDur {
			var resolved map[string][]string
			if err = json.Unmarshal(data, &resolved); err == nil {
				for _, addrs := range resolved {
					for _, addr := range addrs {
						if strings.Contains(addr, ":") ||
							strings.Contains(addr, "/udp/") {
							continue
						}
						if !containsAddr(extraStaticRelays, addr) {
							extraStaticRelays = append(extraStaticRelays, addr)
						}
					}
				}
				return
			}
		}
	}

	ctx := context.Background()
	resolved := resolveAllDNSAddrsQuiet(ctx, libp2pBootstrap)

	if data, err := json.Marshal(resolved); err == nil {
		err = os.WriteFile(dnsaddrsResultFile, data, 0644)
		if err != nil { panic(err) }
	}

	for _, addrs := range resolved {
		for _, addr := range addrs {
			if strings.Contains(addr, ":") ||
				strings.Contains(addr, "/udp/") {
				continue
			}
			if !containsAddr(extraStaticRelays, addr) {
				extraStaticRelays = append(extraStaticRelays, addr)
			}
		}
	}
}

func mainLibp2p(cfg Config) {
	fmt.Println("=== DNSADDR 解析结果汇总 ===")
	fmt.Printf("[*] 原始 bootstrap 地址: %d 个\n", len(libp2pBootstrap))
	// resolveAllDNSAddrsInit()
	loadOrResolveAllDNSAddrs()
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

	// fs := flag.NewFlagSet("libp2p", flag.ContinueOnError)
	// keyFile := fs.String("k", "key.txt", "keyring file")
	// port := fs.Int("l", 0, "TCP listen port - 4001 or random")
	// fs.Parse(os.Args[1:])

	// cfg := Libp2pBootConfig{
	// 	KeyFile:    *keyFile,
	// 	ListenPort: *port,
	// }

	if cfg.Fset.Parsed() {
		log.Println(*cfg._KeyFile)
		log.Println(*cfg._ListenPort)
		cfg.KeyFile = *cfg._KeyFile
		cfg.ListenPort = *cfg._ListenPort
	}
	currConfig = cfg

	res, err := Libp2pBootstrap(context.Background(), currConfig)
	if err != nil {
		panic(err)
	}

	myDumpBoot(res.Host, res.DHT)
	bootres = res

	loadPeerstore(res.Host, peerstorePath)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := savePeerstore(peerstorePath); err != nil {
				log.Printf("[peerstore] save error: %v", err)
			}
			cleanPeerstore()
		}
	}()

	go myDiscoveryV3()
	//go myDiscoveryV2()

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

func Libp2pBootstrap(ctx context.Context, cfg Config) (*Libp2pBootResult, error) {
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

		/*
		libp2p.EnableAutoRelay(
			autorelay.WithNumRelays(3),
			autorelay.WithMinCandidates(3),
			autorelay.WithBootDelay(30*time.Second),
		),
		*/

		libp2p.EnableAutoRelayWithStaticRelays(
			dht.GetDefaultBootstrapPeerAddrInfos(),
			autorelay.WithNumRelays(2),
			autorelay.WithMinCandidates(3),
			autorelay.WithBootDelay(30*time.Second),
		),

		// static relay seems fixed relay, not auto find more relays
		/*libp2p.EnableAutoRelayWithStaticRelays(
			staticRelays,
			autorelay.WithNumRelays(5),
			autorelay.WithMinCandidates(5),
			autorelay.WithBootDelay(60*time.Second),
		),
		*/

		libp2p.EnableHolePunching(),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(websocket.New),
		libp2p.UserAgent("universal-connectivity/go-peer"),

		libp2p.BandwidthReporter(bwc),

		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			var out []multiaddr.Multiaddr
			for _, a := range addrs {
				if isRelayAddr(a) {
					out = append(out, a)
				} else {
					ip4 := false
					tcp := false
					for _, p := range a.Protocols() {
						if p.Code == multiaddr.P_IP4 { ip4 = true }
						if p.Code == multiaddr.P_TCP { tcp = true }
					}
					if ip4 && tcp {
						out = append(out, a)
					}
				}
			}
			if len(addrs) != len(out) {
				log.Println("addrs filter", len(addrs), "=>", len(out))
			}
			return out
		}),
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

	bootCtx, cancel := context.WithTimeout(ctx, 32*time.Second)
	defer cancel()
	kadDHT, err := dht.New(bootCtx, h,
		dht.Mode(dht.ModeClient),
		dht.BootstrapPeers(bootstrapInfos...),
		dht.DisableAutoRefresh(),             // ← 加这一行
		dht.Concurrency(1),                   // ← 并发从 10 降到 3
		dht.RoutingTableRefreshPeriod(15 * time.Minute),  // ← 再加这行, 默认10min
	)
	if err != nil {
		return nil, fmt.Errorf("create DHT: %w", err)
	}

	if err := kadDHT.Bootstrap(bootCtx); err != nil {
		fmt.Printf("  [!] DHT bootstrap warning: %v\n", err)
	}

	fmt.Println("[*] Waiting for DHT routing table to populate...")
	routingDiscovery := routing.NewRoutingDiscovery(kadDHT)
	testCID := currConfig.HubName // "libp2p-bootstrap-test"
	discovery.Advertise(ctx, routingDiscovery, testCID) // broadcast self

	if false {
		pingService := ping.NewPingService(h)
		_ = pingService
	}

	fmt.Println("=== Phase 4: Go Online ===")
	fmt.Printf("[*] Node is now online. Press Ctrl+C to exit.\n")

	myEventSuber(h, new(event.EvtLocalReachabilityChanged),
		new(event.EvtPeerConnectednessChanged),
		new(event.EvtLocalAddressesUpdated))
	pso, err := pubsub.NewGossipSub(context.Background(), h,
		pubsub.WithPeerExchange(true),
		// half default
		pubsub.WithGossipSubParams(myGossipSubParams()),
		pubsub.WithPeerScore(
			&pubsub.PeerScoreParams{
				SkipAtomicValidation: true,
				AppSpecificScore:     func(peer.ID) float64 { return 0 },
				DecayInterval:        time.Second,
				DecayToZero:          0.01,
			},
			&pubsub.PeerScoreThresholds{
				SkipAtomicValidation: true,
			},
		),
		pubsub.WithPeerScoreInspect(
			func(scores map[peer.ID]float64) {
				for pid, s := range scores {
					log.Printf("[score] %s: %.2f", pid.ShortString(), s)
				}
			},
			30*time.Second,
		),
	)
	if err != nil { log.Println(err) }

	fmt.Println("=== Phase 4.5: Waiting for AutoNAT ===")

	log.Println("bootstrap ret...")
	return &Libp2pBootResult{
		Host:      h,
		DHT:       kadDHT,
		PSO:       pso,
		Bwc:       bwc,
		PeerID:    myID,
		PubkeyHex: pubHex,
		BootTime:  time.Since(start),
		Discovery: routingDiscovery,
	}, nil
}

// only find HubName
func myDiscoveryV3() {
	rd := bootres.Discovery
	dht := bootres.DHT
	tag := currConfig.HubName
	sec100 := 100*time.Second
	known := make(map[string]peer.AddrInfo)
	for i := 0 ;; i++{
		time.Sleep(3*time.Second)
		log.Println("start DHT finding...", i)
		result := findAndConnect(tag, rd, 0)
		for _, p := range result {
			known[p.ID.String()] = p
		}
		log.Println("found peers count:", len(known), i)
		if i < 3 && len(result) == 0 {
			time.Sleep(time.Duration(2+i)*time.Second)
			continue
		}

		btime := time.Now()
		var err error
		var p2 peer.AddrInfo
		time.Sleep(3*time.Second)
		// random select 3 and try connect
		for j := 0; ; j++ {
			if time.Since(btime) > sec100 {
				break
			}
			time.Sleep(3*time.Second)
			for _, p := range known {
				if IsPeerInAnyTopic(p.ID) || IsPeerConnected(p.ID) {
					continue
				}
				err = tryConnect(p)
				p2 = p
				if err == nil { break }

				time.Sleep(time.Second)
				// findAndConnect(p2.ID.String(), rd, 1)
				addrinfo, err := dht.FindPeer(context.Background(), p2.ID)
				_ = addrinfo
				if err != nil {
				}
				break
			}
			time.Sleep(13*time.Second)
		}
		if err != nil {
			// time.Sleep(5*time.Second)
			// findAndConnect(p2.ID.String(), rd, 1)
			// addrinfo, err := dht.FindPeer(context.Background(), p2.ID)
			// _ = addrinfo
			// if err != nil {
			// }
		}

		dur := time.Since(btime)
		if dur > sec100 {
			continue
		}
	    time.Sleep(sec100-dur)
	}
}

func myDiscoveryV2ddd() {
	type tagState struct {
		nextAt time.Time
		busy   bool
	}

	rd := bootres.Discovery
	var tagStates sync.Map

	for {
		time.Sleep(300 * time.Millisecond)
		discoveryTags.Range(func(key, _ any) bool {
			tag := key.(string)
			st, loaded := tagStates.Load(tag)
			if !loaded {
				h := fnv.New32a()
				h.Write([]byte(tag))
				phase := time.Duration(h.Sum32()%20) * time.Second
				st = &tagState{nextAt: time.Now().Add(-20*time.Second + phase)}
				tagStates.Store(tag, st)
			}
			s := st.(*tagState)
			if s.busy || time.Since(s.nextAt) < 0 {
				return true
			}
			s.busy = true
			s.nextAt = time.Now().Add(30 * time.Second)
			go func(tag string) {
				findAndConnect(tag, rd, 0)
				if v, _ := tagStates.Load(tag); v != nil {
					v.(*tagState).busy = false
				}
			}(tag)
			return true
		})
	}
}

func findAndConnect(tag string, rd *routing.RoutingDiscovery, limit int) []peer.AddrInfo {
	findCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
    // 连接够多了，不查
    if len(bootres.Host.Network().Conns()) > 9 {
        // return
    }

	if limit <= 0 { limit = 5 }
	peerChan, err := rd.FindPeers(findCtx, tag,
				discovery2.Limit(limit),          // ← 只取 10 个结果
			)
	if err != nil {
		return nil
	}
	var found []peer.AddrInfo
	for p := range peerChan {
		if p.ID == bootres.Host.ID() || p.ID == "" {
			continue
		}
		found = append(found, p)
		if bootres.Host.Network().Connectedness(p.ID) != network.Connected {
            // 每连一个前再检查一次，防止批量连
            // if len(bootres.Host.Network().Conns()) > 12 { break }

			// 每两个连接之间间隔 2s
			time.Sleep(3 * time.Second)
			dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
			t0 := time.Now()
			if err := bootres.Host.Connect(dialCtx, p); err != nil {
				log.Printf("[discovery] connect %s: %v", p.ID.ShortString(), err)
			} else {
				elapsed := time.Since(t0)
				log.Printf("[discovery] connected to %s in %v", p.ID.ShortString(), elapsed)
				updatePeerLatency(p.ID, elapsed)
			}
			dialCancel()
		}
	}
	return found
}

func tryConnect(p peer.AddrInfo) error {
	if bootres.Host.Network().Connectedness(p.ID) == network.Connected {
		return nil
	}

	// 每连一个前再检查一次，防止批量连
	// if len(bootres.Host.Network().Conns()) > 12 { break }

	// 每两个连接之间间隔 2s
	time.Sleep(3 * time.Second)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	t0 := time.Now()
	err := bootres.Host.Connect(dialCtx, p)
	if err != nil {
		log.Printf("[discovery] connect %s: %v", p.ID.ShortString(), err)
	} else {
		elapsed := time.Since(t0)
		log.Printf("[discovery] connected to %s in %v", p.ID.ShortString(), elapsed)
		updatePeerLatency(p.ID, elapsed)
	}
	dialCancel()
	return err
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
			rawChan <- evt

			switch e := evt.(type) {
			case event.EvtLocalReachabilityChanged:
				bootres.NATStatus = e.Reachability
			case event.EvtPeerConnectednessChanged:
				handlePeerConnectednessChanged(e)
			case event.EvtLocalAddressesUpdated:
				go func(){
					// bootres.DHT.RefreshRoutingTable()
					// discovery.Advertise(context.Background(), bootres.Discovery, currConfig.HubName)
				}()
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

func savePeerstore(path string) error {
	if bootres == nil || bootres.Host == nil {
		return fmt.Errorf("peerstore not ready")
	}
	ps := bootres.Host.Peerstore()
	m := make(map[string][]string)
	for _, p := range ps.Peers() {
		addrs := ps.Addrs(p)
		if len(addrs) == 0 {
			continue
		}
		var as []string
		for _, a := range addrs {
			ip := extractIPFromAddr(a)
			if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
				continue
			}
			s := a.String()
			if strings.Contains(s, "/ip6/") ||
				strings.Contains(s, "/udp/") ||
				strings.Contains(s, "/quic") ||
				strings.Contains(s, "webrtc") ||
				strings.Contains(s, "/dns/") {
				continue
			}
			as = append(as, s)
		}
		m[p.String()] = as
	}
	if len(m) < minPeerCount {
		return nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	cs := fmt.Sprintf("%x", md5.Sum(raw))
	if cs == savedPeerstoreSum {
		return nil
	}
	savedPeerstoreSum = cs

	if err := os.WriteFile(path, raw, 0644); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	log.Printf("[peerstore] saved %d peers", len(m))
	return nil
}

func loadPeerstore(h host.Host, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read: %w", err)
	}
	var m map[string][]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	for idStr, addrs := range m {
		pid, err := peer.Decode(idStr)
		if err != nil {
			continue
		}
		var mas []multiaddr.Multiaddr
		for _, a := range addrs {
			ma, err := multiaddr.NewMultiaddr(a)
			if err != nil {
				continue
			}
			mas = append(mas, ma)
		}
		if len(mas) > 0 {
			h.Peerstore().AddAddrs(pid, mas, peerstore.PermanentAddrTTL)
		}
	}
	log.Printf("[peerstore] loaded %d peers from %s", len(m), path)
	return nil
}

func cleanPeerstore() {
	if bootres == nil || bootres.Host == nil {
		return
	}
	h := bootres.Host
	ps := h.Peerstore()
	if len(ps.Peers()) < minPeerCount {
		return
	}
	for _, pid := range ps.Peers() {
		if isBootstrapPeer(pid) {
			continue
		}
		if h.Network().Connectedness(pid) != network.Connected {
			if aps, ok := ps.(peerstore.AddrBook); ok {
				aps.ClearAddrs(pid)
			}
			ps.RemovePeer(pid)
		}
	}
}
