//go:build libp2p

package fedboot

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
	"strings"

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
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	discovery "github.com/libp2p/go-libp2p/p2p/discovery/util"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/multiformats/go-multiaddr"
)

////////////

type Libp2p struct {

}

var _ = regme(&Libp2p{})

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

var extraStaticRelays []string

func init() {
	resolveAllDNSAddrsInit()
}
func resolveAllDNSAddrsInit() {
	fmt.Println("=== [init] DNSADDR 预解析 ===")
	ctx := context.Background()
	btime := time.Now()

	resolvedMap := resolveAllDNSAddrsQuiet(ctx, libp2pBootstrap)

	for _, addrs := range resolvedMap {
		for _, addr := range addrs {
			if strings.Contains(addr, ":") || 
				strings.Contains(addr, "/udp/") || strings.Contains(addr, "/wss/") {
				continue
			}
			if !containsAddr(extraStaticRelays, addr) {
				extraStaticRelays = append(extraStaticRelays, addr)
			}
		}
	}

	fmt.Printf("[*] 预解析完成，添加了 %d 个解析后的地址, %v\n", len(extraStaticRelays), time.Since(btime))
	fmt.Println()
}

func resolveAllDNSAddrsQuiet(ctx context.Context, addrStrs []string) map[string][]string {
	result := make(map[string][]string)

	for _, addrStr := range addrStrs {
		resolved, _ := resolveDNSAddrFully(ctx, addrStr)
		if len(resolved) > 0 {
			result[addrStr] = resolved
		}
	}

	return result
}

func containsAddr(slice []string, addr string) bool {
	for _, a := range slice {
		if a == addr {
			return true
		}
	}
	return false
}

var allStaticRelays = append(libp2pBootstrap, extraStaticRelays...)

func resolveDNSAddrFully(ctx context.Context, addrStr string) ([]string, []error) {
	var resolved []string
	var errs []error

	maddr, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		errs = append(errs, fmt.Errorf("parse multiaddr: %w", err))
		return nil, errs
	}

	results, err := madns.Resolve(ctx, maddr)
	if err != nil {
		errs = append(errs, fmt.Errorf("dnsaddr resolve: %w", err))
	}

	for _, r := range results {
		rStr := r.String()

		if madns.Matches(r) {
			subResolved, subErrs := resolveDNSAddrFully(ctx, rStr)
			resolved = append(resolved, subResolved...)
			errs = append(errs, subErrs...)
			continue
		}

		if hasDNSComponent(r) {
			subResolved, subErrs := resolveDNSAddrFully(ctx, rStr)
			if len(subResolved) > 0 {
				resolved = append(resolved, subResolved...)
			} else {
				resolved = append(resolved, rStr)
			}
			errs = append(errs, subErrs...)
			continue
		}

		resolved = append(resolved, rStr)
	}

	return resolved, errs
}

func hasDNSComponent(maddr multiaddr.Multiaddr) bool {
	for _, proto := range maddr.Protocols() {
		if proto.Name == "dns4" || proto.Name == "dns6" || proto.Name == "dns" || proto.Name == "dnsaddr" {
			return true
		}
	}
	return false
}

func resolveAllDNSAddrs(ctx context.Context, addrStrs []string) map[string][]string {
	result := make(map[string][]string)

	for _, addrStr := range addrStrs {
		resolved, errs := resolveDNSAddrFully(ctx, addrStr)
		if len(resolved) > 0 {
			result[addrStr] = resolved
		}
		if len(errs) > 0 {
			fmt.Printf("  [!] 解析 %s 时发生错误:\n", addrStr)
			for _, err := range errs {
				fmt.Printf("      - %v\n", err)
			}
		}
	}

	return result
}

func printDNSResolutionResult(resolved map[string][]string) {
	fmt.Println()
	fmt.Println("=== DNSADDR 解析结果 ===")
	fmt.Println()

	for original, addrs := range resolved {
		fmt.Printf("📌 原始地址: %s\n", original)
		if len(addrs) == 0 {
			fmt.Println("   ❌ 解析失败，无结果")
		} else {
			fmt.Printf("   ✅ 解析到 %d 个地址:\n", len(addrs))
			for i, addr := range addrs {
				fmt.Printf("      [%02d] %s\n", i+1, addr)
			}
		}
		fmt.Println()
	}

	fmt.Println("=========================")
	fmt.Println()
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

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	if ip.IsUnspecified() {
		return true
	}

	if ip.IsLoopback() {
		return true
	}

	if ip.IsLinkLocalUnicast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		}
		return false
	}

	if ip6 := ip.To16(); ip6 != nil {
		if ip6[0] == 0xfe && ip6[1] >= 0x80 && ip6[1] <= 0xbf {
			return true
		}
		if ip6[0] == 0xfc || ip6[0] == 0xfd {
			return true
		}
	}

	return false
}

func isRelayAddr(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Name == "p2p-circuit" {
			return true
		}
	}
	return false
}

func extractIPFromAddr(addr multiaddr.Multiaddr) net.IP {
	if addr == nil {
		return nil
	}

	for _, proto := range addr.Protocols() {
		if proto.Name == "ip4" || proto.Name == "ip6" {
			ipStr, err := addr.ValueForProtocol(proto.Code)
			if err == nil {
				return net.ParseIP(ipStr)
			}
		}
	}
	return nil
}

func detectNATReachability(h host.Host) (NATReachability, string) {
	addrs := h.Addrs()

	hasPublicIP := false
	hasRelayAddr := false
	hasPrivateIP := false

	for _, addr := range addrs {
		if isRelayAddr(addr) {
			hasRelayAddr = true
			continue
		}

		ip := extractIPFromAddr(addr)
		if ip == nil || ip.IsUnspecified() {
			continue
		}

		if isPrivateIP(ip) {
			hasPrivateIP = true
		} else {
			hasPublicIP = true
		}
	}

	if hasRelayAddr && hasPrivateIP && !hasPublicIP {
		return NATPrivate, "Only private IPs + relay addresses detected (AutoRelay active)"
	}

	if hasPublicIP && !hasRelayAddr {
		return NATPublic, "Public IP detected, no relay addresses needed"
	}

	if hasPublicIP && hasRelayAddr {
		return NATPublic, "Public IP detected (relay addresses may exist for incoming connections)"
	}

	if hasPrivateIP && !hasPublicIP && !hasRelayAddr {
		return NATUnknown, "Private IPs only, but no relay addresses yet (AutoRelay may still be initializing)"
	}

	return NATUnknown, "Could not determine NAT status from available addresses"
}

func collectRelayStatus(h host.Host, connectedPeers []Libp2pBsPeerInfo) Libp2pRelayStatus {
	relayAddrCount := 0
	for _, addr := range h.Addrs() {
		if isRelayAddr(addr) {
			relayAddrCount++
		}
	}

	supportingCount := 0
	for _, p := range connectedPeers {
		if p.SupportsRelay {
			supportingCount++
		}
	}

	return Libp2pRelayStatus{
		StaticCandidates:    len(allStaticRelays),
		ConnectedSupporting: supportingCount,
		ListeningAddrs:      relayAddrCount,
		TargetRelays:        5,
		MinCandidates:       8,
		BootDelay:           60 * time.Second,
	}
}

func collectListeningAddrs(h host.Host) []Libp2pAddrInfo {
	var addrs []Libp2pAddrInfo

	for _, addr := range h.Addrs() {
		isRelay := isRelayAddr(addr)
		ip := extractIPFromAddr(addr)
		isPrivateIPVal := false

		if ip != nil {
			isPrivateIPVal = isPrivateIP(ip)
		}

		addrs = append(addrs, Libp2pAddrInfo{
			Addr:        addr,
			IsRelay:     isRelay,
			IsPrivateIP: isPrivateIPVal,
			IP:          ip,
		})
	}

	return addrs
}

func waitForAutoNAT(h host.Host, maxWait time.Duration) (network.Reachability, bool) {
	sub, err := h.EventBus().Subscribe(new(event.EvtLocalReachabilityChanged))
	if err != nil {
		return network.ReachabilityUnknown, false
	}
	defer sub.Close()

	deadline := time.Now().Add(maxWait)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case e := <-sub.Out():
			evt, ok := e.(event.EvtLocalReachabilityChanged)
			if ok && evt.Reachability != network.ReachabilityUnknown {
				return evt.Reachability, true
			}
		case <-ticker.C:
			continue
		}
	}

	return network.ReachabilityUnknown, false
}

func printFullStatus(status Libp2pFullStatus) {
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  ✅ LIBP2P ONLINE")
	fmt.Println("========================================")

	fmt.Println()
	fmt.Println("  🔍 NAT / Reachability Status:")
	fmt.Println()
	fmt.Println("  [方式 A] 内置 AutoNAT:")
	if status.AutoNATReady {
		fmt.Printf("     Status:          %s\n", status.AutoNATStatus)
	} else {
		fmt.Printf("     Status:          %s (未完成检测)\n", status.AutoNATStatus)
		fmt.Println("        Note: AutoNAT may still be probing. Check again later.")
	}

	fmt.Println()
	fmt.Println("  [方式 B] 自定义地址分析:")
	fmt.Printf("     Status:          %s\n", status.NATStatus)
	fmt.Printf("     Indication:      %s\n", status.NATIndication)

	fmt.Println()
	fmt.Println("  📋 Detailed Listening Addrs:")
	if len(status.ListeningAddrs) == 0 {
		fmt.Println("     (No addresses)")
	} else {
		for i, info := range status.ListeningAddrs {
			addrStr := info.Addr.String()
			typeStr := ""
			if info.IsRelay {
				typeStr = "[RELAY]"
			} else if info.IP != nil {
				if info.IsPrivateIP {
					typeStr = "[PRIVATE]"
				} else {
					typeStr = "[PUBLIC]"
				}
			} else {
				typeStr = "[UNKNOWN]"
			}
			fmt.Printf("  [%02d] %s %s\n", i+1, typeStr, addrStr)
		}
	}

	fmt.Println()
	fmt.Println("  🔄 Relay Status:")
	fmt.Printf("     Enabled:         Yes\n")
	fmt.Printf("     Static Candidates:%d\n", status.Relay.StaticCandidates)
	fmt.Printf("     Target Relays:   %d\n", status.Relay.TargetRelays)
	fmt.Printf("     Min Candidates:  %d\n", status.Relay.MinCandidates)
	fmt.Printf("     Boot Delay:      %s\n", status.Relay.BootDelay)
	fmt.Printf("     Connected peers supporting relay: %d\n", status.Relay.ConnectedSupporting)
	fmt.Printf("     Relay listen addrs: %d\n", status.Relay.ListeningAddrs)

	if status.Relay.ListeningAddrs == 0 {
		fmt.Println()
		fmt.Println("     ⚠️  Note: AutoRelay may still be initializing")
		fmt.Println("        Boot delay is 60s to allow DHT discovery first")
		fmt.Println("        Relay addresses will appear once relays are selected")
	}

	fmt.Println()
	fmt.Println("  👊 HolePunching Status:")
	fmt.Printf("     Enabled:         Yes\n")
	fmt.Printf("     Note:            Will attempt direct connections when possible\n")
	fmt.Printf("                    Requires relayed connection as prerequisite\n")

	fmt.Println()
	fmt.Println("  📊 Network Info:")
	fmt.Printf("     Peer ID:         %s\n", status.PeerID.String())
	fmt.Printf("     Pubkey:          %s...\n", status.PubkeyHex)
	if len(status.PubkeyHex) > 32 {
		fmt.Printf("                    %s...\n", status.PubkeyHex[32:64])
	}
	fmt.Printf("     Active Peers:    %d\n", status.ActivePeers)
	fmt.Printf("     Discovered:      %d peers\n", status.Discovered)
	fmt.Printf("     Boot Time:       %s\n", status.BootTime)

	fmt.Println()
	fmt.Println("========================================")
}

func mainLibp2p() {
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

func parseStaticRelays() []peer.AddrInfo {
	var relays []peer.AddrInfo
	for _, addrStr := range allStaticRelays {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		relays = append(relays, *ai)
	}
	return relays
}

func supportsRelayHop(ctx context.Context, h host.Host, p peer.ID) bool {
	protocols, err := h.Peerstore().GetProtocols(p)
	if err == nil {
		for _, proto := range protocols {
			if protocol.ID(proto) == RelayHopProtocol {
				return true
			}
		}
	}

	streamCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, err := h.NewStream(streamCtx, p, RelayHopProtocol)
	if err != nil {
		return false
	}
	s.Close()
	return true
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
		oksMu sync.Mutex
		noksMu sync.Mutex
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 10)
	)

	for i := range bootstrapInfos {
		ai := &bootstrapInfos[i]
		wg.Add(1)
		go func(info *peer.AddrInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			connCtx, connCancel := context.WithTimeout(bootCtx, 25*time.Second)
			defer connCancel()
			btime := time.Now()

			err := h.Connect(connCtx, *info)
			if err != nil {
				noksMu.Lock()
				noks = append(noks, info.ID.String())
				noksMu.Unlock()
				fmt.Printf("  ✗ %s → %v\n", info.ID.ShortString(), err)
				return
			}

			var conn network.Conn
			for _, c := range h.Network().ConnsToPeer(info.ID) {
				conn = c
				break
			}

			relayCtx, relayCancel := context.WithTimeout(bootCtx, 5*time.Second)
			defer relayCancel()
			supportsRelay := supportsRelayHop(relayCtx, h, info.ID)

			oksMu.Lock()
			addrStr := "?"
			if len(info.Addrs) > 0 {
				addrStr = info.Addrs[0].String()
			}
			relayStatus := ""
			if supportsRelay {
				relayStatus = " [RELAY]"
			}
			oks = append(oks, Libp2pBsPeerInfo{
				Addr:          addrStr,
				PeerID:        info.ID,
				Conn:          conn,
				SupportsRelay: supportsRelay,
			})
			oksMu.Unlock()
			fmt.Printf("  ✓ %s → CONNECTED%s %v\n", info.ID.ShortString(), relayStatus, time.Since(btime))
		}(ai)
	}
	wg.Wait()

	relayCount := 0
	for _, p := range oks {
		if p.SupportsRelay {
			relayCount++
		}
	}
	fmt.Printf("[+] %d/%d bootstrap connections succeeded\n", len(oks), len(bootstrapInfos))
	fmt.Printf("[+] %d peers support relay hop\n\n", relayCount)

	if len(oks) == 0 {
		return nil, fmt.Errorf("failed to connect to any bootstrap peers")
	}

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

	waitStart := time.Now()
	for time.Since(waitStart) < 75*time.Second {
		rtSize := kadDHT.RoutingTable().Size()
		if rtSize >= 3 {
			fmt.Printf("  ✓ Routing table has %d peers\n", rtSize)
			break
		}
		time.Sleep(500 * time.Millisecond)
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

	pingService := ping.NewPingService(h)
	for i := range oks {
		go func(p *Libp2pBsPeerInfo) {
			for {
				time.Sleep(30 * time.Second)
				pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
				ch := pingService.Ping(pingCtx, p.PeerID)
				select {
				case res := <-ch:
					if res.Error == nil {
						continue
					}
				case <-pingCtx.Done():
				}
				pingCancel()
				h.Network().ClosePeer(p.PeerID)
				return
			}
		}(&oks[i])
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
		RelayCount:   relayCount,
		Discovered:   discoveredCount,
		BootTime:     time.Since(start),
		FullStatus:   fullStatus,
	}, nil
}
