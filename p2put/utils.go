package p2put

import (
	"net"
	// "errors"
	"time"
	"fmt"
	"context"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

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
