package p2put

import (
	"net"
	// "errors"
	"time"
	// "fmt"
	"context"

	"github.com/libp2p/go-libp2p/core/host"
	// "github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"
	// "github.com/libp2p/go-libp2p/core/event"
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
