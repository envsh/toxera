package p2put

import (
	"fmt"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"
)

var bootres *Libp2pBootResult

type BoardResp struct {
	PeerID    string         `json:"peer_id"`
	Pubkey    string         `json:"pubkey"`
	NATStatus string         `json:"nat_status"`
	Relays1   int            `json:"relays1"`
	Relays2   int            `json:"relays2"`
	Conns     int            `json:"connections"`
	Addrs     int            `json:"listening_addrs"`
	Bandwidth *BandwidthResp `json:"bandwidth"`
	Resources *ResourcesResp `json:"resources,omitempty"`
}

type ResourcesResp struct {
	System    ScopeStatResp `json:"system"`
	Transient ScopeStatResp `json:"transient"`
}

type ScopeStatResp struct {
	StreamsIn  int   `json:"streams_in"`
	StreamsOut int   `json:"streams_out"`
	ConnsIn    int   `json:"connections_in"`
	ConnsOut   int   `json:"connections_out"`
	FD         int   `json:"fd"`
	Memory     int64 `json:"memory_bytes"`
}

type BandwidthResp struct {
	TotalIn  int64   `json:"total_in_bytes"`
	TotalOut int64   `json:"total_out_bytes"`
	RateIn   float64 `json:"rate_in"`
	RateOut  float64 `json:"rate_out"`
}

type RelayResp struct {
	Candidates []string `json:"candidates"`
	Connected  []string `json:"connected"`
}

type AddrResp struct {
	Addr  string `json:"addr"`
	Relay bool   `json:"is_relay"`
	Priv  bool   `json:"is_private"`
}

type ConnResp struct {
	PeerID    string `json:"peer_id"`
	Addr      string `json:"addr"`
	Direction string `json:"direction"`
}

type DHTResp struct {
	Size  int      `json:"size"`
	Peers []string `json:"peers"`
}

func CollectBoard() (BoardResp, error) {
	if bootres == nil || bootres.Host == nil {
		return BoardResp{}, fmt.Errorf("libp2p not ready")
	}
	h := bootres.Host

	var addrs []AddrResp
	for _, a := range h.Addrs() {
		addrs = append(addrs, AddrResp{
			Addr:  a.String(),
			Relay: isRelayAddr(a),
			Priv:  isPrivateIP(extractIPFromAddr(a)),
		})
	}

	conns, _ := CollectConns()
	relays, _ := CollectRelays()

	var bw *BandwidthResp
	if bootres.Bwc != nil {
		s := bootres.Bwc.GetBandwidthTotals()
		bw = &BandwidthResp{
			TotalIn:  s.TotalIn,
			TotalOut: s.TotalOut,
			RateIn:   s.RateIn,
			RateOut:  s.RateOut,
		}
	}

	var res *ResourcesResp
	if rm := h.Network().ResourceManager(); rm != nil {
		var sys, trans ScopeStatResp
		rm.ViewSystem(func(s network.ResourceScope) error {
			st := s.Stat()
			sys = ScopeStatResp{
				StreamsIn:  st.NumStreamsInbound,
				StreamsOut: st.NumStreamsOutbound,
				ConnsIn:    st.NumConnsInbound,
				ConnsOut:   st.NumConnsOutbound,
				FD:         st.NumFD,
				Memory:     st.Memory,
			}
			return nil
		})
		rm.ViewTransient(func(s network.ResourceScope) error {
			st := s.Stat()
			trans = ScopeStatResp{
				StreamsIn:  st.NumStreamsInbound,
				StreamsOut: st.NumStreamsOutbound,
				ConnsIn:    st.NumConnsInbound,
				ConnsOut:   st.NumConnsOutbound,
				FD:         st.NumFD,
				Memory:     st.Memory,
			}
			return nil
		})
		res = &ResourcesResp{System: sys, Transient: trans}
	}

	return BoardResp{
		PeerID:    h.ID().String(),
		Pubkey:    bootres.PubkeyHex,
		NATStatus: bootres.FullStatus.NATStatus.String(),
		Relays1:    len(relays.Candidates),
		Relays2:    len(relays.Connected),
		Conns:     len(conns),
		Addrs:     len(addrs),
		Bandwidth: bw,
		Resources: res,
	}, nil
}

func CollectConns() ([]ConnResp, error) {
	if bootres == nil || bootres.Host == nil {
		return nil, fmt.Errorf("libp2p not ready")
	}
	var out []ConnResp
	for _, c := range bootres.Host.Network().Conns() {
		dir := "outbound"
		if c.Stat().Direction == network.DirInbound {
			dir = "inbound"
		}
		out = append(out, ConnResp{
			PeerID:    c.RemotePeer().String(),
			Addr:      c.RemoteMultiaddr().String(),
			Direction: dir,
		})
	}
	return out, nil
}

func CollectDHT() (DHTResp, error) {
	if bootres == nil || bootres.Host == nil {
		return DHTResp{}, fmt.Errorf("libp2p not ready")
	}
	if bootres.DHT == nil {
		return DHTResp{}, nil
	}
	rt := bootres.DHT.RoutingTable()
	peers := rt.ListPeers()
	strs := make([]string, len(peers))
	for i, p := range peers {
		strs[i] = p.String()
	}
	return DHTResp{
		Size:  rt.Size(),
		Peers: strs,
	}, nil
}

func CollectRelays() (RelayResp, error) {
	if bootres == nil || bootres.Host == nil {
		return RelayResp{}, fmt.Errorf("libp2p not ready")
	}
	h := bootres.Host

	var candidates []string
	candidatePeers := make(map[peer.ID]struct{})
	for _, a := range h.Addrs() {
		if !isRelayAddr(a) {
			continue
		}
		addrStr := a.String()
		candidates = append(candidates, addrStr)

		trimmed := strings.TrimSuffix(addrStr, "/p2p-circuit")
		ma, err := multiaddr.NewMultiaddr(trimmed)
		if err != nil {
			continue
		}
		pidStr, err := ma.ValueForProtocol(multiaddr.P_P2P)
		if err != nil {
			continue
		}
		pid, err := peer.Decode(pidStr)
		if err != nil {
			continue
		}
		candidatePeers[pid] = struct{}{}
	}

	var connected []string
	for _, c := range h.Network().Conns() {
		if _, ok := candidatePeers[c.RemotePeer()]; ok {
			connected = append(connected, c.RemoteMultiaddr().String()+"/p2p/"+c.RemotePeer().String())
		}
	}

	if candidates == nil {
		candidates = []string{}
	}
	if connected == nil {
		connected = []string{}
	}

	return RelayResp{
		Candidates: candidates,
		Connected:  connected,
	}, nil
}
