package p2put

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const maxStablePeers = 32

var (
	stablePeers   = make(map[peer.ID]*stableInfo)
	stablePeersMu sync.RWMutex

	bootstrapPeerIDs map[peer.ID]struct{}
	bootstrapOnce    sync.Once
)

type stableInfo struct {
	firstSeen    time.Time
	onlineSince  time.Time
	totalOnline  time.Duration
	lastSeen     time.Time
	connCount    int
	disconnCount int
	avgLatency   time.Duration
}

func isBootstrapPeer(id peer.ID) bool {
	bootstrapOnce.Do(func() {
		bootstrapPeerIDs = make(map[peer.ID]struct{}, len(libp2pBootstrap))
		for _, s := range libp2pBootstrap {
			ma, err := multiaddr.NewMultiaddr(s)
			if err != nil {
				continue
			}
			ai, err := peer.AddrInfoFromP2pAddr(ma)
			if err != nil {
				continue
			}
			bootstrapPeerIDs[ai.ID] = struct{}{}
		}
	})
	_, ok := bootstrapPeerIDs[id]
	return ok
}

func evictOne() {
	var victim peer.ID
	var oldest time.Time
	first := true
	for id, si := range stablePeers {
		t := si.lastSeen
		if t.IsZero() {
			t = si.firstSeen
		}
		if first || t.Before(oldest) {
			oldest = t
			victim = id
			first = false
		}
	}
	if !first {
		delete(stablePeers, victim)
	}
}

func handlePeerConnectednessChanged(e event.EvtPeerConnectednessChanged) {
	if isBootstrapPeer(e.Peer) {
		return
	}

	switch e.Connectedness {
	case network.Connected:
		stablePeersMu.Lock()
		if si, ok := stablePeers[e.Peer]; ok {
			if si.onlineSince.IsZero() {
				si.onlineSince = time.Now()
			}
			si.connCount++
		} else {
			if len(stablePeers) >= maxStablePeers {
				evictOne()
			}
			stablePeers[e.Peer] = &stableInfo{
				firstSeen:   time.Now(),
				onlineSince: time.Now(),
				connCount:   1,
			}
		}
		stablePeersMu.Unlock()

	case network.NotConnected:
		stablePeersMu.Lock()
		if si, ok := stablePeers[e.Peer]; ok {
			if !si.onlineSince.IsZero() {
				si.totalOnline += time.Since(si.onlineSince)
				si.onlineSince = time.Time{}
			}
			si.lastSeen = time.Now()
			si.disconnCount++
		}
		stablePeersMu.Unlock()
	}
}

func updatePeerLatency(pid peer.ID, elapsed time.Duration) {
	if isBootstrapPeer(pid) {
		return
	}

	stablePeersMu.Lock()
	defer stablePeersMu.Unlock()
	si, ok := stablePeers[pid]
	if !ok {
		return
	}
	if si.connCount <= 1 {
		si.avgLatency = elapsed
	} else {
		si.avgLatency = time.Duration(float64(elapsed)*0.3 + float64(si.avgLatency)*0.7)
	}
}

func peerScore(si *stableInfo) float64 {
	score := 0.0
	if !si.onlineSince.IsZero() {
		score += 100
	}
	total := si.connCount + si.disconnCount
	if total > 0 {
		score += float64(si.connCount) / float64(total) * 50
	}
	if si.avgLatency > 0 && si.avgLatency < 10*time.Second {
		score += (1 - float64(si.avgLatency)/float64(10*time.Second)) * 50
	}
	return score
}

type StablePeerEntry struct {
	PeerID      string   `json:"peer_id"`
	Addrs       []string `json:"addrs"`
	FirstSeen   string   `json:"first_seen"`
	OnlineSince string   `json:"online_since"`
	TotalOnline string   `json:"total_online"`
	LastSeen    string   `json:"last_seen"`
	ConnCount   int      `json:"conn_count"`
	DisconnCnt  int      `json:"disconn_count"`
	AvgLatency  string   `json:"avg_latency"`
	Online      bool     `json:"online"`
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}

func CollectStablePeers() []StablePeerEntry {
	stablePeersMu.RLock()
	defer stablePeersMu.RUnlock()
	type scored struct {
		entry       StablePeerEntry
		score       float64
		totalOnline time.Duration
	}
	tmp := make([]scored, 0, len(stablePeers))
	for pid, si := range stablePeers {
		var addrs []string
		if bootres != nil && bootres.Host != nil {
			ps := bootres.Host.Peerstore()
			for _, a := range ps.Addrs(pid) {
				s := a.String()
				if strings.Contains(s, "/ip6/") ||
					strings.Contains(s, "/udp/") ||
					strings.Contains(s, "/quic") ||
					strings.Contains(s, "webrtc") ||
					strings.Contains(s, "/dns/") {
					continue
				}
				ip := extractIPFromAddr(a)
				if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
					continue
				}
				addrs = append(addrs, s)
			}
		}
		if addrs == nil {
			addrs = []string{}
		}
		tmp = append(tmp, scored{
			entry: StablePeerEntry{
				PeerID:      pid.String(),
				Addrs:       addrs,
				FirstSeen:   fmtTime(si.firstSeen),
				OnlineSince: fmtTime(si.onlineSince),
				TotalOnline: si.totalOnline.String(),
				LastSeen:    fmtTime(si.lastSeen),
				ConnCount:   si.connCount,
				DisconnCnt:  si.disconnCount,
				AvgLatency:  si.avgLatency.String(),
				Online:      !si.onlineSince.IsZero(),
			},
			score:       peerScore(si),
			totalOnline: si.totalOnline,
		})
	}
	sort.Slice(tmp, func(i, j int) bool {
		return tmp[i].totalOnline > tmp[j].totalOnline
	})
	out := make([]StablePeerEntry, len(tmp))
	for i, s := range tmp {
		out[i] = s.entry
	}
	return out
}
