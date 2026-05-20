package p2put

import (
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
