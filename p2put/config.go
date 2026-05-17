package p2put

import (
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/core/network"
)

type Config struct {
	Server bool
	Dht   bool
	ResRate float32 // 0.5, 1, 2
	Relay bool
	NAT   bool
	Udp   bool
	Tcp   bool
	Wss   bool
	Quic  bool
}

var dftConfig = Config{
	Dht: true,
	ResRate: 0.2,
	Relay: true,
	NAT: true,
	Tcp: true,
}
var currConfig = dftConfig

func DefaultConfig() Config { return dftConfig }

/////
// usage: libp2p.New(libp2p.ResourceManager(myResourcemanager()),
func myResourceManager() network.ResourceManager {
	limits := rcmgr.DefaultLimits
	limits.SystemBaseLimit = rcmgr.BaseLimit{Conns: 32/2, ConnsInbound: 16/2, ConnsOutbound: 16/2, Streams: 64/2, StreamsInbound: 32/2, StreamsOutbound: 32/2, FD: 32/2, Memory: 128 << 20/2}
	rm, _ := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limits.Scale(0, 0)))

	return rm
}
