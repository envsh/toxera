package p2put

import (
	"flag"
	"time"

	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p-pubsub"

)

func getFlagSet(cfg *Config) *flag.FlagSet {
	fs := flag.NewFlagSet("libp2p", flag.ContinueOnError)
	keyFile := fs.String("k", "key.txt", "keyring file")
	port := fs.Int("l", 0, "TCP listen port - 4001 or random")
	_ , _  = keyFile, port
	cfg._KeyFile = keyFile
	cfg._ListenPort = port
	return fs
}

type Config struct {
	// usage1, just Fset.parse()
	Fset *flag.FlagSet // caller parser
	_KeyFile *string
	_ListenPort *int

	// usage2, assign direct, without Fset.parse
	KeyFile    string // fedkey seed file
	ListenPort int
	HubName string // VlanName, our every nodes same name for find
	IsMobile  bool // bandwidth and battary
	UserAgent string // "universal-connectivity/go-peer"

	Server bool
	Dht   bool
	ResRate float32 // 0.5, 1, 2
	Relay bool
	NAT   bool
	Udp   bool
	Tcp   bool
	Wss   bool
	Quic  bool
	Bw   bool
	Punching bool
	AutoPing bool
}

var currConfig = DefaultConfig()

func DefaultConfig() Config {
	var dftConfig = Config{
		KeyFile: "key.txt",
		HubName: "envsh-p2d", // p2p to daemon/distribute
		UserAgent: "universal-connectivity/envsh-d2hub",
		Dht: true,
		ResRate: 0.2,
		Relay: true,
		NAT: true,
		Tcp: true,
		Punching: true,
	}

	dftConfig.Fset = getFlagSet(&dftConfig)
	return dftConfig
}

/////
// usage: libp2p.New(libp2p.ResourceManager(myResourcemanager()),
func myResourceManager() network.ResourceManager {
	limits := rcmgr.DefaultLimits
	syslmt := limits.SystemBaseLimit
	const rate = 1
	limits.SystemBaseLimit = rcmgr.BaseLimit{
		Conns: (syslmt.Conns/4)*rate,
		ConnsInbound: (syslmt.ConnsInbound/4)*rate,
		ConnsOutbound: (syslmt.ConnsOutbound/4)*rate,
		Streams: (syslmt.Streams/4)*rate,
		StreamsInbound: (syslmt.StreamsInbound/4)*rate,
		StreamsOutbound: (syslmt.StreamsOutbound/4)*rate,
		FD: (syslmt.FD/4)*rate,
		Memory: (syslmt.Memory/4)*int64(rate),
	}
	rm, _ := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limits.Scale(0, 0)))

	return rm
}

func myGossipSubParams() pubsub.GossipSubParams {
	dft := pubsub.DefaultGossipSubParams()
	if true { // lower bw
		dft.D =                 3
		dft.Dlo =                 2
		dft.Dhi =                 4
		dft.Dlazy =               2
		dft.GossipFactor =        0.02
		dft.HeartbeatInterval =   10 * time.Second
		dft.HistoryLength =       2
		dft.HistoryGossip =       1
		dft.DirectConnectTicks =  600  // ← 必须，否则除以零
	}else{
		dft.D =                 3
		dft.Dlo =                 2
		dft.Dhi =                 6
		dft.Dlazy =               3
		dft.GossipFactor =        0.1
		dft.HeartbeatInterval =   2 * time.Second
		dft.HistoryLength =       5
		dft.HistoryGossip =       3
		dft.DirectConnectTicks =  600  // ← 必须，否则除以零
	}
	return dft
}
