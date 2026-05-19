package p2put

import (
	"flag"

	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/core/network"
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

var dftConfig = Config{
	KeyFile: "key.txt",
	Dht: true,
	ResRate: 0.2,
	Relay: true,
	NAT: true,
	Tcp: true,
	Punching: true,
}
var currConfig = dftConfig

func DefaultConfig() Config {
	dftConfig.Fset = getFlagSet(&dftConfig)
	return dftConfig
}

/////
// usage: libp2p.New(libp2p.ResourceManager(myResourcemanager()),
func myResourceManager() network.ResourceManager {
	limits := rcmgr.DefaultLimits
	limits.SystemBaseLimit = rcmgr.BaseLimit{
		Conns: 32/2,
		ConnsInbound: 16/2,
		ConnsOutbound: 16/2,
		Streams: 64/2,
		StreamsInbound: 32/2,
		StreamsOutbound: 32/2,
		FD: 32/2,
		Memory: (128 << 20)/2,
	}
	rm, _ := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limits.Scale(0, 0)))

	return rm
}
