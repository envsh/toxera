//go:build eth

package fedboot

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/envsh/toxera/fedkey"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

////////////

type Eth struct {

}

var _ = regme(&Eth{})

func (o *Eth) Start() error {
	return nil
}

func (o *Eth) Stop() error {
	return nil
}

func (o *Eth) Info() string {
	return "{}"
}

func MainEth() {
	mainEth()
}

//////


var ethBoot = []string{
	"enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
	"enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",
	"enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303",
	"enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303",
}

type BootConfig struct {
	KeyFile    string
	ListenPort int
	Timeout    time.Duration
}

type BootResult struct {
	Server    *p2p.Server
	NodeID    enode.ID
	PubkeyHex string
	BootTime  time.Duration
}

func Bootstrap(ctx context.Context, cfg BootConfig) (*BootResult, error) {
	start := time.Now()

	kr, err := fedkey.LoadKeyRing(cfg.KeyFile, true)
	if err != nil {
		return nil, fmt.Errorf("load keyring: %w", err)
	}

	privBytes := kr.Secp256k1Priv().Serialize()
	priv, err := crypto.ToECDSA(privBytes)
	if err != nil {
		return nil, fmt.Errorf("to ecdsa: %w", err)
	}

	bootNodes := make([]*enode.Node, 0, len(ethBoot))
	for _, url := range ethBoot {
		n, err := enode.ParseV4(url)
		if err != nil {
			continue
		}
		bootNodes = append(bootNodes, n)
	}

	srv := &p2p.Server{
		Config: p2p.Config{
			PrivateKey:     priv,
			Name:           "eth_bs",
			ListenAddr:     fmt.Sprintf(":%d", cfg.ListenPort),
			NAT:            nat.Any(),
			DiscoveryV4:    true,
			BootstrapNodes: bootNodes,
			MaxPeers:       0,
		},
	}

	if err := srv.Start(); err != nil {
		return nil, fmt.Errorf("start server: %w", err)
	}

	// v1.14: use DiscoveryV4() method to get the discovery instance
	disc := srv.DiscoveryV4()
	if disc == nil {
		srv.Stop()
		return nil, fmt.Errorf("discovery v4 not available")
	}

	// wait for disc.Self() != nil (DHT ready)
	waitCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if disc.Self() != nil {
			break
		}
		select {
		case <-waitCtx.Done():
			srv.Stop()
			return nil, fmt.Errorf("bootstrap timeout: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}

	pubHex := hex.EncodeToString(crypto.FromECDSAPub(&priv.PublicKey)[1:])
	selfNode := enode.NewV4(&priv.PublicKey, nil, 0, 0)

	return &BootResult{
		Server:    srv,
		NodeID:    selfNode.ID(),
		PubkeyHex: pubHex,
		BootTime:  time.Since(start),
	}, nil
}


func mainEth() {
	fs := flag.NewFlagSet("eth", flag.ContinueOnError)
	keyFile := fs.String("k", "key.txt", "keyring file")
	port := fs.Int("l", 30303, "listen port")
	timeoutSec := fs.Int("t", 60, "bootstrap timeout (seconds)")
	fs.Parse(os.Args[1:])

	cfg := BootConfig{
		KeyFile:    *keyFile,
		ListenPort: *port,
		Timeout:    time.Duration(*timeoutSec) * time.Second,
	}

	res, err := Bootstrap(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("✅ ONLINE\n")
	fmt.Printf("   NodeID:    %x\n", res.NodeID[:8])
	fmt.Printf("   Pubkey:    %s\n", res.PubkeyHex[:16]+"...")
	fmt.Printf("   Boot time: %v\n", res.BootTime)

	for { time.Sleep(time.Second) }
}
