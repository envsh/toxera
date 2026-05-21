package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/envsh/toxera/fedkey"
	"github.com/envsh/toxera/relayhub"
)

func main() {
	seed := flag.String("seed", "key.txt", "path to seed file")
	relayAddr := flag.String("relay", "104.131.131.82:4001", "relay address")
	flag.Parse()

	kr, err := fedkey.LoadKeyRing(*seed, false)
	if err != nil {
		log.Fatal("load key:", err)
	}

	peerIDStr := kr.Libp2pPeerID(fedkey.Libp2pEd25519)
	myID, err := relayhub.ParsePeerID(peerIDStr)
	if err != nil {
		log.Fatal("parse peer id:", err)
	}
	log.Println("peer ID:", myID)

	privKey := kr.BTDHTKey()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c := relayhub.NewRelayClient(myID, privKey)
	defer c.Close()

	if err := c.Connect(ctx, *relayAddr); err != nil {
		log.Fatal("connect:", err)
	}
	log.Println("connected, reserving...")

	if err := c.Reserve(ctx); err != nil {
		log.Fatal("reserve:", err)
	}

	dispatcher := relayhub.NewCircuitDispatcher(ctx, c)
	go dispatcher.Loop()

	go func() {
		<-ctx.Done()
		dispatcher.Close()
	}()

	log.Println("waiting for budgeted connection...")
	bc, err := relayhub.NewBudgetedConnAcceptor(ctx, c, dispatcher)
	if err != nil {
		log.Fatal("accept budgeted:", err)
	}
	log.Printf("conn ID: %s", bc.ConnID())
	defer bc.Close()

	var recv atomic.Int64
	buf := make([]byte, 64<<10)
	for {
		n, err := bc.Read(buf)
		if err != nil {
			log.Printf("read error: %v (recv=%d rotations=%d)", err, recv.Load(), bc.Rotations())
			break
		}
		total := recv.Add(int64(n))
		if total%(512<<10) == 0 {
			log.Printf("recv %d bytes, rotations=%d remaining=%d",
				total, bc.Rotations(), bc.Remaining())
		}
	}
	log.Printf("done, total recv=%d rotations=%d", recv.Load(), bc.Rotations())
}
