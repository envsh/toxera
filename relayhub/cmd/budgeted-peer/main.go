package main

import (
	"context"
	"crypto/md5"
	"flag"
	"log"
	"sync/atomic"

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
	ctx := context.Background()

	c := relayhub.NewRelayClient(myID, privKey)
	defer c.Close()

	if err := c.Connect(ctx, *relayAddr); err != nil {
		log.Fatal("connect:", err)
	}
	log.Println("connected, reserving...")

	if err := c.Reserve(ctx); err != nil {
		log.Fatal("reserve:", err)
	}

	log.Println("waiting for budgeted connection...")
	bc, err := relayhub.NewBudgetedListener(ctx, c)
	if err != nil {
		log.Fatal("accept budgeted:", err)
	}
	defer bc.Close()

	var recv atomic.Int64
	h := md5.New()
	buf := make([]byte, 64<<10)
	for {
		n, err := bc.Read(buf)
		if err != nil {
			log.Printf("read error: %v (conn=%s recv=%d rotations=%d)", err, bc.ConnID(), recv.Load(), bc.Rotations())
			break
		}
		h.Write(buf[:n])
		total := recv.Add(int64(n))
		if total%(512<<10) == 0 {
			log.Printf("recv %d bytes (conn=%s rotations=%d remaining=%d)",
				total, bc.ConnID(), bc.Rotations(), bc.Remaining())
		}
	}
	log.Printf("done, total recv=%d md5=%x (conn=%s rotations=%d)", recv.Load(), h.Sum(nil), bc.ConnID(), bc.Rotations())
}
