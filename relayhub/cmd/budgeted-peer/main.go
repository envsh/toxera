package main

import (
	"context"
	"crypto/md5"
	"flag"
	"log"
	"sync/atomic"
	"time"

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

	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for range t.C {
			log.Println("refreshing reservation...")
			if err := c.RefreshReservation(ctx); err != nil {
				log.Printf("refresh reservation: %v", err)
			}
		}
	}()

	c.Start(ctx)

	srv := c.NewSocket()
	srv.Listen()
	log.Println("waiting for connection...")

	acc, err := srv.Accept(ctx)
	if err != nil {
		log.Fatal("accept:", err)
	}
	log.Printf("accepted socket %s", acc.ID())

	var recv atomic.Int64
	h := md5.New()
	buf := make([]byte, 64<<10)
	for {
		n, err := acc.Read(buf)
		if err != nil {
			log.Printf("read error: %v (sock=%s recv=%d rotations=%d)", err, acc.ID(), recv.Load(), acc.Rotations())
			break
		}
		h.Write(buf[:n])
		total := recv.Add(int64(n))
		if total%(512<<10) == 0 {
			log.Printf("recv %d bytes (sock=%s rotations=%d remaining=%d)",
				total, acc.ID(), acc.Rotations(), acc.Remaining())
		}
	}
	log.Printf("done, total recv=%d md5=%x (sock=%s rotations=%d)", recv.Load(), h.Sum(nil), acc.ID(), acc.Rotations())
}
