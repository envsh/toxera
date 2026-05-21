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

	for {
		c := relayhub.NewRelayClient(myID, privKey)

		if err := c.Connect(ctx, *relayAddr); err != nil {
			log.Printf("connect: %v, retry in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Println("connected, reserving...")

		if err := c.Reserve(ctx); err != nil {
			log.Printf("reserve: %v, retry in 5s", err)
			c.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		go func() {
			c.RefreshReservation(ctx)
			t := time.NewTicker(1 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-c.SessionDone():
					return
				case <-t.C:
				}
				c.RefreshReservation(ctx)
			}
		}()

		c.Start(ctx)

		srv := c.NewSocket()
		srv.Listen()
		log.Println("waiting for connection...")

		acc, err := srv.Accept(ctx)
		if err != nil {
			log.Printf("accept: %v, reconnecting in 5s", err)
			c.Close()
			time.Sleep(5 * time.Second)
			continue
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
		c.Close()
	}
}
