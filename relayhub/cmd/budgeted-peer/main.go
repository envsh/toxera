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

	c.Start(ctx)

	log.Println("waiting for budgeted connection...")
	sock := c.NewSocket()
	sock.Listen()
	defer sock.Close()

	var recv atomic.Int64
	h := md5.New()
	buf := make([]byte, 64<<10)
	for {
		n, err := sock.Read(buf)
		if err != nil {
			log.Printf("read error: %v (sock=%s recv=%d rotations=%d)", err, sock.ID(), recv.Load(), sock.Rotations())
			break
		}
		h.Write(buf[:n])
		total := recv.Add(int64(n))
		if total%(512<<10) == 0 {
			log.Printf("recv %d bytes (sock=%s rotations=%d remaining=%d)",
				total, sock.ID(), sock.Rotations(), sock.Remaining())
		}
	}
	log.Printf("done, total recv=%d md5=%x (sock=%s rotations=%d)", recv.Load(), h.Sum(nil), sock.ID(), sock.Rotations())
}
