package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"flag"
	"log"
	"time"

	"github.com/envsh/toxera/fedkey"
	"github.com/envsh/toxera/relayhub"
)

func main() {
	seed := flag.String("seed", "key.txt", "path to seed file")
	relayAddr := flag.String("relay", "104.131.131.82:4001", "relay address")
	dstPeerStr := flag.String("dst", "", "destination peer ID")
	size := flag.Int64("size", 1<<20, "total bytes to send")
	flag.Parse()

	if *dstPeerStr == "" {
		log.Fatal("-dst is required")
	}

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

	dstID, err := relayhub.ParsePeerID(*dstPeerStr)
	if err != nil {
		log.Fatal("parse dst peer id:", err)
	}

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

	sock := c.NewSocket()
	defer sock.Close()

	if _, err := sock.Connect(ctx, dstID); err != nil {
		log.Fatal("connect through relay:", err)
	}
	log.Printf("socket ID: %s", sock.ID())

	h := md5.New()
	chunk := make([]byte, 8<<10)
	sent := int64(0)
	for sent < *size {
		writeBuf := chunk
		if remain := *size - sent; remain < int64(len(writeBuf)) {
			writeBuf = writeBuf[:remain]
		}
		rand.Read(writeBuf)
		n, err := sock.Write(writeBuf)
		if err != nil {
			log.Fatalf("socket write at %d: %v", sent, err)
		}
		h.Write(writeBuf[:n])
		sent += int64(n)
		if sent%(512<<10) == 0 || sent == *size {
			log.Printf("sent %d/%d bytes (sock=%s rotations=%d remaining=%d)",
				sent, *size, sock.ID(), sock.Rotations(), sock.Remaining())
		}
	}
	log.Printf("done, total sent=%d md5=%x (sock=%s rotations=%d)", sent, h.Sum(nil), sock.ID(), sock.Rotations())
}
