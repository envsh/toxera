package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	bc, err := relayhub.NewBudgetedConn(ctx, c, dstID)
	if err != nil {
		log.Fatal("budgeted connect:", err)
	}
	log.Printf("conn ID: %s", bc.ConnID())
	defer bc.Close()

	chunk := make([]byte, 64<<10)
	sent := int64(0)
	for sent < *size {
		writeLen := len(chunk)
		if remain := *size - sent; remain < int64(writeLen) {
			chunk = chunk[:remain]
			writeLen = int(remain)
		}
		n, err := bc.Write(chunk)
		if err != nil {
			log.Fatalf("write at %d: %v", sent, err)
		}
		sent += int64(n)
		if sent%(512<<10) == 0 || sent == *size {
			log.Printf("sent %d/%d bytes, rotations=%d remaining=%d",
				sent, *size, bc.Rotations(), bc.Remaining())
		}
	}
	log.Printf("done, total sent=%d rotations=%d", sent, bc.Rotations())
}
