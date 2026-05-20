package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/envsh/toxera/fedkey"
	"github.com/envsh/toxera/relayhub"
)

func main() {
	seed := flag.String("seed", "key.txt", "path to seed file")
	relayAddr := flag.String("relay", "104.131.131.82:4001", "relay address")
	dstStr := flag.String("dst", "", "destination peer ID (base58)")
	flag.Parse()

	if *dstStr == "" {
		log.Fatal("missing -dst peer ID")
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
	dstID, err := relayhub.ParsePeerID(*dstStr)
	if err != nil {
		log.Fatal("parse dst peer id:", err)
	}
	log.Println("myID:", myID, "dstID:", dstID)

	privKey := kr.BTDHTKey()
	ctx := context.Background()

	c := relayhub.NewRelayClient(myID, privKey)
	if err := c.Connect(ctx, *relayAddr); err != nil {
		log.Fatal("connect:", err)
	}
	log.Println("connected to relay")

	relayed, err := c.ConnectThroughRelay(ctx, dstID)
	if err != nil {
		log.Fatal("connect through relay:", err)
	}
	log.Println("relay established")

	relayed.Write([]byte("hello from source\n"))
	log.Println("sent, waiting for reply...")

	buf := make([]byte, 4096)
	n, err := relayed.Read(buf)
	if err != nil {
		log.Printf("read reply: %v", err)
	} else {
		os.Stdout.Write([]byte("<< "))
		os.Stdout.Write(buf[:n])
	}
}
