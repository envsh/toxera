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
	log.Println("connected to relay, requesting circuit v2 reservation...")

	go func() {
		if err := c.Reserve(ctx); err != nil {
			log.Printf("reserve failed (non-fatal): %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		log.Println("shutting down...")
		c.Close()
	}()

	log.Println("waiting for incoming relayed connections...")
	for {
		conn, err := c.AcceptRelay(ctx)
		if err != nil {
			log.Fatal("accept:", err)
		}
		log.Println("relayed connection accepted, reading...")
		go func() {
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err == nil {
				os.Stdout.Write([]byte("<< "))
				os.Stdout.Write(buf[:n])
			}
			conn.Write([]byte("hello from peer\n"))
			conn.Close()
		}()
	}
}
