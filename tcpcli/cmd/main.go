package main

import (
	"flag"
	"time"
	"fmt"
	"log"

	"github.com/envsh/toxera/tcpcli"
)

var peerpk string
var keyfile string = "node.key"

func main() {
	flag.StringVar(&peerpk, "p", peerpk, "peerpk")
	flag.StringVar(&keyfile, "f", keyfile, "keyfile")
	flag.Parse()

	cli := tcpcli.New(keyfile)
	defer cli.Close()
	// cli.AddTcpRelay("43.198.227.166", 3389, "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E")
	for _, n := range bootstrapNodes {
		if true {
			cli.AddTcpRelay(n.IPv4, int(n.Port), n.PublicKey)
		}
	}

	log.Printf("pk=%v\n", cli.Selfpk)
	log.Println("connected", cli.WaitConnected())

	go func() {
		for {
			buf := make([]byte, 2048)
			rn, addr, err := cli.ReadFrom(buf)
			log.Println("<<", rn, err, addr.(peer_address).Sub7(), string(buf[:rn]))
		}
	}()

	if peerpk != "" {
		log.Println("yes peerpk, sender mode")
		btime := time.Now()
		for i:=0; ; i++ {
			cli.Iterate()
			time.Sleep(60*time.Millisecond)
			if time.Since(btime) < 3*time.Second {
				continue
			}
			btime = time.Now()

			scc := fmt.Sprintf("from %v %v", keyfile, i)
			bcc := []byte(scc)
			wn, err := cli.WriteTo(bcc, peer_address(peerpk))
			log.Println(">>", scc, wn, err)
		}
	}else{
		log.Println("no peerpk, wait mode")
		for {
			time.Sleep(60*time.Millisecond)
			cli.Iterate()
		}
	}
}

type peer_address = tcpcli.PeerAddr


// BootstrapNode represents a Tox bootstrap node
type BootstrapNode struct {
	IPv4       string
	IPv6       string
	Port       uint16
	PublicKey  string
	Maintainer string
}

// Bootstrap nodes from C version (bootstrap.c)
var bootstrapNodes = []BootstrapNode{
	{
		IPv4:       "43.198.227.166",
		IPv6:       "-",
		Port:       3389,
		PublicKey:  "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E",
		Maintainer: "AnthonyBilinski (C version)",
	},
    {
      IPv4: "86.107.187.54",
      IPv6: "-",
      Port: 33445,
      PublicKey: "2C0F90965134C7BEFAFE72B077A19221628D7045BB51C1165A2C75CDB2B32634",
      Maintainer: "Boca",
    },

}
