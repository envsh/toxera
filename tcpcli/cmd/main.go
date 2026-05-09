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
	cli.AddTcpRelay("43.198.227.166", 3389, "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E")
	for _, n := range bootstrapNodes {
		if true {
			cli.AddTcpRelay(n.IPv4, int(n.Port), n.PublicKey)
		}
	}

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
			cli.WriteTo(bcc, &peer_address{peerpk})
			log.Printf(">> %v %v\n", scc, 1)
		}
	}else{
		log.Println("no peerpk, wait mode")
		for {
			time.Sleep(60*time.Millisecond)
			cli.Iterate()
		}
	}
}

type peer_address struct {
	pk string
}

func (a *peer_address) Network() string {
	return ""
}
func (a *peer_address) String() string {
	return a.pk
}


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
		IPv4:       "104.225.141.59",
		IPv6:       "-",
		Port:       33445,
		PublicKey:  "933BA20B2E258B4C0D475B6DECE90C7E827FE83EFA9655414E7841251B19A72C",
		Maintainer: "velusip (C version)",
	},
	{
		IPv4:       "43.198.227.166",
		IPv6:       "-",
		Port:       3389,
		PublicKey:  "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E",
		Maintainer: "AnthonyBilinski (C version)",
	},
	{
		IPv4:       "3.0.24.15",
		IPv6:       "-",
		Port:       33445,
		PublicKey:  "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D",
		Maintainer: "2mf (C version)",
	},
	{
      IPv4: "144.217.167.73",
      IPv6: "-",
      Port: 33445,
      PublicKey: "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C",
      Maintainer: "velusip",
    },
    {
      IPv4: "tox.abilinski.com",
      IPv6: "-",
      Port: 33445,
      PublicKey: "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E",
      Maintainer: "AnthonyBilinski",
    },
    {
      IPv4: "86.107.187.54",
      IPv6: "-",
      Port: 33445,
      PublicKey: "2C0F90965134C7BEFAFE72B077A19221628D7045BB51C1165A2C75CDB2B32634",
      Maintainer: "Boca",
    },

}
