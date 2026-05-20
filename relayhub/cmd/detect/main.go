package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/envsh/toxera/relayhub"
)

func main() {
	log.SetFlags(0)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: detect [flags] <addr> [addr...]\n")
		fmt.Fprintf(os.Stderr, "       detect [flags] -file <peerstore.json>\n")
		flag.PrintDefaults()
	}
	filePath := flag.String("file", "", "JSON peerstore file")
	flag.Parse()

	var addrs []string
	if *filePath != "" {
		data, err := os.ReadFile(*filePath)
		if err != nil {
			log.Fatal(err)
		}
		var ps map[string][]string
		json.Unmarshal(data, &ps)
		seen := make(map[string]bool)
		for _, alist := range ps {
			for _, a := range alist {
				parts := splitAddr(a)
				if parts == nil {
					continue
				}
				k := parts[0] + ":" + parts[1]
				if !seen[k] {
					seen[k] = true
					addrs = append(addrs, k)
				}
			}
		}
	} else {
		addrs = flag.Args()
	}
	if len(addrs) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for i, a := range addrs {
		if i > 0 {
			fmt.Println()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		r := relayhub.DetectRelay(ctx, a, priv)
		cancel()
		printResult(r)
	}
}

func printResult(r *relayhub.DetectResult) {
	fmt.Printf("Address: %s\n", r.Addr)
	fmt.Printf("  TCP:     %s (%v)\n", ok(r.TCPOK), r.TCPDuration)
	if !r.TCPOK {
		return
	}
	fmt.Printf("  TLS:     %s\n", ok(r.TLSOK))
	fmt.Printf("  Yamux:   %s\n", ok(r.YamuxOK))
	if !r.YamuxOK {
		return
	}

	fmt.Printf("  Identify: %s\n", ok(r.IdentifyOK))
	if r.IdentifyOK {
		fmt.Printf("    PeerID:  %s\n", r.Identify.PeerID)
		fmt.Printf("    Agent:   %s\n", r.Identify.Agent)
		for _, p := range r.Identify.Protos {
			disp := p
			if len(disp) > 100 {
				disp = disp[:100] + "..."
			}
			fmt.Printf("    Protocol: %s\n", disp)
		}
	}

	printV1(r)
	printV2Hop(r)
	printV2Connect(r)
	printV2Stop(r)

	relay := " NO"
	if r.V1OK && r.V1Code == 100 {
		relay = " YES (v1)"
	} else if r.V2HopOK && r.V2Status == 100 && r.V2StopOK {
		relay = " YES (v2)"
	}
	fmt.Printf("  RELAY CAPABLE:%s\n", relay)
}

func printV1(r *relayhub.DetectResult) {
	if r.V1OK {
		relay := ""
		if r.V1Code == 100 {
			relay = " YES"
		}
		fmt.Printf("  Circuit v1 (/libp2p/circuit/relay/0.1.0):\n")
		fmt.Printf("    Negotiated: yes\n")
		fmt.Printf("    CAN_HOP:    %d (%s)\n", r.V1Code, r.V1Status)
		fmt.Printf("    Relay:%s\n", relay)
	} else {
		fmt.Printf("  Circuit v1 (/libp2p/circuit/relay/0.1.0): no\n")
	}
}

func printV2Hop(r *relayhub.DetectResult) {
	if r.V2HopOK {
		relay := ""
		exp := ""
		if r.V2Status == 100 {
			relay = " YES"
			if r.V2Expire > 0 {
				exp = fmt.Sprintf(", expire=%ds", r.V2Expire)
			}
		}
		fmt.Printf("  Circuit v2 hop (/libp2p/circuit/relay/0.2.0/hop):\n")
		fmt.Printf("    Negotiated: yes\n")
		fmt.Printf("    RESERVE:    %d (%s)%s\n", r.V2Status, statusString(r.V2Status), exp)
		fmt.Printf("    Relay:%s\n", relay)
	} else {
		fmt.Printf("  Circuit v2 hop (/libp2p/circuit/relay/0.2.0/hop): no\n")
	}
}

func printV2Connect(r *relayhub.DetectResult) {
	if r.V2ConnectOK {
		fmt.Printf("    CONNECT:   %d (%s)\n", r.V2ConnectStatus, statusString(r.V2ConnectStatus))
		fmt.Printf("    Duration:  %v\n", r.V2ConnectDuration)
	} else if r.V2Status == 100 {
		fmt.Printf("    CONNECT:   no response (not supported or timed out)\n")
		fmt.Printf("    Duration:  %v\n", r.V2ConnectDuration)
	}
}

func printV2Stop(r *relayhub.DetectResult) {
	if r.V2StopOK {
		fmt.Printf("  Circuit v2 stop (/libp2p/circuit/relay/0.2.0/stop): yes\n")
	} else {
		fmt.Printf("  Circuit v2 stop (/libp2p/circuit/relay/0.2.0/stop): no\n")
	}
}

func statusString(s int32) string {
	switch s {
	case 0:
		return "UNUSED"
	case 100:
		return "OK"
	case 200:
		return "RESERVATION_REFUSED"
	case 201:
		return "RESOURCE_LIMIT_EXCEEDED"
	case 202:
		return "PERMISSION_DENIED"
	case 203:
		return "CONNECTION_FAILED"
	case 204:
		return "NO_RESERVATION"
	case 400:
		return "MALFORMED_MESSAGE"
	case 401:
		return "UNEXPECTED_MESSAGE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

func ok(v bool) string {
	if v {
		return "OK"
	}
	return "FAIL"
}

func splitAddr(addr string) []string {
	parts := splitPath(addr)
	var ip, port string
	for i, p := range parts {
		if p == "tcp" && i+1 < len(parts) {
			port = parts[i+1]
		}
		if p == "ip4" && i+1 < len(parts) {
			ip = parts[i+1]
		}
	}
	if ip != "" && port != "" {
		return []string{ip, port}
	}
	return nil
}

func splitPath(s string) []string {
	var r []string
	for _, p := range splitRaw(s, '/') {
		if p != "" {
			r = append(r, p)
		}
	}
	return r
}

func splitRaw(s string, sep byte) []string {
	var r []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			if i > start {
				r = append(r, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		r = append(r, s[start:])
	}
	return r
}
