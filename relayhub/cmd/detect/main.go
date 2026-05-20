package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/envsh/toxera/relayhub"
	"github.com/hashicorp/yamux"
)

type result struct {
	addr string

	tcpOK  bool
	tcpDur time.Duration
	tlsOK  bool
	yamux    bool
	yamuxDur time.Duration

	v1Neg bool
	v1Msg *v1Msg

	v2hopNeg bool
	v2hop    *hopMsg

	v2connect  *hopMsg
	connectDur time.Duration

	v2stopNeg bool

	idOK    bool
	idPeer  string
	idAgent string
	idProtos []string
}

type v1Msg struct {
	code   int
	codeStr string
}

type hopMsg struct {
	status   int32
	statusStr string
	expire   uint64
}

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
		printResult(detect(a, priv))
	}
}

func detect(addr string, key ed25519.PrivateKey) *result {
	r := &result{addr: addr}
	t0 := time.Now()
	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	r.tcpDur = time.Since(t0)
	if err != nil {
		return r
	}
	r.tcpOK = true
	defer raw.Close()

	if relayhub.MSSelect(raw, "/tls/1.0.0") != nil {
		return r
	}
	tlsCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tlsConn, err := relayhub.TLSClient(raw, key, tlsCtx)
	if err != nil {
		return r
	}
	r.tlsOK = true
	defer tlsConn.Close()

	if relayhub.MSSelectOver(tlsConn, "/yamux/1.0.0") != nil {
		return r
	}
	sess, err := yamux.Client(tlsConn, nil)
	if err != nil {
		return r
	}
	r.yamux = true
	r.yamuxDur = time.Since(t0)
	defer sess.Close()

	testIdentify(sess, r)
	testV1(sess, r)
	testV2Hop(sess, r)
	testV2Connect(sess, r, key)
	testV2Stop(sess, r)
	return r
}

func testIdentify(sess *yamux.Session, r *result) {
	s, err := sess.Open()
	if err != nil {
		return
	}
	defer s.Close()
	if relayhub.MSSelect(s, "/ipfs/id/1.0.0") != nil {
		return
	}
	data, err := readOnePb(s)
	if err != nil {
		return
	}
	r.idOK = true
	parseIdentify(data, r)
}

func parseIdentify(data []byte, r *result) {
	rest := data
	for len(rest) > 0 {
		tag, n := readVarintBytes(rest)
		if n <= 0 {
			break
		}
		rest = rest[n:]
		field := int(tag >> 3)
		wt := int(tag & 7)
		if wt == 2 { // length-delimited
			l, n := readVarintBytes(rest)
			if n <= 0 || int(l) > len(rest[n:]) {
				break
			}
			rest = rest[n:]
			val := rest[:l]
			rest = rest[l:]
			switch field {
			case 1: // PubKey
				r.idPeer = peerID(val)
			case 3: // Protocols
				r.idProtos = append(r.idProtos, string(val))
			case 6: // AgentVersion
				r.idAgent = string(val)
			}
		} else if wt == 0 { // varint
			_, n := readVarintBytes(rest)
			if n <= 0 {
				break
			}
			rest = rest[n:]
		} else {
			break
		}
	}
}

func testV1(sess *yamux.Session, r *result) {
	s, err := sess.Open()
	if err != nil {
		return
	}
	defer s.Close()
	if relayhub.MSSelect(s, "/libp2p/circuit/relay/0.1.0") != nil {
		return
	}
	r.v1Neg = true

	sendPb(s, []byte{0x08, 0x04})
	resp, err := readOnePb(s)
	if err != nil {
		return
	}
	msg := &v1Msg{}
	rest := resp
	for len(rest) > 0 {
		tag, n := readVarintBytes(rest)
		if n <= 0 {
			break
		}
		rest = rest[n:]
		field := int(tag >> 3)
		wt := int(tag & 7)
		if wt != 0 || rest == nil {
			break
		}
		v, n := readVarintBytes(rest)
		if n <= 0 {
			break
		}
		rest = rest[n:]
		if field == 1 {
			// type, skip
		} else if field == 4 || field == 6 {
			msg.code = int(v)
		}
	}
	msg.codeStr = v1Status(msg.code)
	r.v1Msg = msg
}

func testV2Hop(sess *yamux.Session, r *result) {
	s, err := sess.Open()
	if err != nil {
		return
	}
	defer s.Close()
	if relayhub.MSSelect(s, "/libp2p/circuit/relay/0.2.0/hop") != nil {
		return
	}
	r.v2hopNeg = true

	// Send RESERVE: type=RESERVE(0), field 1
	sendPb(s, []byte{0x08, 0x00})
	resp, err := readOnePb(s)
	if err != nil {
		return
	}
	msg := &hopMsg{}
	rest := resp
	for len(rest) > 0 {
		tag, n := readVarintBytes(rest)
		if n <= 0 {
			break
		}
		rest = rest[n:]
		field := int(tag >> 3)
		wt := int(tag & 7)
		switch {
		case field == 1 && wt == 0: // Type
			_, n := readVarintBytes(rest)
			if n <= 0 {
				break
			}
			rest = rest[n:]
		case field == 3 && wt == 2: // Reservation
			l, n := readVarintBytes(rest)
			if n <= 0 {
				break
			}
			rest = rest[n:]
			sub := rest[:l]
			rest = rest[l:]
			parseReservation(sub, msg)
		case field == 4 && wt == 2: // Limit
			l, n := readVarintBytes(rest)
			if n <= 0 {
				break
			}
			rest = rest[n+int(l):]
		case field == 5 && wt == 0: // Status
			v, n := readVarintBytes(rest)
			if n <= 0 {
				break
			}
			rest = rest[n:]
			msg.status = int32(v)
		default:
			if wt == 0 {
				_, n := readVarintBytes(rest)
				if n <= 0 {
					break
				}
				rest = rest[n:]
			} else if wt == 2 {
				l, n := readVarintBytes(rest)
				if n <= 0 || int(l) > len(rest[n:]) {
					break
				}
				rest = rest[n+int(l):]
			} else {
				break
			}
		}
	}
	msg.statusStr = v2Status(msg.status)
	r.v2hop = msg
}

func parseReservation(data []byte, msg *hopMsg) {
	rest := data
	for len(rest) > 0 {
		tag, n := readVarintBytes(rest)
		if n <= 0 {
			break
		}
		rest = rest[n:]
		field := int(tag >> 3)
		wt := int(tag & 7)
		if field == 1 && wt == 0 { // Expire
			v, n := readVarintBytes(rest)
			if n <= 0 {
				break
			}
			rest = rest[n:]
			msg.expire = v
		} else if wt == 2 {
			l, n := readVarintBytes(rest)
			if n <= 0 || int(l) > len(rest[n:]) {
				break
			}
			rest = rest[n+int(l):]
		} else if wt == 0 {
			_, n := readVarintBytes(rest)
			if n <= 0 {
				break
			}
			rest = rest[n:]
		} else {
			break
		}
	}
}

func testV2Connect(sess *yamux.Session, r *result, priv ed25519.PrivateKey) {
	if r.v2hop == nil || r.v2hop.status != 100 {
		return
	}

	s, err := sess.Open()
	if err != nil {
		return
	}
	defer s.Close()

	if relayhub.MSSelect(s, "/libp2p/circuit/relay/0.2.0/hop") != nil {
		return
	}

	pub := priv.Public().(ed25519.PublicKey)
	pid := computePeerID(pub)

	data := []byte{}
	data = append(data, putVarint((1<<3)|0)...)   // field 1 (Type), varint
	data = append(data, putVarint(uint64(1))...)   // CONNECT

	peerData := []byte{}
	peerData = append(peerData, putVarint((1<<3)|2)...)          // field 1 (id), len-delim
	peerData = append(peerData, putVarint(uint64(len(pid)))...)  // length
	peerData = append(peerData, pid...)                          // value
	data = append(data, putVarint((2<<3)|2)...)                  // field 2 (Peer), len-delim
	data = append(data, putVarint(uint64(len(peerData)))...)
	data = append(data, peerData...)

	connectStart := time.Now()
	sendPb(s, data)

	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := readOnePb(s)
	if err != nil {
		r.connectDur = time.Since(connectStart)
		return
	}
	r.connectDur = time.Since(connectStart)

	msg := &hopMsg{}
	rest := resp
	for len(rest) > 0 {
		tag, n := readVarintBytes(rest)
		if n <= 0 {
			break
		}
		rest = rest[n:]
		field := int(tag >> 3)
		wt := int(tag & 7)
		switch {
		case field == 1 && wt == 0:
			_, n = readVarintBytes(rest)
			if n <= 0 {
				break
			}
			rest = rest[n:]
		case field == 5 && wt == 0:
			v, n := readVarintBytes(rest)
			if n <= 0 {
				break
			}
			rest = rest[n:]
			msg.status = int32(v)
		default:
			if wt == 0 {
				_, n := readVarintBytes(rest)
				if n <= 0 {
					break
				}
				rest = rest[n:]
			} else if wt == 2 {
				l, n := readVarintBytes(rest)
				if n <= 0 || int(l) > len(rest[n:]) {
					break
				}
				rest = rest[n+int(l):]
			} else {
				break
			}
		}
	}
	msg.statusStr = v2Status(msg.status)
	r.v2connect = msg
}

func computePeerID(pk ed25519.PublicKey) []byte {
	protoPubKey := append([]byte{0x08, 0x01, 0x12, 0x20}, pk...)
	h := sha256.Sum256(protoPubKey)
	return append([]byte{0x12, 0x20}, h[:]...)
}

func testV2Stop(sess *yamux.Session, r *result) {
	s, err := sess.Open()
	if err != nil {
		return
	}
	defer s.Close()
	r.v2stopNeg = relayhub.MSSelect(s, "/libp2p/circuit/relay/0.2.0/stop") == nil
}

func peerID(pk []byte) string {
	// pk is protobuf-encoded public key from Identify (08 01 12 20 <32 bytes>)
	h := sha256.Sum256(pk)
	mh := append([]byte{0x12, 0x20}, h[:]...)
	return b58enc(mh)
}

const b58abc = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func b58enc(in []byte) string {
	n := new(big.Int).SetBytes(in)
	zero := big.NewInt(0)
	base := big.NewInt(58)
	mod := new(big.Int)
	var rev []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		rev = append(rev, b58abc[mod.Int64()])
	}
	// Add leading '1's for leading zero bytes
	for _, b := range in {
		if b != 0 {
			break
		}
		rev = append(rev, b58abc[0])
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if len(rev) == 0 {
		rev = append(rev, b58abc[0])
	}
	return string(rev)
}

func sendPb(w io.Writer, data []byte) {
	buf := append(putVarint(uint64(len(data))), data...)
	w.Write(buf)
}

func readOnePb(r io.Reader) ([]byte, error) {
	l, err := readVarint(r)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	return buf, err
}

func putVarint(v uint64) []byte {
	var buf []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			break
		}
	}
	return buf
}

func readVarint(r io.Reader) (uint64, error) {
	var v uint64
	for i := 0; ; i++ {
		b := []byte{0}
		if _, err := r.Read(b); err != nil {
			return 0, err
		}
		v |= uint64(b[0]&0x7f) << (7 * i)
		if b[0]&0x80 == 0 {
			break
		}
	}
	return v, nil
}

func readVarintBytes(b []byte) (uint64, int) {
	var v uint64
	for i, bt := range b {
		v |= uint64(bt&0x7f) << (7 * i)
		if bt&0x80 == 0 {
			return v, i + 1
		}
	}
	return v, len(b)
}

func v1Status(c int) string {
	switch c {
	case 100:
		return "SUCCESS"
	case 260:
		return "HOP_NO_CONN_TO_DST"
	case 261:
		return "HOP_CANT_DIAL_DST"
	case 262:
		return "HOP_CANT_OPEN_DST_STREAM"
	case 270:
		return "HOP_CANT_SPEAK_RELAY"
	case 280:
		return "HOP_CANT_RELAY_TO_SELF"
	case 400:
		return "MALFORMED_MESSAGE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", c)
	}
}

func v2Status(c int32) string {
	switch c {
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
		return fmt.Sprintf("UNKNOWN(%d)", c)
	}
}

func printResult(r *result) {
	fmt.Printf("Address: %s\n", r.addr)
	fmt.Printf("  TCP:     %s (%v)\n", ok(r.tcpOK), r.tcpDur)
	if !r.tcpOK {
		return
	}
	fmt.Printf("  TLS:     %s\n", ok(r.tlsOK))
	fmt.Printf("  Yamux:   %s\n", ok(r.yamux))
	fmt.Printf("  Relay Connect: %s (%v)\n", ok(r.yamux), r.yamuxDur)
	if !r.yamux {
		return
	}

	fmt.Printf("  Identify: %s\n", ok(r.idOK))
	if r.idOK {
		fmt.Printf("    PeerID:  %s\n", r.idPeer)
		fmt.Printf("    Agent:   %s\n", r.idAgent)
		if len(r.idProtos) > 0 {
			for _, p := range r.idProtos {
				if len(p) > 100 {
					p = p[:100] + "..."
				}
				fmt.Printf("    Protocol: %s\n", p)
			}
		}
	}

	printV1(r)
	printV2Hop(r)
	printV2Connect(r)
	printV2Stop(r)

	relay := ""
	if (r.v1Msg != nil && r.v1Msg.code == 100) || (r.v2connect != nil && r.v2connect.status == 100) {
		relay = " YES"
	}
	fmt.Printf("  RELAY CAPABLE:%s\n", relay)
}

func printV1(r *result) {
	if r.v1Neg {
		relay := ""
		if r.v1Msg != nil && r.v1Msg.code == 100 {
			relay = " YES"
		}
		fmt.Printf("  Circuit v1 (/libp2p/circuit/relay/0.1.0):\n")
		fmt.Printf("    Negotiated: yes\n")
		if r.v1Msg != nil {
			fmt.Printf("    CAN_HOP:    %d (%s)\n", r.v1Msg.code, r.v1Msg.codeStr)
		}
		fmt.Printf("    Relay:%s\n", relay)
	} else {
		fmt.Printf("  Circuit v1 (/libp2p/circuit/relay/0.1.0): no\n")
	}
}

func printV2Hop(r *result) {
	if r.v2hopNeg {
		relay := ""
		exp := ""
		if r.v2hop != nil && r.v2hop.status == 100 {
			relay = " YES"
			if r.v2hop.expire > 0 {
				exp = fmt.Sprintf(", expire=%ds", r.v2hop.expire)
			}
		}
		fmt.Printf("  Circuit v2 hop (/libp2p/circuit/relay/0.2.0/hop):\n")
		fmt.Printf("    Negotiated: yes\n")
		if r.v2hop != nil {
			fmt.Printf("    RESERVE:    %d (%s)%s\n", r.v2hop.status, r.v2hop.statusStr, exp)
		}
		fmt.Printf("    Relay:%s\n", relay)
	} else {
		fmt.Printf("  Circuit v2 hop (/libp2p/circuit/relay/0.2.0/hop): no\n")
	}
}

func printV2Connect(r *result) {
	if r.v2connect != nil {
		fmt.Printf("    CONNECT:   %d (%s)\n", r.v2connect.status, r.v2connect.statusStr)
		fmt.Printf("    Duration:  %v\n", r.connectDur)
	} else if r.v2hop != nil && r.v2hop.status == 100 {
		fmt.Printf("    CONNECT:   no response (not supported or timed out)\n")
		fmt.Printf("    Duration:  %v\n", r.connectDur)
	}
}

func printV2Stop(r *result) {
	if r.v2stopNeg {
		fmt.Printf("  Circuit v2 stop (/libp2p/circuit/relay/0.2.0/stop): yes\n")
	} else {
		fmt.Printf("  Circuit v2 stop (/libp2p/circuit/relay/0.2.0/stop): no\n")
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


