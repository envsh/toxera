//go:build btc

package fedboot

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/envsh/toxera/fedkey"
)

////////////

type Btc struct {

}

var _ = regme(&Btc{})

func (o *Btc) Start() error {
	return nil
}

func (o *Btc) Stop() error {
	return nil
}

func (o *Btc) Info() string {
	return "{}"
}

func MainBtc() {
	mainBtc()
}

//////


const (
	bitcoinMagic   = 0xD9B4BEF9
	btcProtocolVer = 70015
	btcCmdLen      = 12
	btcHeaderLen   = 24
	btcServiceNode = 1
	btcServiceChat = 1 << 24
)

var btcDNSSeds = []string{
	"seed.bitcoin.sipa.be",
	"dnsseed.bluematt.me",
	"dnsseed.bitcoin.dashjr.org",
	"seed.bitcoinstats.com",
	"seed.bitnodes.io",
}

type SeedResult struct {
	Host    string
	Addrs   []string
	Success bool
	Err     string
}

type BsPeerInfo struct {
	Addr   string
	Pubkey string
	Conn   net.Conn
}

type BtcBootConfig struct {
	KeyFile    string
	ListenPort int
	Timeout    time.Duration
}

type BtcBootResult struct {
	PubkeyHex  string
	Seeds      []SeedResult
	ConnectOK  []BsPeerInfo
	ConnectNOK []string
	Discovered int
	BootTime   time.Duration
}

func mainBtc() {
	keyFile := flag.String("k", "key.txt", "keyring file")
	port := flag.Int("l", 8333, "TCP listen port")
	timeoutSec := flag.Int("t", 120, "bootstrap timeout (seconds)")
	flag.Parse()

	cfg := BtcBootConfig{
		KeyFile:    *keyFile,
		ListenPort: *port,
		Timeout:    time.Duration(*timeoutSec) * time.Second,
	}

	res, err := BtcBootstrap(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  ✅ BITCOIN ONLINE")
	fmt.Println("========================================")
	fmt.Printf("  Node pubkey:  %s\n", res.PubkeyHex)
	fmt.Printf("  Active peers: %d\n", len(res.ConnectOK))
	fmt.Printf("  Discovered:   %d addresses\n", res.Discovered)
	fmt.Printf("  Boot time:    %v\n", res.BootTime)
	fmt.Println("========================================")
}

func BtcBootstrap(ctx context.Context, cfg BtcBootConfig) (*BtcBootResult, error) {
	start := time.Now()
	fmt.Println("=== Key Loading ===")
	kr, err := fedkey.LoadKeyRing(cfg.KeyFile, true)
	if err != nil {
		return nil, fmt.Errorf("load keyring: %w", err)
	}
	fmt.Println("[+] Loaded key from:", cfg.KeyFile)
	myPub := hex.EncodeToString(kr.Secp256k1Pub())
	pubShort := myPub
	if len(pubShort) > 16 {
		pubShort = pubShort[:16] + "..."
	}
	fmt.Printf("    My pubkey: %s\n\n", pubShort)

	bootCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	fmt.Println("=== Phase 1: DNS Seed Resolution ===")
	fmt.Printf("[*] Resolving %d DNS seeds...\n", len(btcDNSSeds))
	seeds := resolveSeeds(bootCtx)
	totalAddrs := 0
	okSeeds := 0
	for _, s := range seeds {
		if s.Success {
			okSeeds++
			totalAddrs += len(s.Addrs)
			fmt.Printf("  ✓ %-35s → %d addresses\n", s.Host, len(s.Addrs))
			for i, a := range s.Addrs {
				if i >= 5 {
					fmt.Printf("      ... and %d more\n", len(s.Addrs)-5)
					break
				}
				fmt.Printf("      - %s\n", a)
			}
		} else {
			fmt.Printf("  ✗ %-35s → FAILED: %s\n", s.Host, s.Err)
		}
	}
	fmt.Printf("[+] %d/%d seeds resolved, %d addresses total\n\n", okSeeds, len(btcDNSSeds), totalAddrs)

	if totalAddrs == 0 {
		return nil, fmt.Errorf("no addresses resolved from DNS seeds")
	}

	allAddrs := make([]string, 0, totalAddrs)
	for _, s := range seeds {
		allAddrs = append(allAddrs, s.Addrs...)
	}

	fmt.Println("=== Phase 2: TCP Connect & Handshake ===")
	fmt.Printf("[*] Connecting to %d bootstrap peers...\n", len(allAddrs))

	var (
		oks   []BsPeerInfo
		noks  []string
		oksMu sync.Mutex
		noksMu sync.Mutex
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 10)
	)

	for _, addr := range allAddrs {
		addr := addr
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			conn, peerPub, err := connectPeer(bootCtx, addr, kr, myPub, 10*time.Second)
			if err != nil {
				noksMu.Lock()
				noks = append(noks, addr)
				noksMu.Unlock()
				fmt.Printf("  ✗ %-21s → %v\n", addr, err)
				return
			}
			pubShort := peerPub
			if len(pubShort) > 16 {
				pubShort = pubShort[:16] + "..."
			}
			oksMu.Lock()
			oks = append(oks, BsPeerInfo{Addr: addr, Pubkey: peerPub, Conn: conn})
			oksMu.Unlock()
			fmt.Printf("  ✓ %-21s → HANDSHAKE OK   [pubkey: %s]\n", addr, pubShort)
		}()
	}
	wg.Wait()
	fmt.Printf("[+] %d/%d handshakes succeeded\n\n", len(oks), len(allAddrs))

	if len(oks) == 0 {
		return nil, fmt.Errorf("no peers connected")
	}

	fmt.Println("=== Phase 3: Peer Discovery (getaddr/addr) ===")
	fmt.Printf("[*] Requesting peer lists from %d peers...\n", len(oks))
	discoveredSet := make(map[string]struct{})
	var discMu sync.Mutex
	var discWg sync.WaitGroup

	for i := range oks {
		p := &oks[i]
		discWg.Add(1)
		go func(pi *BsPeerInfo) {
			defer discWg.Done()
			addrs, err := requestAddrs(bootCtx, pi.Conn, 10*time.Second)
			if err != nil {
				fmt.Printf("  ✗ from %-21s → %v\n", pi.Addr, err)
				return
			}
			newCount := 0
			discMu.Lock()
			for _, a := range addrs {
				if _, exists := discoveredSet[a]; !exists {
					discoveredSet[a] = struct{}{}
					newCount++
				}
			}
			discMu.Unlock()
			fmt.Printf("  ✓ from %-21s → %d addresses (new: %d)\n", pi.Addr, len(addrs), newCount)
		}(p)
	}
	discWg.Wait()
	fmt.Printf("[+] Total discovered: %d unique addresses\n\n", len(discoveredSet))

	fmt.Println("=== Phase 4: Go Online ===")
	fmt.Printf("[*] Starting listener on :%d ...\n", cfg.ListenPort)

	go btcListener(cfg.ListenPort)

	for i, p := range oks {
		go keepAlive(p.Conn)
		short := p.Pubkey
		if len(short) > 16 {
			short = short[:16] + "..."
		}
		fmt.Printf("  [%02d] %s  %s\n", i+1, short, p.Addr)
	}

	return &BtcBootResult{
		PubkeyHex:  myPub,
		Seeds:      seeds,
		ConnectOK:  oks,
		ConnectNOK: noks,
		Discovered: len(discoveredSet),
		BootTime:   time.Since(start),
	}, nil
}

func resolveSeeds(ctx context.Context) []SeedResult {
	var results []SeedResult
	for _, host := range btcDNSSeds {
		r := SeedResult{Host: host}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			r.Success = false
			r.Err = err.Error()
			results = append(results, r)
			continue
		}
		r.Success = true
		r.Addrs = make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				r.Addrs = append(r.Addrs, net.JoinHostPort(ip.IP.String(), "8333"))
			}
		}
		if len(r.Addrs) == 0 {
			r.Success = false
			r.Err = "no IPv4 addresses resolved"
		}
		results = append(results, r)
	}
	return results
}

func connectPeer(ctx context.Context, addr string, kr *fedkey.KeyRing, myPub string, timeout time.Duration) (net.Conn, string, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("dial: %w", err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	peerPub, err := clientHandshake(conn, myPub)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("handshake: %w", err)
	}

	conn.SetDeadline(time.Time{})
	return conn, peerPub, nil
}

func clientHandshake(conn net.Conn, myPub string) (string, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	v := btcBuildVersion(myPub, conn.LocalAddr(), conn.RemoteAddr(), binary.LittleEndian.Uint64(nonce))
	if err := btcWriteMsg(conn, "version", v); err != nil {
		return "", fmt.Errorf("send version: %w", err)
	}

	msg, err := btcReadMsg(conn)
	if err != nil {
		return "", fmt.Errorf("read version: %w", err)
	}
	cmd := strings.TrimRight(string(msg.command[:]), "\x00")
	if cmd != "version" {
		return "", fmt.Errorf("expected version, got %s", cmd)
	}
	peerPub := btcParseVersionPubkey(msg.payload)

	if err := btcWriteMsg(conn, "verack", nil); err != nil {
		return "", fmt.Errorf("send verack: %w", err)
	}

	msg, err = btcReadMsg(conn)
	if err != nil {
		return "", fmt.Errorf("read verack: %w", err)
	}
	cmd = strings.TrimRight(string(msg.command[:]), "\x00")
	if cmd != "verack" {
		return "", fmt.Errorf("expected verack, got %s", cmd)
	}

	return peerPub, nil
}

func serverHandshake(conn net.Conn, myPub string) (string, error) {
	msg, err := btcReadMsg(conn)
	if err != nil {
		return "", fmt.Errorf("read version: %w", err)
	}
	cmd := strings.TrimRight(string(msg.command[:]), "\x00")
	if cmd != "version" {
		return "", fmt.Errorf("expected version, got %s", cmd)
	}
	peerPub := btcParseVersionPubkey(msg.payload)

	nonce := make([]byte, 8)
	rand.Read(nonce)
	v := btcBuildVersion(myPub, conn.LocalAddr(), conn.RemoteAddr(), binary.LittleEndian.Uint64(nonce))
	if err := btcWriteMsg(conn, "version", v); err != nil {
		return "", fmt.Errorf("send version: %w", err)
	}

	if err := btcWriteMsg(conn, "verack", nil); err != nil {
		return "", fmt.Errorf("send verack: %w", err)
	}

	msg, err = btcReadMsg(conn)
	if err != nil {
		return "", fmt.Errorf("read verack: %w", err)
	}
	cmd = strings.TrimRight(string(msg.command[:]), "\x00")
	if cmd != "verack" {
		return "", fmt.Errorf("expected verack, got %s", cmd)
	}

	return peerPub, nil
}

func requestAddrs(ctx context.Context, conn net.Conn, timeout time.Duration) ([]string, error) {
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	if err := btcWriteMsg(conn, "getaddr", nil); err != nil {
		return nil, fmt.Errorf("send getaddr: %w", err)
	}

	for {
		msg, err := btcReadMsg(conn)
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}
		cmd := strings.TrimRight(string(msg.command[:]), "\x00")
		switch cmd {
		case "addr":
			return parseAddrMsg(msg.payload), nil
		case "ping":
			btcWriteMsg(conn, "pong", nil)
		default:
			continue
		}
	}
}

func parseAddrMsg(payload []byte) []string {
	r := bytes.NewReader(payload)
	count, err := btcReadVarInt(r)
	if err != nil || count == 0 {
		return nil
	}
	var addrs []string
	for i := uint64(0); i < count; i++ {
		buf := make([]byte, 30)
		if _, err := io.ReadFull(r, buf); err != nil {
			break
		}
		ip := net.IP(buf[8:24])
		port := binary.BigEndian.Uint16(buf[24:26])
		addrs = append(addrs, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
		if len(addrs) >= 1000 {
			break
		}
	}
	return addrs
}

func btcReadVarInt(r *bytes.Reader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch b {
	case 0xFD:
		var tmp [2]byte
		if _, err := io.ReadFull(r, tmp[:]); err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint16(tmp[:])), nil
	case 0xFE:
		var tmp [4]byte
		if _, err := io.ReadFull(r, tmp[:]); err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint32(tmp[:])), nil
	case 0xFF:
		var tmp [8]byte
		if _, err := io.ReadFull(r, tmp[:]); err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(tmp[:]), nil
	default:
		return uint64(b), nil
	}
}

func keepAlive(conn net.Conn) {
	for {
		time.Sleep(30 * time.Second)
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := btcWriteMsg(conn, "ping", nil); err != nil {
			conn.Close()
			return
		}
		msg, err := btcReadMsg(conn)
		conn.SetDeadline(time.Time{})
		if err != nil {
			conn.Close()
			return
		}
		cmd := strings.TrimRight(string(msg.command[:]), "\x00")
		if cmd != "pong" {
			continue
		}
	}
}

func btcListener(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("listener failed: %v", err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go btcHandleIncoming(conn)
	}
}

func btcHandleIncoming(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, err := serverHandshake(conn, "")
	if err != nil {
		return
	}
	conn.SetDeadline(time.Time{})

	for {
		msg, err := btcReadMsg(conn)
		if err != nil {
			return
		}
		cmd := strings.TrimRight(string(msg.command[:]), "\x00")
		switch cmd {
		case "ping":
			btcWriteMsg(conn, "pong", nil)
		case "getaddr":
			btcWriteMsg(conn, "addr", nil)
		default:
		}
	}
}

func btcBuildVersion(myPub string, localAddr, remoteAddr net.Addr, nonce uint64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, int32(btcProtocolVer))
	binary.Write(buf, binary.LittleEndian, uint64(btcServiceNode|btcServiceChat))
	binary.Write(buf, binary.LittleEndian, time.Now().Unix())

	var addrRecv [26]byte
	var addrFrom [26]byte
	if remoteAddr != nil {
		ra := remoteAddr.(*net.TCPAddr)
		copy(addrRecv[8:24], ra.IP.To16())
		binary.BigEndian.PutUint16(addrRecv[24:26], uint16(ra.Port))
	}
	if localAddr != nil {
		la := localAddr.(*net.TCPAddr)
		copy(addrFrom[8:24], la.IP.To16())
		binary.BigEndian.PutUint16(addrFrom[24:26], uint16(la.Port))
	}
	buf.Write(addrRecv[:])
	buf.Write(addrFrom[:])
	binary.Write(buf, binary.LittleEndian, nonce)

	ua := fmt.Sprintf("/bitcoin_bs:pubkey=%s/", myPub)
	btcWriteVarStr(buf, ua)

	binary.Write(buf, binary.LittleEndian, int32(0))
	buf.WriteByte(0)
	return buf.Bytes()
}

func btcParseVersionPubkey(payload []byte) string {
	r := bytes.NewReader(payload)
	r.Seek(80, 0)
	ua, err := btcReadVarStr(r)
	if err != nil {
		return ""
	}
	idx := strings.Index(ua, "pubkey=")
	if idx < 0 {
		return ""
	}
	p := ua[idx+7:]
	end := strings.IndexByte(p, '/')
	if end < 0 {
		end = len(p)
	}
	if end >= 128 {
		end = 128
	}
	return p[:end]
}

func btcWriteMsg(conn net.Conn, cmd string, payload []byte) error {
	if len(cmd) > btcCmdLen {
		cmd = cmd[:btcCmdLen]
	}
	var header [btcHeaderLen]byte
	binary.LittleEndian.PutUint32(header[0:4], bitcoinMagic)
	copy(header[4:16], []byte(cmd))
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(payload)))
	if len(payload) > 0 {
		chk := fedkey.Sha256d(payload)
		copy(header[20:24], chk[:4])
	}
	if _, err := conn.Write(header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

type btcMsg struct {
	command [12]byte
	payload []byte
}

func btcReadMsg(conn net.Conn) (*btcMsg, error) {
	var header [btcHeaderLen]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	magic := binary.LittleEndian.Uint32(header[0:4])
	if magic != bitcoinMagic {
		return nil, fmt.Errorf("bad magic: %x", magic)
	}
	var cmd [12]byte
	copy(cmd[:], header[4:16])
	length := binary.LittleEndian.Uint32(header[16:20])
	var chk [4]byte
	copy(chk[:], header[20:24])

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
		realChk := fedkey.Sha256d(payload)
		if chk != [4]byte(realChk[:4]) {
			return nil, fmt.Errorf("bad checksum")
		}
	}
	return &btcMsg{command: cmd, payload: payload}, nil
}

func btcWriteVarStr(buf *bytes.Buffer, s string) {
	l := len(s)
	if l < 0xFD {
		buf.WriteByte(byte(l))
	} else if l <= 0xFFFF {
		buf.WriteByte(0xFD)
		var tmp [2]byte
		binary.LittleEndian.PutUint16(tmp[:], uint16(l))
		buf.Write(tmp[:])
	} else {
		buf.WriteByte(0xFE)
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], uint32(l))
		buf.Write(tmp[:])
	}
	buf.WriteString(s)
}

func btcReadVarStr(r *bytes.Reader) (string, error) {
	b, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	var l uint64
	switch b {
	case 0xFD:
		var tmp [2]byte
		if _, err := io.ReadFull(r, tmp[:]); err != nil {
			return "", err
		}
		l = uint64(binary.LittleEndian.Uint16(tmp[:]))
	case 0xFE:
		var tmp [4]byte
		if _, err := io.ReadFull(r, tmp[:]); err != nil {
			return "", err
		}
		l = uint64(binary.LittleEndian.Uint32(tmp[:]))
	case 0xFF:
		var tmp [8]byte
		if _, err := io.ReadFull(r, tmp[:]); err != nil {
			return "", err
		}
		l = binary.LittleEndian.Uint64(tmp[:])
	default:
		l = uint64(b)
	}
	s := make([]byte, l)
	if _, err := io.ReadFull(r, s); err != nil {
		return "", err
	}
	return string(s), nil
}
