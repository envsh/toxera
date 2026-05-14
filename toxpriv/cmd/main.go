package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/envsh/toxera/toxpriv"
)

type oobPkt struct {
	pk   string
	data string
}

func main() {
	var peerpk, keyfile string
	flag.StringVar(&peerpk, "p", "", "peer public key (hex)")
	flag.StringVar(&keyfile, "f", "node.key", "key file path")
	flag.Parse()

	mem := toxpriv.OsMemory()
	rng := toxpriv.OsRandom()
	ns := toxpriv.OsNetwork()
	logger := toxpriv.LoggerNew(mem)
	monoT := toxpriv.MonoTimeNew(mem, nil, nil)
	np := toxpriv.NetprofNew(logger, mem)

	pk, sk := loadOrGenKeys(keyfile, rng)
	log.Printf("pk=%s\n", strings.ToUpper(hex.EncodeToString(pk)))

	proxy := make([]byte, 256)
	conns := toxpriv.NewTCPConnections(logger, mem, rng, ns, monoT,
		unsafe.Pointer(&sk[0]), unsafe.Pointer(&proxy[0]), np)
	if unsafe.Pointer(conns) == nil {
		log.Fatal("NewTCPConnections failed")
	}
	defer toxpriv.KillTCPConnections(conns)

	toxpriv.SetTCPOnionStatus(conns, true)

	oobCh := make(chan oobPkt, 8)
	var keepAlive []any

	oobFn := func(object, publicKey unsafe.Pointer, connNum int32, packet unsafe.Pointer, length uint16, userdata unsafe.Pointer) int32 {
		data := string(unsafe.Slice((*byte)(packet), int(length)))
		pkHex := strings.ToUpper(hex.EncodeToString(unsafe.Slice((*byte)(publicKey), 32)))
		oobCh <- oobPkt{pkHex, data}
		return 0
	}
	cb := purego.NewCallback(oobFn)
	keepAlive = append(keepAlive, oobFn)
	toxpriv.SetOOBPacketTCPConnectionCallback(conns, cb, unsafe.Pointer(conns))

	var relayPKs [][]byte
	for _, n := range bootstrapNodes {
		ipp, err := toxpriv.MakeIPPort(n.IPv4, n.Port)
		if err != nil {
			log.Printf("skip relay %s: %v", n.IPv4, err)
			continue
		}
		pkb := mustHexDecode(n.PublicKey)
		rv := toxpriv.AddTCPRelayGlobal(conns, unsafe.Pointer(&ipp), unsafe.Pointer(&pkb[0]))
		if rv != 0 {
			log.Printf("AddTCPRelayGlobal(%s) = %d", n.IPv4, rv)
		}
		relayPKs = append(relayPKs, pkb)
	}

	log.Println("wait for relay connection...")
	btime := time.Now()
	for toxpriv.TCPConnectedRelaysCount(conns) == 0 {
		toxpriv.DoTCPConnections(logger, conns, nil)
		time.Sleep(60 * time.Millisecond)
	}
	log.Println("connected after", time.Since(btime))

	go func() {
		for pkt := range oobCh {
			short := pkt.pk[:7]
			log.Printf("<< %s %s", short, pkt.data)
		}
	}()

	if peerpk != "" {
		log.Println("sender mode")
		peerPK := mustHexDecode(peerpk)
		btime := time.Now()
		for i := 0; ; i++ {
			toxpriv.DoTCPConnections(logger, conns, nil)
			time.Sleep(60 * time.Millisecond)
			if time.Since(btime) < 3*time.Second {
				continue
			}
			btime = time.Now()

			msg := fmt.Sprintf("from %s %d", keyfile, i)
			if len(relayPKs) == 0 {
				continue
			}
			rv := toxpriv.TCPSendOOBPacketUsingRelay(conns,
				unsafe.Pointer(&relayPKs[0][0]),
				unsafe.Pointer(&peerPK[0]),
				unsafe.Pointer(&[]byte(msg)[0]), int16(len(msg)))
			log.Printf(">> %s sent=%d", msg, rv)
		}
	} else {
		log.Println("receive mode")
		for {
			toxpriv.DoTCPConnections(logger, conns, nil)
			time.Sleep(60 * time.Millisecond)
		}
	}
}

func loadOrGenKeys(path string, rng toxpriv.Random) (pk, sk []byte) {
	pk = make([]byte, 32)
	sk = make([]byte, 32)

	if f, err := os.Open(path); err == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			if strings.HasPrefix(line, "pk=") {
				b, _ := hex.DecodeString(line[3:])
				copy(pk, b)
			} else if strings.HasPrefix(line, "sk=") {
				b, _ := hex.DecodeString(line[3:])
				copy(sk, b)
			}
		}
		log.Println("loaded key file", path)
	} else {
		toxpriv.CryptoNewKeypair(rng, unsafe.Pointer(&pk[0]), unsafe.Pointer(&sk[0]))
		f, _ := os.Create(path)
		if f != nil {
			fmt.Fprintf(f, "pk=%s\n", strings.ToUpper(hex.EncodeToString(pk)))
			fmt.Fprintf(f, "sk=%s\n", strings.ToUpper(hex.EncodeToString(sk)))
			f.Close()
		}
		log.Println("generated new key, saved to", path)
	}
	return
}

type bootstrapNode struct {
	IPv4      string
	Port      uint16
	PublicKey string
}

var bootstrapNodes = []bootstrapNode{
	{IPv4: "43.198.227.166", Port: 3389, PublicKey: "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E"},
	{IPv4: "86.107.187.54", Port: 33445, PublicKey: "2C0F90965134C7BEFAFE72B077A19221628D7045BB51C1165A2C75CDB2B32634"},
}

func mustHexDecode(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := nibble(s[i])
		lo := nibble(s[i+1])
		b[i/2] = (hi << 4) | lo
	}
	return b
}

func nibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return 0
	}
}
