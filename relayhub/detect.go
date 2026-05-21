package relayhub

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

type IdentifyInfo struct {
	PeerID            string
	Agent             string
	Protos            []string
	SignedPeerRecord  []byte
}

type DetectResult struct {
	Addr string

	TCPOK       bool
	TCPDuration time.Duration

	TLSOK   bool
	YamuxOK bool

	IdentifyOK bool
	Identify   *IdentifyInfo

	V1OK     bool
	V1Code   int
	V1Status string

	V2HopOK         bool
	V2Status        int32
	V2Expire        uint64
	V2LimitDuration uint32
	V2LimitData     uint64
	V2ReservationAddrs [][]byte
	V2Voucher         []byte

	V2ConnectOK       bool
	V2ConnectStatus   int32
	V2ConnectDuration time.Duration

	V2StopOK bool
}

func DetectRelay(ctx context.Context, addr string, key ed25519.PrivateKey) *DetectResult {
	r := &DetectResult{Addr: addr}

	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()
	d := net.Dialer{}
	t0 := time.Now()
	raw, err := d.DialContext(dialCtx, "tcp", addr)
	r.TCPDuration = time.Since(t0)
	if err != nil {
		return r
	}
	r.TCPOK = true
	defer raw.Close()

	raw.SetDeadline(time.Now().Add(30 * time.Second))

	if err := MSSelect(raw, "/tls/1.0.0"); err != nil {
		return r
	}
	tlsConn, err := TLSClient(raw, key, ctx)
	if err != nil {
		return r
	}
	r.TLSOK = true
	defer tlsConn.Close()

	if err := MSSelectOver(tlsConn, "/yamux/1.0.0"); err != nil {
		return r
	}
	sess, err := yamux.Client(tlsConn, nil)
	if err != nil {
		return r
	}
	r.YamuxOK = true
	defer sess.Close()

	r.Identify, r.IdentifyOK = detectIdentify(sess)
	r.V1OK, r.V1Code, r.V1Status = detectV1(sess)
	r.V2HopOK, r.V2Status, r.V2Expire, r.V2LimitDuration, r.V2LimitData, r.V2ReservationAddrs, r.V2Voucher = detectV2Hop(sess)
	if r.V2Status == StatusOK {
		r.V2ConnectOK, r.V2ConnectStatus, r.V2ConnectDuration = detectV2Connect(sess, key)
	}
	r.V2StopOK = detectV2Stop(sess)

	return r
}

func detectIdentify(sess *yamux.Session) (*IdentifyInfo, bool) {
	s, err := sess.Open()
	if err != nil {
		return nil, false
	}
	defer s.Close()
	if MSSelect(s, "/ipfs/id/1.0.0") != nil {
		return nil, false
	}
	data, err := readOnePb(s)
	if err != nil {
		return nil, false
	}
	return parseIdentify(data), true
}

func parseIdentify(data []byte) *IdentifyInfo {
	info := &IdentifyInfo{}
	rest := data
	for len(rest) > 0 {
		tag, n := decodeVarint(rest)
		if n <= 0 {
			break
		}
		rest = rest[n:]
		field := int(tag >> 3)
		wt := int(tag & 7)
		if wt != 2 {
			if wt == 0 {
				_, n := decodeVarint(rest)
				if n <= 0 {
					break
				}
				rest = rest[n:]
			} else {
				break
			}
			continue
		}
		l, n := decodeVarint(rest)
		if n <= 0 || int(l) > len(rest[n:]) {
			break
		}
		rest = rest[n:]
		val := rest[:l]
		rest = rest[l:]
		switch field {
		case 1:
			h := sha256.Sum256(val)
			mh := append([]byte{0x12, 0x20}, h[:]...)
			info.PeerID = base58Encode(mh)
		case 3:
			info.Protos = append(info.Protos, string(val))
		case 6:
			info.Agent = string(val)
		case 8:
			info.SignedPeerRecord = val
		}
	}
	return info
}

func detectV1(sess *yamux.Session) (bool, int, string) {
	s, err := sess.Open()
	if err != nil {
		return false, 0, ""
	}
	defer s.Close()
	if MSSelect(s, CircuitV1ProtoID) != nil {
		return false, 0, ""
	}

	msg := &CircuitV1Message{Type: CircuitV1TypeCanHop}
	if err := writePbMessage(s, encodeCircuitV1(msg)); err != nil {
		return false, 0, ""
	}

	respData, err := readOnePb(s)
	if err != nil {
		return false, 0, circuitV1StatusString(0)
	}

	resp, err := decodeCircuitV1(respData)
	if err != nil {
		return true, 0, "PARSE_ERROR"
	}

	return true, resp.Code, circuitV1StatusString(resp.Code)
}

func detectV2Hop(sess *yamux.Session) (bool, int32, uint64, uint32, uint64, [][]byte, []byte) {
	s, err := sess.Open()
	if err != nil {
		return false, 0, 0, 0, 0, nil, nil
	}
	defer s.Close()
	if MSSelect(s, "/libp2p/circuit/relay/0.2.0/hop") != nil {
		return false, 0, 0, 0, 0, nil, nil
	}

	reserveMsg := &HopMessage{Type: HopTypeReserve}
	if err := writePbMessage(s, encodeHopMessage(reserveMsg)); err != nil {
		return false, 0, 0, 0, 0, nil, nil
	}

	respData, err := readOnePb(s)
	if err != nil {
		return false, 0, 0, 0, 0, nil, nil
	}

	resp, err := decodeHopMessage(respData)
	if err != nil {
		return false, 0, 0, 0, 0, nil, nil
	}

	expire := uint64(0)
	var addrs [][]byte
	var voucher []byte
	if resp.Reservation != nil {
		expire = resp.Reservation.Expire
		addrs = resp.Reservation.Addrs
		voucher = resp.Reservation.Voucher
	}
	var limitDur uint32
	var limitData uint64
	if resp.Limit != nil {
		limitDur = resp.Limit.Duration
		limitData = resp.Limit.Data
	}
	return true, resp.Status, expire, limitDur, limitData, addrs, voucher
}

func detectV2Connect(sess *yamux.Session, priv ed25519.PrivateKey) (bool, int32, time.Duration) {
	s, err := sess.Open()
	if err != nil {
		return false, 0, 0
	}
	defer s.Close()
	if MSSelect(s, "/libp2p/circuit/relay/0.2.0/hop") != nil {
		return false, 0, 0
	}

	pub := priv.Public().(ed25519.PublicKey)
	pid := computePeerID(pub)

	connMsg := &HopMessage{
		Type: HopTypeConnect,
		Peer: &Peer{ID: pid},
	}
	if err := writePbMessage(s, encodeHopMessage(connMsg)); err != nil {
		return false, 0, 0
	}

	t0 := time.Now()
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	respData, err := readOnePb(s)
	dur := time.Since(t0)
	if err != nil {
		return false, 0, dur
	}

	resp, err := decodeHopMessage(respData)
	if err != nil {
		return false, 0, dur
	}

	return true, resp.Status, dur
}

func detectV2Stop(sess *yamux.Session) bool {
	s, err := sess.Open()
	if err != nil {
		return false
	}
	defer s.Close()
	return MSSelect(s, "/libp2p/circuit/relay/0.2.0/stop") == nil
}

func computePeerID(pk ed25519.PublicKey) []byte {
	protoPubKey := append([]byte{0x08, 0x01, 0x12, 0x20}, pk...)
	h := sha256.Sum256(protoPubKey)
	return append([]byte{0x12, 0x20}, h[:]...)
}

type maProto struct {
	name string
	size int
}

var maProtos = map[uint64]maProto{
	0x04:   {"ip4", 4},
	0x06:   {"tcp", 2},
	0x29:   {"ip6", 16},
	0x35:   {"dns", -1},
	0x36:   {"dns4", -1},
	0x37:   {"dns6", -1},
	0x0111: {"udp", 2},
	0x0118: {"webrtc-direct", 0},
	0x0119: {"webrtc", 0},
	0x0122: {"p2p-circuit", 0},
	0x01a5: {"p2p", -1},
	0x01bb: {"https", 0},
	0x01c0: {"tls", 0},
	0x01c6: {"noise", 0},
	0x01cc: {"quic", 0},
	0x01cd: {"quic-v1", 0},
	0x01d1: {"webtransport", 0},
	0x01d2: {"certhash", -1},
	0x01dd: {"ws", -1},
	0x01de: {"wss", -1},
}

func MultiaddrString(b []byte) string {
	s := ""
	for len(b) > 0 {
		code, n := decodeVarint(b)
		if n <= 0 {
			break
		}
		b = b[n:]
		p, ok := maProtos[code]
		if !ok {
			s += fmt.Sprintf("/<proto-%d>", code)
			v, m := decodeVarint(b)
			if m > 0 && int(v) <= len(b)-m && int(v) < 256 {
				b = b[m+int(v):]
			}
			continue
		}
		s += "/" + p.name
		if p.size == 0 {
			continue
		}
		var val []byte
		if p.size > 0 {
			if len(b) < p.size {
				break
			}
			val = b[:p.size]
			b = b[p.size:]
		} else {
			v, m := decodeVarint(b)
			if m <= 0 || v > uint64(len(b)-m) {
				break
			}
			val = b[m : m+int(v)]
			b = b[m+int(v):]
		}
		switch p.name {
		case "ip4":
			s += fmt.Sprintf("/%d.%d.%d.%d", val[0], val[1], val[2], val[3])
		case "ip6":
			s += fmt.Sprintf("/%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
				val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15])
		case "tcp", "udp":
			s += fmt.Sprintf("/%d", uint(val[0])<<8|uint(val[1]))
		case "p2p":
			s += "/" + base58Encode(val)
		case "certhash":
			s += fmt.Sprintf("/%x", val)
		default:
			s += "/" + string(val)
		}
	}
	return s
}
