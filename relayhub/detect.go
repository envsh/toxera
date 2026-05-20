package relayhub

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

type IdentifyInfo struct {
	PeerID string
	Agent  string
	Protos []string
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

	V2HopOK  bool
	V2Status int32
	V2Expire uint64

	V2ConnectOK       bool
	V2ConnectStatus   int32
	V2ConnectDuration time.Duration

	V2StopOK bool
}

func DetectRelay(ctx context.Context, addr string, key ed25519.PrivateKey) *DetectResult {
	r := &DetectResult{Addr: addr}

	d := net.Dialer{}
	t0 := time.Now()
	raw, err := d.DialContext(ctx, "tcp", addr)
	r.TCPDuration = time.Since(t0)
	if err != nil {
		return r
	}
	r.TCPOK = true
	defer raw.Close()

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
	r.V2HopOK, r.V2Status, r.V2Expire = detectV2Hop(sess)
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

func detectV2Hop(sess *yamux.Session) (bool, int32, uint64) {
	s, err := sess.Open()
	if err != nil {
		return false, 0, 0
	}
	defer s.Close()
	if MSSelect(s, "/libp2p/circuit/relay/0.2.0/hop") != nil {
		return false, 0, 0
	}

	reserveMsg := &HopMessage{Type: HopTypeReserve}
	if err := writePbMessage(s, encodeHopMessage(reserveMsg)); err != nil {
		return false, 0, 0
	}

	respData, err := readOnePb(s)
	if err != nil {
		return false, 0, 0
	}

	resp, err := decodeHopMessage(respData)
	if err != nil {
		return false, 0, 0
	}

	expire := uint64(0)
	if resp.Reservation != nil {
		expire = resp.Reservation.Expire
	}
	return true, resp.Status, expire
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
