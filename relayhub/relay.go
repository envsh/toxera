package relayhub

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

var ErrRelayStatus = errors.New("relay status error")
var ErrClosed = errors.New("connection closed")

type PeerID []byte

func ParsePeerID(s string) (PeerID, error) {
	return base58Decode(s)
}

func (id PeerID) String() string {
	return base58Encode(id)
}

func (id PeerID) Clone() PeerID {
	if id == nil {
		return nil
	}
	c := make([]byte, len(id))
	copy(c, id)
	return c
}

type RelayedConn struct {
	conn net.Conn
	once sync.Once
}

func newRelayedConn(c net.Conn) *RelayedConn {
	return &RelayedConn{conn: c}
}

func (rc *RelayedConn) Read(b []byte) (int, error) {
	return rc.conn.Read(b)
}

func (rc *RelayedConn) Write(b []byte) (int, error) {
	return rc.conn.Write(b)
}

func (rc *RelayedConn) Close() error {
	var err error
	rc.once.Do(func() {
		err = rc.conn.Close()
	})
	return err
}

func (rc *RelayedConn) LocalAddr() net.Addr  { return rc.conn.LocalAddr() }
func (rc *RelayedConn) RemoteAddr() net.Addr { return rc.conn.RemoteAddr() }

func (rc *RelayedConn) SetDeadline(t time.Time) error      { return rc.conn.SetDeadline(t) }
func (rc *RelayedConn) SetReadDeadline(t time.Time) error  { return rc.conn.SetReadDeadline(t) }
func (rc *RelayedConn) SetWriteDeadline(t time.Time) error { return rc.conn.SetWriteDeadline(t) }

type RelayClient struct {
	id      PeerID
	key     ed25519.PrivateKey
	session *yamux.Session
	mu      sync.Mutex

	reservationExpiry time.Time
	limit             *Limit
	watchdogCancel    context.CancelFunc
}

func NewRelayClient(id PeerID, key ed25519.PrivateKey) *RelayClient {
	return &RelayClient{id: id.Clone(), key: key}
}

func (c *RelayClient) PeerID() PeerID {
	return c.id.Clone()
}

func (c *RelayClient) Connect(ctx context.Context, relayAddr string) error {
	c.mu.Lock()
	if c.session != nil {
		c.mu.Unlock()
		return errors.New("already connected")
	}
	c.mu.Unlock()

	secure, err := c.dialNoise(ctx, relayAddr)
	if err != nil {
		secure, err = ConnectTLS(ctx, relayAddr, c.key)
		if err != nil {
			return fmt.Errorf("connect failed (noise+tls): %w", err)
		}
	}

	c.mu.Lock()
	if err := c.setupSession(secure); err != nil {
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()

	c.startWatchdog(ctx)
	return nil
}

func (c *RelayClient) ConnectTLS(ctx context.Context, relayAddr string) error {
	c.mu.Lock()
	if c.session != nil {
		c.mu.Unlock()
		return errors.New("already connected")
	}
	c.mu.Unlock()

	secure, err := ConnectTLS(ctx, relayAddr, c.key)
	if err != nil {
		return err
	}

	c.mu.Lock()
	if err := c.setupSession(secure); err != nil {
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()

	c.startWatchdog(ctx)
	return nil
}

func (c *RelayClient) dialNoise(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(15 * time.Second)
	}
	if err := MSSelect(raw, "/noise"); err != nil {
		raw.Close()
		return nil, err
	}
	secure, err := noiseHandshake(raw, c.key)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return secure, nil
}

func (c *RelayClient) setupSession(secure net.Conn) error {
	if err := MSSelectOver(secure, "/yamux/1.0.0"); err != nil {
		secure.Close()
		return fmt.Errorf("yamux negotiate: %w", err)
	}
	session, err := newYamuxClient(secure)
	if err != nil {
		secure.Close()
		return fmt.Errorf("yamux client: %w", err)
	}
	c.session = session

	go func() {
		<-session.CloseChan()
		log.Printf("yamux session closed")
	}()

	go c.pullIdentify(session)

	go func() {
		stream, err := session.Open()
		if err != nil {
			return
		}
		if err := MSSelect(stream, CircuitV1ProtoID); err != nil {
			stream.Close()
			return
		}
		msg := &CircuitV1Message{Type: CircuitV1TypeCanHop}
		writePbMessage(stream, encodeCircuitV1(msg))
		data, _ := readOnePb(stream)
		resp, _ := decodeCircuitV1(data)
		if resp != nil {
			log.Printf("setupSession: relay CAN_HOP response code=%d (%s)", resp.Code, circuitV1StatusString(resp.Code))
		}
		stream.Close()
	}()

	return nil
}

func (c *RelayClient) startWatchdog(ctx context.Context) {
	c.mu.Lock()
	if c.watchdogCancel != nil {
		c.mu.Unlock()
		return
	}
	watchCtx, cancel := context.WithCancel(ctx)
	c.watchdogCancel = cancel
	c.mu.Unlock()

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-t.C:
			}
			c.mu.Lock()
			s := c.session
			c.mu.Unlock()
			if s == nil || s.IsClosed() {
				return
			}
			stream, err := s.Open()
			if err != nil {
				log.Printf("watchdog: Open failed: %v", err)
				continue
			}
			err = MSSelectOver(stream, "/ipfs/id/1.0.0")
			if err != nil {
				log.Printf("watchdog: MSSelect failed: %v", err)
				stream.Close()
				continue
			}
			stream.Close()
		}
	}()
}

func (c *RelayClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.watchdogCancel != nil {
		c.watchdogCancel()
		c.watchdogCancel = nil
	}
	if c.session != nil {
		err := c.session.Close()
		c.session = nil
		return err
	}
	return nil
}

func (c *RelayClient) HasReservation() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.reservationExpiry.IsZero() && time.Now().Before(c.reservationExpiry)
}

func (c *RelayClient) ReservationExpiry() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reservationExpiry
}

func (c *RelayClient) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session != nil && !c.session.IsClosed()
}

func (c *RelayClient) ConnectThroughRelay(ctx context.Context, dstPeerID PeerID) (*RelayedConn, error) {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()

	if s == nil {
		return nil, errors.New("not connected to relay, call Connect first")
	}

	conn, v2Err := c.connectV2Hop(s, dstPeerID)
	if v2Err == nil {
		return conn, nil
	}

	conn, v1Err := c.connectV1Hop(s, dstPeerID)
	if v1Err == nil {
		return conn, nil
	}

	return nil, fmt.Errorf("relay connect failed:\n  v2: %w\n  v1: %w", v2Err, v1Err)
}

func (c *RelayClient) connectV2Hop(s *yamux.Session, dstPeerID PeerID) (*RelayedConn, error) {
	stream, err := s.Open()
	if err != nil {
		return nil, fmt.Errorf("open yamux stream: %w", err)
	}

	stream.SetDeadline(time.Now().Add(60 * time.Second))

	if err := MSSelect(stream, "/libp2p/circuit/relay/0.2.0/hop"); err != nil {
		stream.Close()
		return nil, err
	}

	hopMsg := &HopMessage{
		Type: HopTypeConnect,
		Peer: &Peer{ID: dstPeerID},
	}
	data := encodeHopMessage(hopMsg)

	if err := writePbMessage(stream, data); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}

	respData, err := readOnePb(stream)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}

	resp, err := decodeHopMessage(respData)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("decode CONNECT response: %w", err)
	}

	if resp.Type != HopTypeStatus {
		stream.Close()
		return nil, fmt.Errorf("%w: expected STATUS, got type %d", ErrRelayStatus, resp.Type)
	}

	if resp.Status != StatusOK {
		stream.Close()
		return nil, fmt.Errorf("%w: %s", ErrRelayStatus, statusString(resp.Status))
	}

	return newRelayedConn(stream), nil
}

func (c *RelayClient) connectV1Hop(s *yamux.Session, dstPeerID PeerID) (*RelayedConn, error) {
	stream, err := s.Open()
	if err != nil {
		return nil, fmt.Errorf("open yamux stream: %w", err)
	}

	stream.SetDeadline(time.Now().Add(60 * time.Second))

	if err := MSSelect(stream, CircuitV1ProtoID); err != nil {
		stream.Close()
		return nil, fmt.Errorf("v1 negotiate: %w", err)
	}

	msg := &CircuitV1Message{
		Type:    CircuitV1TypeHop,
		SrcPeer: &Peer{ID: c.id.Clone()},
		DstPeer: &Peer{ID: dstPeerID},
	}
	data := encodeCircuitV1(msg)

	if err := writePbMessage(stream, data); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send HOP: %w", err)
	}

	respData, err := readOnePb(stream)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("read v1 response: %w", err)
	}

	resp, err := decodeCircuitV1(respData)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("decode v1 response: %w", err)
	}

	if resp.Type != CircuitV1TypeStatus {
		stream.Close()
		return nil, fmt.Errorf("%w: expected STATUS, got type %d", ErrRelayStatus, resp.Type)
	}

	if resp.Code != CircuitV1StatusSuccess {
		stream.Close()
		return nil, fmt.Errorf("%w: v1 %s", ErrRelayStatus, circuitV1StatusString(resp.Code))
	}

	return newRelayedConn(stream), nil
}

func ConnectThroughRelay(ctx context.Context, relayAddr string, dstPeerID PeerID) (*RelayedConn, error) {
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial relay %s: %w", relayAddr, err)
	}

	if err := MSSelect(raw, "/libp2p/circuit/relay/0.2.0/hop"); err != nil {
		raw.Close()
		return nil, fmt.Errorf("protocol negotiate: %w", err)
	}

	hopMsg := &HopMessage{
		Type: HopTypeConnect,
		Peer: &Peer{ID: dstPeerID},
	}
	data := encodeHopMessage(hopMsg)
	if err := writePbMessage(raw, data); err != nil {
		raw.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}

	respData, err := readOnePb(raw)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}

	resp, err := decodeHopMessage(respData)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("decode CONNECT response: %w", err)
	}

	if resp.Type != HopTypeStatus {
		raw.Close()
		return nil, fmt.Errorf("%w: expected STATUS, got type %d", ErrRelayStatus, resp.Type)
	}

	if resp.Status != StatusOK {
		raw.Close()
		return nil, fmt.Errorf("%w: %s", ErrRelayStatus, statusString(resp.Status))
	}

	return newRelayedConn(raw), nil
}

func (c *RelayClient) Reserve(ctx context.Context) error {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()

	if s == nil {
		return errors.New("not connected to relay, call Connect first")
	}

	stream, err := s.Open()
	if err != nil {
		return fmt.Errorf("open yamux stream: %w", err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(60 * time.Second))

	if err := MSSelect(stream, "/libp2p/circuit/relay/0.2.0/hop"); err != nil {
		return fmt.Errorf("hop negotiate: %w", err)
	}

	reserveMsg := &HopMessage{Type: HopTypeReserve}
	data := encodeHopMessage(reserveMsg)
	if err := writePbMessage(stream, data); err != nil {
		return fmt.Errorf("send RESERVE: %w", err)
	}

	respData, err := readOnePb(stream)
	if err != nil {
		return fmt.Errorf("read RESERVE response: %w", err)
	}

	resp, err := decodeHopMessage(respData)
	if err != nil {
		return fmt.Errorf("decode RESERVE response: %w", err)
	}

	if resp.Type != HopTypeStatus {
		return fmt.Errorf("%w: expected STATUS, got type %d", ErrRelayStatus, resp.Type)
	}
	if resp.Status != StatusOK {
		return fmt.Errorf("%w: %s (reservation refused)", ErrRelayStatus, statusString(resp.Status))
	}

	if resp.Reservation != nil {
		c.mu.Lock()
		c.reservationExpiry = time.Unix(int64(resp.Reservation.Expire), 0)
		c.mu.Unlock()
		log.Printf("Reserve: reservation obtained, expire=%ds", resp.Reservation.Expire)
	}
	if resp.Limit != nil {
		c.mu.Lock()
		c.limit = resp.Limit
		c.mu.Unlock()
		log.Printf("Reserve: limit duration=%ds data=%d", resp.Limit.Duration, resp.Limit.Data)
	}
	return nil
}

func (c *RelayClient) RefreshReservation(ctx context.Context) error {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()

	if s == nil {
		return errors.New("not connected")
	}

	stream, err := s.Open()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(60 * time.Second))

	if err := MSSelect(stream, "/libp2p/circuit/relay/0.2.0/hop"); err != nil {
		return fmt.Errorf("hop negotiate: %w", err)
	}

	reserveMsg := &HopMessage{Type: HopTypeReserve}
	if err := writePbMessage(stream, encodeHopMessage(reserveMsg)); err != nil {
		return fmt.Errorf("send RESERVE: %w", err)
	}

	respData, err := readOnePb(stream)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	resp, err := decodeHopMessage(respData)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if resp.Type != HopTypeStatus || resp.Status != StatusOK {
		return fmt.Errorf("%w: refresh failed", ErrRelayStatus)
	}

	if resp.Reservation != nil {
		c.mu.Lock()
		c.reservationExpiry = time.Unix(int64(resp.Reservation.Expire), 0)
		c.mu.Unlock()
		log.Printf("RefreshReservation: renewed, expire=%ds", resp.Reservation.Expire)
	}
	return nil
}

func (c *RelayClient) AcceptRelay(ctx context.Context) (*RelayedConn, error) {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()

	if s == nil {
		return nil, errors.New("not connected to relay, call Connect first")
	}

	for {
		stream, err := s.AcceptStream()
		if err != nil {
			return nil, fmt.Errorf("accept stream: %w", err)
		}
		log.Printf("AcceptRelay: got new yamux stream")

		conn, err := c.handleIncoming(stream)
		if conn == nil && err == nil {
			continue
		}
		if err != nil {
			log.Printf("AcceptRelay: handleIncoming error: %v", err)
			stream.Close()
			continue
		}
		return conn, nil
	}
}

func (c *RelayClient) handleIncoming(stream *yamux.Stream) (*RelayedConn, error) {
	proto, err := MSRespond(stream)
	if err != nil {
		return nil, fmt.Errorf("ms respond: %w", err)
	}

	proto = strings.TrimRight(proto, "\n\r\t ")
	log.Printf("handleIncoming: proto=%q hex=%x", proto, []byte(proto))
	switch proto {
	case CircuitV1ProtoID:
		return c.acceptV1Hop(stream)
	case "/libp2p/circuit/relay/0.2.0/stop":
		return c.acceptV2Stop(stream)
	case "/ipfs/id/1.0.0":
		log.Printf("handleIncoming: got /ipfs/id/1.0.0, sending identify")
		pubKeyProto := marshalEd25519PubKey(c.key.Public().(ed25519.PublicKey))
		resp := c.buildIdentifyResponse(pubKeyProto, []string{
			CircuitV1ProtoID,
			"/ipfs/id/1.0.0",
		})
		writePbMessage(stream, resp)
		return nil, nil
	case "/ipfs/id/push/1.0.0":
		log.Printf("handleIncoming: got /ipfs/id/push/1.0.0, reading")
		data, err := readOnePb(stream)
		if err != nil {
			log.Printf("handleIncoming: read identify push: %v", err)
		} else {
			log.Printf("handleIncoming: relay pushed identify (%d bytes)", len(data))
		}
		return nil, nil
	case "/ipfs/kad/1.0.0":
		log.Printf("handleIncoming: got /ipfs/kad/1.0.0, ignoring")
		return nil, nil
	case "/ipfs/ping/1.0.0":
		go c.handlePing(stream)
		return nil, nil
	default:
		log.Printf("handleIncoming: ignoring unknown proto: %s", proto)
		return nil, nil
	}
}

func (c *RelayClient) isHandled(conn *RelayedConn, err error) bool {
	return conn == nil && err == nil
}

func (c *RelayClient) handlePing(stream *yamux.Stream) {
	defer stream.Close()
	buf := make([]byte, 32)
	for {
		_, err := io.ReadFull(stream, buf)
		if err != nil {
			return
		}
		if _, err := stream.Write(buf); err != nil {
			return
		}
	}
}

func (c *RelayClient) acceptV1Hop(stream *yamux.Stream) (*RelayedConn, error) {
	data, err := readOnePb(stream)
	if err != nil {
		return nil, fmt.Errorf("read v1 msg: %w", err)
	}
	log.Printf("acceptV1Hop: got %d bytes: %x", len(data), data)

	msg, err := decodeCircuitV1(data)
	if err != nil {
		return nil, fmt.Errorf("decode v1 msg: %w", err)
	}
	log.Printf("acceptV1Hop: type=%d srcPeer=%v dstPeer=%v code=%d", msg.Type, msg.SrcPeer, msg.DstPeer, msg.Code)

	switch msg.Type {
	case CircuitV1TypeStop:
		log.Printf("acceptV1Hop: got STOP, sending SUCCESS")
		resp := &CircuitV1Message{Type: CircuitV1TypeStatus, Code: CircuitV1StatusSuccess}
		if err := writePbMessage(stream, encodeCircuitV1(resp)); err != nil {
			return nil, fmt.Errorf("send v1 status: %w", err)
		}
		return newRelayedConn(stream), nil

	case CircuitV1TypeCanHop:
		log.Printf("acceptV1Hop: got CAN_HOP probe, responding SUCCESS")
		resp := &CircuitV1Message{Type: CircuitV1TypeStatus, Code: CircuitV1StatusSuccess}
		writePbMessage(stream, encodeCircuitV1(resp))
		stream.Close()
		return nil, nil

	default:
		return nil, fmt.Errorf("%w: unexpected v1 type %d", ErrRelayStatus, msg.Type)
	}
}

func (c *RelayClient) acceptV2Stop(stream *yamux.Stream) (*RelayedConn, error) {
	data, err := readOnePb(stream)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("read v2 stop: %w", err)
	}

	msg, err := decodeStopMessage(data)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("decode v2 stop: %w", err)
	}

	if msg.Type != StopTypeConnect {
		stream.Close()
		return nil, fmt.Errorf("%w: expected CONNECT, got type %d", ErrRelayStatus, msg.Type)
	}

	resp := &StopMessage{Type: StopTypeStatus, Status: StatusOK}
	if err := writePbMessage(stream, encodeStopMessage(resp)); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send v2 status: %w", err)
	}

	return newRelayedConn(stream), nil
}

func readOnePb(r io.Reader) ([]byte, error) {
	l, err := readVarint(newByteReader(r))
	if err != nil {
		return nil, err
	}
	if l > 4096 {
		return nil, errors.New("protobuf message too large")
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	return buf, err
}

func (c *RelayClient) buildIdentifyResponse(pubKey []byte, protocols []string) []byte {
	var b []byte
	b = append(b, pbEncodeLengthDelimField(1, pubKey)...)
	for _, p := range protocols {
		b = append(b, pbEncodeLengthDelimField(3, []byte(p))...)
	}
	b = append(b, pbEncodeLengthDelimField(6, []byte("relayhub/0.1.0"))...)

	seq := uint64(time.Now().UnixNano())
	pr := encodePeerRecord(seq, c.id, nil)
	payloadType := []byte{0x81, 0x06}
	sigInput := append([]byte("libp2p-envelope"), pubKey...)
	sigInput = append(sigInput, payloadType...)
	sigInput = append(sigInput, pr...)
	sig := ed25519.Sign(c.key, sigInput)
	env := encodeEnvelope(pubKey, payloadType, pr, sig)
	b = append(b, pbEncodeLengthDelimField(8, env)...)

	return b
}

func (c *RelayClient) pullIdentify(s *yamux.Session) {
	stream, err := s.Open()
	if err != nil {
		return
	}
	defer stream.Close()

	if err := MSSelect(stream, "/ipfs/id/1.0.0"); err != nil {
		log.Printf("pullIdentify: MSSelect failed: %v", err)
		return
	}

	data, err := readOnePb(stream)
	if err != nil {
		log.Printf("pullIdentify: read failed: %v", err)
		return
	}
	log.Printf("pullIdentify: read relay identify (%d bytes)", len(data))
}
