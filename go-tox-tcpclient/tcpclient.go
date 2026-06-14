package tcpclient

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

type clientStatus int

const (
	statusNoStatus     clientStatus = 0
	statusConnecting   clientStatus = 1
	statusUnconfirmed  clientStatus = 2
	statusConfirmed    clientStatus = 3
	statusDisconnected clientStatus = 4
)

const (
	connFree    = 0
	connOffline = 1
	connOnline  = 2
)

type connSlot struct {
	status uint8
	pubkey [PublicKeySize]byte
	number uint32
}

type TCPClient struct {
	addr     string
	serverPK [PublicKeySize]byte
	selfPK   [PublicKeySize]byte
	selfSK   [SecretKeySize]byte

	mu     sync.Mutex
	status clientStatus

	conn    net.Conn
	reader  *PacketReader
	writeCh chan []byte
	doneCh  chan struct{}
	wg      sync.WaitGroup

	shrkey    [SharedKeySize]byte
	sentNonce [24]byte
	recvNonce [24]byte

	pingID     uint64
	lastPinged time.Time

	conns [NumClientConnections]connSlot

	OnRoutingResponse  func(connID uint8, pubkey string)
	OnConnectionStatus func(connID uint8, online bool)
	OnData             func(connID uint8, data string)
	OnOOBData          func(pubkey string, data string)
	OnDisconnected     func()
}

func New(addr string, serverPK, selfSK string) *TCPClient {
	c := &TCPClient{
		addr:    addr,
		writeCh: make(chan []byte, 64),
		doneCh:  make(chan struct{}),
	}

	b, err := hex.DecodeString(serverPK)
	if err != nil {
		panic("tcpclient.New: serverPK hex: " + err.Error())
	}
	copy(c.serverPK[:], b)

	b, err = hex.DecodeString(selfSK)
	if err != nil {
		panic("tcpclient.New: selfSK hex: " + err.Error())
	}
	copy(c.selfSK[:], b)

	curve25519.ScalarBaseMult(&c.selfPK, &c.selfSK)

	return c
}

func (c *TCPClient) Connect() error {
	hs := newHandshakeState(&c.serverPK, &c.selfPK, &c.selfSK)

	clientPkt, err := hs.generateClientPacket()
	if err != nil {
		return err
	}

	conn, err := net.DialTimeout("tcp", c.addr, TCPConnectionTimeout*time.Second)
	if err != nil {
		c.setStatus(statusDisconnected)
		return err
	}

	c.mu.Lock()
	c.conn = conn
	c.status = statusConnecting
	c.reader = NewPacketReader(conn)
	c.mu.Unlock()

	if _, err := conn.Write(clientPkt); err != nil {
		conn.Close()
		c.setStatus(statusDisconnected)
		return err
	}
	c.setStatus(statusUnconfirmed)

	var resp [ServerHandshakeSize]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		conn.Close()
		c.setStatus(statusDisconnected)
		return err
	}

	sk, rn, err := hs.handleServerResponse(resp[:])
	if err != nil {
		conn.Close()
		c.setStatus(statusDisconnected)
		return err
	}

	c.mu.Lock()
	copy(c.shrkey[:], sk[:])
	copy(c.sentNonce[:], hs.sentNonce[:])
	copy(c.recvNonce[:], rn[:])
	c.status = statusConfirmed
	c.mu.Unlock()

	c.startIO()

	c.sendPing()

	return nil
}

func (c *TCPClient) Close() {
	c.mu.Lock()
	select {
	case <-c.doneCh:
	default:
		close(c.doneCh)
	}
	if c.conn != nil {
		c.conn.Close()
	}
	c.status = statusDisconnected
	c.mu.Unlock()
	c.wg.Wait()
}

func (c *TCPClient) RoutingRequest(pubkey string) error {
	b, err := hex.DecodeString(pubkey)
	if err != nil {
		return ErrInvalidKey
	}
	c.sendPlaintext(buildRoutingRequest(b[:PublicKeySize]))
	return nil
}

func (c *TCPClient) findConnID(pubkey []byte) (uint8, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.conns {
		if c.conns[i].status != connFree && bytes.Equal(c.conns[i].pubkey[:], pubkey) {
			return uint8(i), true
		}
	}
	return 0, false
}

func (c *TCPClient) SendData(pubkey string, data string) error {
	b, err := hex.DecodeString(pubkey)
	if err != nil {
		return ErrInvalidKey
	}
	connID, ok := c.findConnID(b)
	if !ok {
		return ErrPeerNotFound
	}
	pkt, err := buildDataPacket(connID, []byte(data))
	if err != nil {
		return err
	}
	c.sendPlaintext(pkt)
	return nil
}

func (c *TCPClient) SendOOB(pubkey string, data string) error {
	b, err := hex.DecodeString(pubkey)
	if err != nil {
		return ErrInvalidKey
	}
	pkt, err := buildOOBSend(b[:PublicKeySize], []byte(data))
	if err != nil {
		return err
	}
	c.sendPlaintext(pkt)
	return nil
}

func (c *TCPClient) SendOnionRequest(data string) error {
	c.sendPlaintext(buildOnionRequest([]byte(data)))
	return nil
}

func (c *TCPClient) DisconnectPeer(pubkey string) error {
	b, err := hex.DecodeString(pubkey)
	if err != nil {
		return ErrInvalidKey
	}
	connID, ok := c.findConnID(b)
	if !ok {
		return ErrPeerNotFound
	}
	c.mu.Lock()
	c.conns[connID].status = connFree
	c.mu.Unlock()
	c.sendPlaintext(buildDisconnNotification(connID + NumReservedPorts))
	return nil
}

func (c *TCPClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status == statusConfirmed
}

var (
	ErrInvalidKey    = &protocolError{"invalid key"}
	ErrInvalidConnID = &protocolError{"invalid connection ID"}
	ErrPeerNotFound  = &protocolError{"peer not found"}
)

type protocolError struct{ msg string }

func (e *protocolError) Error() string { return e.msg }

func (c *TCPClient) setStatus(s clientStatus) {
	c.mu.Lock()
	c.status = s
	c.mu.Unlock()
}

func (c *TCPClient) sendPlaintext(plain []byte) {
	select {
	case c.writeCh <- plain:
	case <-c.doneCh:
	}
}

func (c *TCPClient) sendPing() {
	id := randomUint64()
	for id == 0 {
		id = randomUint64()
	}
	c.mu.Lock()
	c.pingID = id
	c.lastPinged = time.Now()
	c.mu.Unlock()
	c.sendPlaintext(buildPing(id))
}

func (c *TCPClient) startIO() {
	c.wg.Add(2)
	go c.writeLoop()
	go c.readLoop()
	go c.pingLoop()
}

func (c *TCPClient) writeLoop() {
	defer c.wg.Done()
	for {
		select {
		case plain := <-c.writeCh:
			c.mu.Lock()
			shrkey := c.shrkey
			nonce := c.sentNonce
			c.mu.Unlock()

			pkt, err := encodePacket(&shrkey, &nonce, plain)
			if err != nil {
				continue
			}

			c.mu.Lock()
			c.sentNonce = nonce
			conn := c.conn
			c.mu.Unlock()

			if conn == nil {
				return
			}

			if _, err := conn.Write(pkt); err != nil {
				c.handleDisconnect()
				return
			}
		case <-c.doneCh:
			return
		}
	}
}

func (c *TCPClient) readLoop() {
	defer c.wg.Done()
	for {
		data, err := c.reader.ReadPacket()
		if err != nil {
			c.handleDisconnect()
			return
		}

		c.mu.Lock()
		shrkey := c.shrkey
		nonce := c.recvNonce
		c.mu.Unlock()

		plain, err := decodePacket(&shrkey, &nonce, data)
		if err != nil {
			continue
		}

		c.mu.Lock()
		c.recvNonce = nonce
		c.mu.Unlock()

		c.dispatchPacket(plain)
	}
}

func (c *TCPClient) pingLoop() {
	ticker := time.NewTicker(TCPPingFrequency * time.Second / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			pid := c.pingID
			lp := c.lastPinged
			c.mu.Unlock()

			if pid != 0 && time.Since(lp) > TCPPingTimeout*time.Second {
				c.handleDisconnect()
				return
			}
			if pid == 0 && time.Since(lp) > TCPPingFrequency*time.Second {
				c.sendPing()
			}
		case <-c.doneCh:
			return
		}
	}
}

func (c *TCPClient) dispatchPacket(plain []byte) {
	if len(plain) == 0 {
		return
	}

	switch plain[0] {
	case PacketPing:
		id, ok := parsePing(plain)
		if ok {
			c.sendPlaintext(buildPong(id))
		}
	case PacketPong:
		id, ok := parsePong(plain)
		if ok && id != 0 {
			c.mu.Lock()
			if id == c.pingID {
				c.pingID = 0
			}
			c.mu.Unlock()
		}
	case PacketRoutingResponse:
		connID, pk, ok := parseRoutingResponse(plain)
		if ok && connID >= NumReservedPorts {
			actualID := connID - NumReservedPorts
			if actualID < NumClientConnections {
				c.mu.Lock()
				c.conns[actualID].status = connOffline
				copy(c.conns[actualID].pubkey[:], pk)
				c.mu.Unlock()
				if c.OnRoutingResponse != nil {
					c.OnRoutingResponse(actualID, hex.EncodeToString(pk))
				}
			}
		}
	case PacketConnectionNotification:
		connID, ok := parseConnNotification(plain)
		if ok && connID >= NumReservedPorts {
			actualID := connID - NumReservedPorts
			if actualID < NumClientConnections {
				c.mu.Lock()
				c.conns[actualID].status = connOnline
				c.mu.Unlock()
				if c.OnConnectionStatus != nil {
					c.OnConnectionStatus(actualID, true)
				}
			}
		}
	case PacketDisconnectNotification:
		connID, ok := parseDisconnNotification(plain)
		if ok && connID >= NumReservedPorts {
			actualID := connID - NumReservedPorts
			if actualID < NumClientConnections {
				c.mu.Lock()
				if c.conns[actualID].status == connOnline {
					c.conns[actualID].status = connOffline
				}
				c.mu.Unlock()
				if c.OnConnectionStatus != nil {
					c.OnConnectionStatus(actualID, false)
				}
			}
		}
	case PacketOOBRecv:
		pk, data, ok := parseOOBRecv(plain)
		if ok && c.OnOOBData != nil {
			c.OnOOBData(hex.EncodeToString(pk), string(data))
		}
	case PacketOnionResponse:
		_, _ = parseOnionResponse(plain)
	default:
		if isDataPacket(plain) {
			connID, data, ok := parseDataPacket(plain)
			if ok && c.OnData != nil {
				c.OnData(connID, string(data))
			}
		}
	}
}

func (c *TCPClient) handleDisconnect() {
	c.mu.Lock()
	select {
	case <-c.doneCh:
	default:
		close(c.doneCh)
	}
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.status = statusDisconnected
	c.mu.Unlock()
	if c.OnDisconnected != nil {
		c.OnDisconnected()
	}
}
