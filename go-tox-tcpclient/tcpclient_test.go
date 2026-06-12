package tcpclient

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/envsh/toxera/bsdata"
)

var knownNodes = []string{
	"tox1.mf-net.eu:33445",
	"tox2.mf-net.eu:33445",
	"172.104.215.182:33445",
	"43.198.227.166:33445",
}

func nodeByAddr(addr string) *bsdata.BSNode {
	nodes, err := bsdata.LoadBSNodes()
	if err != nil {
		return nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	for i := range nodes {
		n := &nodes[i]
		if n.Host != host {
			continue
		}
		for _, p := range n.Ports {
			if fmt.Sprint(p) == portStr {
				return n
			}
		}
	}
	return nil
}

func tryConnectRelay(t *testing.T, n bsdata.BSNode) *TCPClient {
	for _, port := range n.Ports {
		if port != 33445 && port != 3389 {
			continue
		}
		addr := net.JoinHostPort(n.Host, fmt.Sprint(port))
		serverPK, err := hex.DecodeString(n.Pubkey)
		if err != nil {
			continue
		}
		selfPK, selfSK, err := generateSelfKeys()
		if err != nil {
			continue
		}

		client := New(addr, serverPK, selfPK[:], selfSK[:])
		disconnected := make(chan struct{}, 1)
		client.OnDisconnected = func() {
			select {
			case disconnected <- struct{}{}:
			default:
			}
		}

		if err := client.Connect(); err != nil {
			continue
		}

		select {
		case <-disconnected:
			continue
		case <-time.After(3 * time.Second):
		}

		if !client.IsConnected() {
			client.Close()
			continue
		}
		return client
	}
	return nil
}

func testRelayClient(t *testing.T, client *TCPClient, name string) {
	t.Logf("--- testing %s ---", name)

	routingCh := make(chan uint8, 1)
	client.OnRoutingResponse = func(connID uint8, pk [PublicKeySize]byte) {
		routingCh <- connID
	}

	var pk [PublicKeySize]byte
	rand.Read(pk[:])

	// RoutingRequest
	if err := client.RoutingRequest(pk[:]); err != nil {
		t.Fatalf("[%s] RoutingRequest failed: %v", name, err)
	}
	select {
	case connID := <-routingCh:
		t.Logf("[%s] RoutingResponse connID=%d", name, connID)
	case <-time.After(3 * time.Second):
		t.Logf("[%s] RoutingResponse not received (peer unknown)", name)
	}
	if !client.IsConnected() {
		t.Fatalf("[%s] disconnected after RoutingRequest", name)
	}
	t.Logf("[%s] RoutingRequest OK", name)

	// SendOOB
	rand.Read(pk[:])
	if err := client.SendOOB(pk[:], []byte("hello from go-tox-tcpclient")); err != nil {
		t.Fatalf("[%s] SendOOB failed: %v", name, err)
	}
	time.Sleep(500 * time.Millisecond)
	if !client.IsConnected() {
		t.Fatalf("[%s] disconnected after SendOOB", name)
	}
	t.Logf("[%s] SendOOB OK", name)

	// OnionRequest — relay may or may not support it
	onionData := make([]byte, PublicKeySize+16)
	rand.Read(onionData[:PublicKeySize])
	rand.Read(onionData[PublicKeySize:])
	if err := client.SendOnionRequest(onionData); err != nil {
		t.Fatalf("[%s] SendOnionRequest failed: %v", name, err)
	}
	time.Sleep(500 * time.Millisecond)
	if !client.IsConnected() {
		t.Logf("[%s] relay does not support onion forwarding (expected)", name)
	} else {
		t.Logf("[%s] SendOnionRequest OK", name)
	}

	client.Close()
	if client.IsConnected() {
		t.Fatalf("[%s] client should be disconnected after Close()", name)
	}
	t.Logf("[%s] all operations completed", name)
}

func TestConnectToTCPRelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// try known nodes first
	tested := 0
	for _, addr := range knownNodes {
		if tested >= 2 {
			break
		}
		n := nodeByAddr(addr)
		if n == nil {
			continue
		}
		client := tryConnectRelay(t, *n)
		if client == nil {
			continue
		}
		testRelayClient(t, client, addr)
		tested++
	}

	// fallback: try all nodes from bsdata
	if tested == 0 {
		nodes, err := bsdata.LoadBSNodes()
		if err != nil {
			t.Fatalf("LoadBSNodes failed: %v", err)
		}
		for _, n := range nodes {
			if tested >= 2 {
				break
			}
			client := tryConnectRelay(t, n)
			if client == nil {
				continue
			}
			addr := net.JoinHostPort(n.Host, fmt.Sprint(n.Ports[0]))
			testRelayClient(t, client, addr)
			tested++
		}
	}

	if tested == 0 {
		t.Skip("no TCP relays were reachable")
	}
	t.Logf("tested %d relays successfully", tested)
}

func TestTwoPeerMessageExchange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	type peerState struct {
		client       *TCPClient
		pk           [PublicKeySize]byte
		sk           [SecretKeySize]byte
		routingResp  chan uint8
		connStatus   chan bool
		dataCh       chan []byte
		disconnected chan struct{}
		name         string
		connected    bool
	}

	pkA, skA, err := generateSelfKeys()
	if err != nil {
		t.Fatal(err)
	}
	pkB, skB, err := generateSelfKeys()
	if err != nil {
		t.Fatal(err)
	}

	a := &peerState{
		pk:           *pkA,
		sk:           *skA,
		routingResp:  make(chan uint8, 1),
		connStatus:   make(chan bool, 2),
		dataCh:       make(chan []byte, 4),
		disconnected: make(chan struct{}, 1),
		name:         "A",
	}
	b := &peerState{
		pk:           *pkB,
		sk:           *skB,
		routingResp:  make(chan uint8, 1),
		connStatus:   make(chan bool, 2),
		dataCh:       make(chan []byte, 4),
		disconnected: make(chan struct{}, 1),
		name:         "B",
	}

	setupClient := func(ps *peerState, relayAddr, relayPK string) error {
		serverPK, err := hex.DecodeString(relayPK)
		if err != nil {
			return err
		}
		ps.client = New(relayAddr, serverPK, ps.pk[:], ps.sk[:])
		ps.client.OnRoutingResponse = func(connID uint8, pk [PublicKeySize]byte) {
			ps.routingResp <- connID
		}
		ps.client.OnConnectionStatus = func(connID uint8, online bool) {
			ps.connStatus <- online
		}
		ps.client.OnData = func(connID uint8, data []byte) {
			ps.dataCh <- data
		}
		ps.client.OnDisconnected = func() {
			ps.disconnected <- struct{}{}
		}
		if err := ps.client.Connect(); err != nil {
			return err
		}
		select {
		case <-ps.disconnected:
			return fmt.Errorf("disconnected during handshake")
		case <-time.After(3 * time.Second):
		}
		if !ps.client.IsConnected() {
			return fmt.Errorf("not connected after handshake")
		}
		return nil
	}

	relayAddrs := append([]string{}, knownNodes...)
	nodes, err := bsdata.LoadBSNodes()
	if err == nil {
		for _, n := range nodes {
			relayAddrs = append(relayAddrs, net.JoinHostPort(n.Host, fmt.Sprint(n.Ports[0])))
		}
	}

	tried := 0
	for _, addr := range relayAddrs {
		if a.connected && b.connected {
			break
		}
		n := nodeByAddr(addr)
		if n == nil {
			continue
		}
		tried++

		a.connected = false
		b.connected = false

		if err := setupClient(a, addr, n.Pubkey); err != nil {
			continue
		}
		a.connected = true
		if err := setupClient(b, addr, n.Pubkey); err != nil {
			a.client.Close()
			a.connected = false
			continue
		}
		b.connected = true
		t.Logf("both clients connected to %s (%s)", addr, n.Pubkey[:16])
	}

	if !a.connected || !b.connected {
		t.Skip("could not connect both clients to any relay")
	}
	defer a.client.Close()
	defer b.client.Close()

	a.client.RoutingRequest(b.pk[:])
	select {
	case aConnID := <-a.routingResp:
		t.Logf("[A] RoutingResponse for B: connID=%d", aConnID)
	case <-time.After(5 * time.Second):
		t.Fatal("[A] no RoutingResponse")
	}
	if !a.client.IsConnected() {
		t.Fatal("[A] disconnected after RoutingRequest")
	}

	b.client.RoutingRequest(a.pk[:])
	select {
	case bConnID := <-b.routingResp:
		t.Logf("[B] RoutingResponse for A: connID=%d", bConnID)
	case <-time.After(5 * time.Second):
		t.Fatal("[B] no RoutingResponse")
	}
	if !b.client.IsConnected() {
		t.Fatal("[B] disconnected after RoutingRequest")
	}

	for i := 0; i < 1; i++ {
		select {
		case online := <-a.connStatus:
			t.Logf("[A] connection status: online=%v", online)
		case <-time.After(5 * time.Second):
			t.Fatal("[A] timeout waiting for ConnectionNotification")
		}
	}
	for i := 0; i < 1; i++ {
		select {
		case online := <-b.connStatus:
			t.Logf("[B] connection status: online=%v", online)
		case <-time.After(5 * time.Second):
			t.Fatal("[B] timeout waiting for ConnectionNotification")
		}
	}
	t.Log("both peers connected via relay")

	msgA := "ping from A"
	a.client.SendData(0, []byte(msgA))
	select {
	case recvData := <-b.dataCh:
		if string(recvData) != msgA {
			t.Fatalf("[B] received wrong data: got %q, expected %q", string(recvData), msgA)
		}
		t.Logf("[B] correctly received: %q", string(recvData))
	case <-time.After(5 * time.Second):
		t.Fatal("[B] timeout waiting for data from A")
	}
	if !a.client.IsConnected() || !b.client.IsConnected() {
		t.Fatal("one or both clients disconnected after A->B data")
	}
	t.Log("A -> B data verified")

	msgB := "pong from B"
	b.client.SendData(0, []byte(msgB))
	select {
	case recvData := <-a.dataCh:
		if string(recvData) != msgB {
			t.Fatalf("[A] received wrong data: got %q, expected %q", string(recvData), msgB)
		}
		t.Logf("[A] correctly received: %q", string(recvData))
	case <-time.After(5 * time.Second):
		t.Fatal("[A] timeout waiting for data from B")
	}
	t.Log("B -> A data verified")

	a.client.Close()
	b.client.Close()
	if a.client.IsConnected() || b.client.IsConnected() {
		t.Fatal("clients should be disconnected after Close()")
	}
	t.Log("Two-peer message exchange completed successfully")
}

func TestConnectFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	selfPK, selfSK, err := generateSelfKeys()
	if err != nil {
		t.Fatal(err)
	}

	serverPK := make([]byte, PublicKeySize)
	if _, err := rand.Read(serverPK); err != nil {
		t.Fatal(err)
	}

	client := New("127.0.0.1:1", serverPK, selfPK[:], selfSK[:])

	err = client.Connect()
	if err == nil {
		client.Close()
		t.Fatal("expected connection failure")
	}
	t.Logf("expected failure: %v", err)
}

func TestMultipleBootstrapNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	nodes, err := bsdata.LoadBSNodes()
	if err != nil {
		t.Fatalf("LoadBSNodes failed: %v", err)
	}

	connected := 0
	for _, n := range nodes {
		if connected >= 3 {
			break
		}
		client := tryConnectRelay(t, n)
		if client == nil {
			continue
		}

		addr := net.JoinHostPort(n.Host, fmt.Sprint(n.Ports[0]))
		t.Logf("[%d] connected to %s (%s)", connected+1, addr, n.Pubkey[:16])

		var pk [PublicKeySize]byte
		rand.Read(pk[:])
		client.RoutingRequest(pk[:])
		rand.Read(pk[:])
		client.SendOOB(pk[:], []byte("multi-test"))
		onionData := make([]byte, PublicKeySize+8)
		rand.Read(onionData)
		client.SendOnionRequest(onionData)

		time.Sleep(500 * time.Millisecond)
		if client.IsConnected() {
			connected++
		} else {
			t.Logf("[%d] relay disconnected after data (expected if onion unsupported)", connected+1)
		}
		client.Close()
	}

	if connected == 0 {
		t.Skip("no TCP relays were reachable")
	}
	t.Logf("successfully: %d TCP relays with data", connected)
}
