package tcpclient

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestBuildRoutingRequest(t *testing.T) {
	var pk [PublicKeySize]byte
	for i := range pk {
		pk[i] = byte(i)
	}

	pkt := buildRoutingRequest(pk[:])
	if len(pkt) != 1+PublicKeySize {
		t.Fatalf("wrong length: %d", len(pkt))
	}
	if pkt[0] != PacketRoutingRequest {
		t.Fatalf("wrong type: expected %d, got %d", PacketRoutingRequest, pkt[0])
	}
	if !bytes.Equal(pkt[1:], pk[:]) {
		t.Fatal("wrong pubkey")
	}
}

func TestBuildRoutingResponse(t *testing.T) {
	var pk [PublicKeySize]byte
	for i := range pk {
		pk[i] = byte(i)
	}
	connID := uint8(42)

	pkt := buildRoutingResponse(connID, pk[:])
	if len(pkt) != 1+1+PublicKeySize {
		t.Fatalf("wrong length: %d", len(pkt))
	}
	if pkt[0] != PacketRoutingResponse {
		t.Fatalf("wrong type")
	}
	if pkt[1] != connID+NumReservedPorts {
		t.Fatalf("wrong connID: expected %d, got %d", connID+NumReservedPorts, pkt[1])
	}
	if !bytes.Equal(pkt[2:], pk[:]) {
		t.Fatal("wrong pubkey")
	}

	parsedID, parsedPK, ok := parseRoutingResponse(pkt)
	if !ok {
		t.Fatal("parse failed")
	}
	if parsedID != connID+NumReservedPorts {
		t.Fatalf("wrong parsed connID: expected %d, got %d", connID+NumReservedPorts, parsedID)
	}
	if !bytes.Equal(parsedPK, pk[:]) {
		t.Fatal("wrong parsed pubkey")
	}
}

func TestBuildConnNotification(t *testing.T) {
	connID := uint8(16)
	pkt := buildConnNotification(connID)

	if len(pkt) != 2 {
		t.Fatalf("wrong length: %d", len(pkt))
	}
	if pkt[0] != PacketConnectionNotification {
		t.Fatalf("wrong type")
	}
	if pkt[1] != connID {
		t.Fatalf("wrong connID")
	}

	parsedID, ok := parseConnNotification(pkt)
	if !ok {
		t.Fatal("parse failed")
	}
	if parsedID != connID {
		t.Fatalf("wrong parsed connID: %d", parsedID)
	}
}

func TestBuildDisconnNotification(t *testing.T) {
	connID := uint8(16)
	pkt := buildDisconnNotification(connID)

	if len(pkt) != 2 {
		t.Fatalf("wrong length: %d", len(pkt))
	}
	if pkt[0] != PacketDisconnectNotification {
		t.Fatalf("wrong type")
	}

	parsedID, ok := parseDisconnNotification(pkt)
	if !ok {
		t.Fatal("parse failed")
	}
	if parsedID != connID {
		t.Fatalf("wrong parsed connID")
	}
}

func TestBuildPingPong(t *testing.T) {
	pingID := uint64(1234567890)

	ping := buildPing(pingID)
	if len(ping) != 1+8 {
		t.Fatalf("wrong ping length: %d", len(ping))
	}
	if ping[0] != PacketPing {
		t.Fatalf("wrong type")
	}

	parsedID, ok := parsePing(ping)
	if !ok {
		t.Fatal("parsePing failed")
	}
	if parsedID != pingID {
		t.Fatalf("wrong pingID: expected %d, got %d", pingID, parsedID)
	}

	pong := buildPong(pingID)
	if len(pong) != 1+8 {
		t.Fatalf("wrong pong length: %d", len(pong))
	}
	if pong[0] != PacketPong {
		t.Fatalf("wrong type")
	}

	parsedPongID, ok := parsePong(pong)
	if !ok {
		t.Fatal("parsePong failed")
	}
	if parsedPongID != pingID {
		t.Fatalf("wrong pongID: expected %d, got %d", pingID, parsedPongID)
	}
}

func TestBuildOOBSend(t *testing.T) {
	var pk [PublicKeySize]byte
	for i := range pk {
		pk[i] = byte(i)
	}
	data := []byte("hello oob")

	pkt, err := buildOOBSend(pk[:], data)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 1+PublicKeySize+len(data) {
		t.Fatalf("wrong length: %d", len(pkt))
	}
	if pkt[0] != PacketOOBSend {
		t.Fatalf("wrong type")
	}
	if !bytes.Equal(pkt[1:1+PublicKeySize], pk[:]) {
		t.Fatal("wrong pubkey")
	}
	if !bytes.Equal(pkt[1+PublicKeySize:], data) {
		t.Fatal("wrong data")
	}
}

func TestBuildOOBSendTooLarge(t *testing.T) {
	var pk [PublicKeySize]byte
	data := make([]byte, MaxOOBDataLength+1)
	_, err := buildOOBSend(pk[:], data)
	if err == nil {
		t.Fatal("expected error for oversized OOB data")
	}
}

func TestBuildOOBRecv(t *testing.T) {
	var pk [PublicKeySize]byte
	for i := range pk {
		pk[i] = byte(i)
	}
	data := []byte("oob recv data")

	pkt := buildOOBRecv(pk[:], data)
	if len(pkt) != 1+PublicKeySize+len(data) {
		t.Fatalf("wrong length: %d", len(pkt))
	}
	if pkt[0] != PacketOOBRecv {
		t.Fatalf("wrong type")
	}

	parsedPK, parsedData, ok := parseOOBRecv(pkt)
	if !ok {
		t.Fatal("parseOOBRecv failed")
	}
	if !bytes.Equal(parsedPK, pk[:]) {
		t.Fatal("wrong parsed pubkey")
	}
	if !bytes.Equal(parsedData, data) {
		t.Fatal("wrong parsed data")
	}
}

func TestBuildOnionRequest(t *testing.T) {
	data := []byte("onion data")
	pkt := buildOnionRequest(data)
	if len(pkt) != 1+len(data) {
		t.Fatalf("wrong length: %d", len(pkt))
	}
	if pkt[0] != PacketOnionRequest {
		t.Fatalf("wrong type")
	}
	if !bytes.Equal(pkt[1:], data) {
		t.Fatal("wrong data")
	}
}

func TestBuildOnionResponse(t *testing.T) {
	data := []byte("onion response data")
	pkt := buildOnionResponse(data)
	if len(pkt) != 1+len(data) {
		t.Fatalf("wrong length: %d", len(pkt))
	}
	if pkt[0] != PacketOnionResponse {
		t.Fatalf("wrong type")
	}

	parsedData, ok := parseOnionResponse(pkt)
	if !ok {
		t.Fatal("parseOnionResponse failed")
	}
	if !bytes.Equal(parsedData, data) {
		t.Fatal("wrong parsed data")
	}
}

func TestBuildDataPacket(t *testing.T) {
	connID := uint8(5)
	data := []byte("routed data")
	pkt, err := buildDataPacket(connID, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 1+len(data) {
		t.Fatalf("wrong length: %d", len(pkt))
	}
	if pkt[0] != connID+NumReservedPorts {
		t.Fatalf("wrong type: expected %d, got %d", connID+NumReservedPorts, pkt[0])
	}
	if !bytes.Equal(pkt[1:], data) {
		t.Fatal("wrong data")
	}

	if !isDataPacket(pkt) {
		t.Fatal("should be data packet")
	}

	parsedID, parsedData, ok := parseDataPacket(pkt)
	if !ok {
		t.Fatal("parseDataPacket failed")
	}
	if parsedID != connID {
		t.Fatalf("wrong connID: expected %d, got %d", connID, parsedID)
	}
	if !bytes.Equal(parsedData, data) {
		t.Fatal("wrong parsed data")
	}
}

func TestBuildDataPacketInvalidConnID(t *testing.T) {
	_, err := buildDataPacket(NumClientConnections, []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid connID")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	_, sec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shr := beforeNm(pub, sec)

	var nonce [24]byte
	plain := []byte{PacketPing, 0, 0, 0, 0, 0, 0, 0, 1}

	encoded, err := encodePacket(shr, &nonce, plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) < 2 {
		t.Fatal("encoded too short")
	}
	encLen := binary.BigEndian.Uint16(encoded[:2])
	if int(encLen) != len(plain)+box.Overhead {
		t.Fatalf("wrong encLen: expected %d, got %d", len(plain)+box.Overhead, encLen)
	}

	var decNonce [24]byte
	decoded, err := decodePacket(shr, &decNonce, encoded[2:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, decoded) {
		t.Fatalf("round trip failed: got %x, expected %x", decoded, plain)
	}
}

func TestEncodeDecodeMultiple(t *testing.T) {
	_, sec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shr := beforeNm(pub, sec)

	plains := [][]byte{
		{PacketPing, 1, 0, 0, 0, 0, 0, 0, 0},
		{PacketRoutingRequest, 2, 3, 4},
		{PacketOOBSend, 5, 6, 7, 8, 9},
	}

	var encNonce [24]byte
	var decNonce [24]byte

	for _, plain := range plains {
		encNonceCopy := encNonce
		encoded, err := encodePacket(shr, &encNonceCopy, plain)
		if err != nil {
			t.Fatal(err)
		}

		decNonceCopy := decNonce
		decoded, err := decodePacket(shr, &decNonceCopy, encoded[2:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, decoded) {
			t.Fatalf("round trip failed")
		}

		encNonce = encNonceCopy
		decNonce = decNonceCopy
	}
}

func TestEncodeDecryptNonceAdvance(t *testing.T) {
	_, sec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shr := beforeNm(pub, sec)

	var nonce [24]byte
	origNonce := nonce

	plain := []byte{PacketPing, 1, 0, 0, 0, 0, 0, 0, 0}
	_, err = encodePacket(shr, &nonce, plain)
	if err != nil {
		t.Fatal(err)
	}
	if nonce == origNonce {
		t.Fatal("nonce should advance after encodePacket")
	}
}

func TestParseRoutingResponseInvalid(t *testing.T) {
	_, _, ok := parseRoutingResponse([]byte{PacketRoutingResponse})
	if ok {
		t.Fatal("should fail on short packet")
	}
	_, _, ok = parseRoutingResponse([]byte{PacketPing, 1, 2, 3})
	if ok {
		t.Fatal("should fail on wrong type")
	}
}

func TestParseConnNotificationInvalid(t *testing.T) {
	_, ok := parseConnNotification([]byte{PacketConnectionNotification})
	if ok {
		t.Fatal("should fail on short packet")
	}
	_, ok = parseConnNotification([]byte{PacketPing, 1})
	if ok {
		t.Fatal("should fail on wrong type")
	}
}

func TestParseDataPacketInvalid(t *testing.T) {
	_, _, ok := parseDataPacket([]byte{})
	if ok {
		t.Fatal("should fail on empty")
	}
	_, _, ok = parseDataPacket([]byte{5})
	if ok {
		t.Fatal("should fail on control packet type")
	}
}

func TestIsDataPacket(t *testing.T) {
	if isDataPacket([]byte{PacketPing}) {
		t.Fatal("ping should not be data packet")
	}
	if !isDataPacket([]byte{NumReservedPorts}) {
		t.Fatal("type 16 should be data packet")
	}
	if !isDataPacket([]byte{255}) {
		t.Fatal("type 255 should be data packet")
	}
}

func TestBuildDataPacketAllConnIDs(t *testing.T) {
	for i := uint8(0); i < NumClientConnections; i++ {
		pkt, err := buildDataPacket(i, []byte{0x01})
		if err != nil {
			t.Fatalf("buildDataPacket(%d) failed: %v", i, err)
		}
		if pkt[0] != i+NumReservedPorts {
			t.Fatalf("connID %d: wrong type %d", i, pkt[0])
		}
	}
}

func TestPacketReaderWriter(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	pr := NewPacketReader(r)

	_, sec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shr := beforeNm(pub, sec)

	var encNonce [24]byte
	var decNonce [24]byte
	plain := []byte{PacketPing, 1, 2, 3, 4, 5, 6, 7, 8}
	encoded, err := encodePacket(shr, &encNonce, plain)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		w.Write(encoded)
		w.Close()
	}()

	readData, err := pr.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := decodePacket(shr, &decNonce, readData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, decoded) {
		t.Fatalf("round trip failed")
	}
}
