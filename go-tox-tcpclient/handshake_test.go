package tcpclient

import (
	"bytes"
	"testing"
)

func TestNewHandshakeState(t *testing.T) {
	serverPK, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	selfPK, selfSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hs := newHandshakeState(serverPK, selfPK, selfSK)

	if !bytes.Equal(hs.serverPK[:], serverPK[:]) {
		t.Fatal("serverPK mismatch")
	}
	if !bytes.Equal(hs.selfPK[:], selfPK[:]) {
		t.Fatal("selfPK mismatch")
	}

	shr := beforeNm(serverPK, selfSK)
	if !bytes.Equal(hs.initShr[:], shr[:]) {
		t.Fatal("initial shared key mismatch")
	}
}

func TestGenerateClientHandshakePacketSize(t *testing.T) {
	serverPK, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	selfPK, selfSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hs := newHandshakeState(serverPK, selfPK, selfSK)
	pkt, err := hs.generateClientPacket()
	if err != nil {
		t.Fatal(err)
	}

	if len(pkt) != ClientHandshakeSize {
		t.Fatalf("wrong handshake size: expected %d, got %d", ClientHandshakeSize, len(pkt))
	}
}

func TestClientHandshakePacketStructure(t *testing.T) {
	serverPK, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	selfPK, selfSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hs := newHandshakeState(serverPK, selfPK, selfSK)
	pkt, err := hs.generateClientPacket()
	if err != nil {
		t.Fatal(err)
	}

	gotSelfPK := pkt[:PublicKeySize]
	if !bytes.Equal(gotSelfPK, selfPK[:]) {
		t.Fatal("packet does not start with self public key")
	}
	initNonce := pkt[PublicKeySize : PublicKeySize+NonceSize]
	if len(initNonce) != NonceSize {
		t.Fatalf("wrong nonce size: %d", len(initNonce))
	}
	encrypted := pkt[PublicKeySize+NonceSize:]
	if len(encrypted) != HandshakePlainSize+MacSize {
		t.Fatalf("wrong encrypted size: %d", len(encrypted))
	}
}

func TestClientHandshakePacketEncryptedContent(t *testing.T) {
	serverPK, serverSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	selfPK, selfSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hs := newHandshakeState(serverPK, selfPK, selfSK)
	pkt, err := hs.generateClientPacket()
	if err != nil {
		t.Fatal(err)
	}

	initNonce := pkt[PublicKeySize : PublicKeySize+NonceSize]
	encrypted := pkt[PublicKeySize+NonceSize:]

	var nonceArr [24]byte
	copy(nonceArr[:], initNonce)

	shr := beforeNm(selfPK, serverSK)

	plain, ok := decryptDataSymmetric(shr, &nonceArr, encrypted)
	if !ok {
		t.Fatal("server cannot decrypt client handshake")
	}

	tempPK := plain[:PublicKeySize]
	sentNonce := plain[PublicKeySize:]

	if len(tempPK) != PublicKeySize {
		t.Fatalf("wrong temp PK size: %d", len(tempPK))
	}
	if len(sentNonce) != NonceSize {
		t.Fatalf("wrong sent nonce size: %d", len(sentNonce))
	}
}

func TestFullHandshakeRoundTrip(t *testing.T) {
	serverPK, serverSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientPK, clientSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	clientHS := newHandshakeState(serverPK, clientPK, clientSK)
	clientPkt, err := clientHS.generateClientPacket()
	if err != nil {
		t.Fatal(err)
	}

	initNonce := clientPkt[PublicKeySize : PublicKeySize+NonceSize]
	encrypted := clientPkt[PublicKeySize+NonceSize:]

	var nonceArr [24]byte
	copy(nonceArr[:], initNonce)

	serverInitShr := beforeNm(clientPK, serverSK)
	plain, ok := decryptDataSymmetric(serverInitShr, &nonceArr, encrypted)
	if !ok {
		t.Fatal("server cannot decrypt client handshake")
	}

	clientTempPKSlice := plain[:PublicKeySize]
	clientSentNonce := plain[PublicKeySize:]

	var clientSentNonceArr [24]byte
	copy(clientSentNonceArr[:], clientSentNonce)

	var clientTempPKArr [32]byte
	copy(clientTempPKArr[:], clientTempPKSlice)

	serverTempPK, serverTempSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var responsePlain [HandshakePlainSize]byte
	copy(responsePlain[:], serverTempPK[:])
	copy(responsePlain[PublicKeySize:], clientSentNonceArr[:])

	serverRespNonce := randomNonce()
	serverEncResp := encryptDataSymmetric(serverInitShr, serverRespNonce, responsePlain[:])

	serverResp := make([]byte, NonceSize+len(serverEncResp))
	copy(serverResp[:NonceSize], serverRespNonce[:])
	copy(serverResp[NonceSize:], serverEncResp)

	sessionKey, recvNonce, err := clientHS.handleServerResponse(serverResp)
	if err != nil {
		t.Fatalf("client cannot handle server response: %v", err)
	}

	expectedSessionKey := beforeNm(serverTempPK, &clientHS.tempSK)
	if !bytes.Equal(sessionKey[:], expectedSessionKey[:]) {
		t.Fatal("session key mismatch")
	}

	if !bytes.Equal(recvNonce[:], clientSentNonceArr[:]) {
		t.Fatal("recv nonce mismatch")
	}

	serverSessionKey := beforeNm(&clientTempPKArr, serverTempSK)
	if !bytes.Equal(sessionKey[:], serverSessionKey[:]) {
		t.Fatal("server and client session keys do not match")
	}
}

func TestHandshakeResponseTooShort(t *testing.T) {
	serverPK, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	selfPK, selfSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hs := newHandshakeState(serverPK, selfPK, selfSK)
	_, _, err = hs.handleServerResponse(make([]byte, ServerHandshakeSize-1))
	if err == nil {
		t.Fatal("expected error for short response")
	}
}

func TestHandshakeResponseInvalidEncryption(t *testing.T) {
	serverPK, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	selfPK, selfSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	hs := newHandshakeState(serverPK, selfPK, selfSK)

	resp := make([]byte, ServerHandshakeSize)
	for i := range resp {
		resp[i] = 0xFF
	}

	_, _, err = hs.handleServerResponse(resp)
	if err == nil {
		t.Fatal("expected error for invalid encryption")
	}
}

func TestEncryptDecryptWithSessionKey(t *testing.T) {
	serverPK, serverSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientPK, clientSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	clientHS := newHandshakeState(serverPK, clientPK, clientSK)
	clientPkt, err := clientHS.generateClientPacket()
	if err != nil {
		t.Fatal(err)
	}

	initNonce := clientPkt[PublicKeySize : PublicKeySize+NonceSize]
	encrypted := clientPkt[PublicKeySize+NonceSize:]

	var nonceArr [24]byte
	copy(nonceArr[:], initNonce)

	serverInitShr := beforeNm(clientPK, serverSK)
	plain, _ := decryptDataSymmetric(serverInitShr, &nonceArr, encrypted)

	clientTempPKSlice := plain[:PublicKeySize]
	clientSentNonce := plain[PublicKeySize:]

	var clientTempPKArr [32]byte
	copy(clientTempPKArr[:], clientTempPKSlice)

	serverTempPK, serverTempSK, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var respPlain [HandshakePlainSize]byte
	copy(respPlain[:], serverTempPK[:])
	copy(respPlain[PublicKeySize:], clientSentNonce)

	respNonce := randomNonce()
	serverEncResp := encryptDataSymmetric(serverInitShr, respNonce, respPlain[:])

	serverResp := make([]byte, NonceSize+len(serverEncResp))
	copy(serverResp[:NonceSize], respNonce[:])
	copy(serverResp[NonceSize:], serverEncResp)

	sessionKey, _, _ := clientHS.handleServerResponse(serverResp)
	serverSessionKey := beforeNm(&clientTempPKArr, serverTempSK)

	pingPlain := buildPing(42)
	var clientNonce [24]byte
	encPing := encryptDataSymmetric(sessionKey, &clientNonce, pingPlain)

	var serverNonce [24]byte
	decPing, ok := decryptDataSymmetric(serverSessionKey, &serverNonce, encPing)
	if !ok {
		t.Fatal("server cannot decrypt ping with session key")
	}
	if !bytes.Equal(decPing, pingPlain) {
		t.Fatal("decrypted ping mismatch")
	}
}

func TestGenerateSelfKeysValid(t *testing.T) {
	pk, sk, err := generateSelfKeys()
	if err != nil {
		t.Fatal(err)
	}
	if pk == "" || sk == "" {
		t.Fatal("got empty keys")
	}
}
