package tcpclient

import (
	"crypto/rand"
	"errors"
)

const (
	PublicKeySize = 32
	SecretKeySize = 32
	SharedKeySize = 32
	NonceSize     = 24
	MacSize       = 16

	HandshakePlainSize  = PublicKeySize + NonceSize
	ServerHandshakeSize = NonceSize + HandshakePlainSize + MacSize
	ClientHandshakeSize = PublicKeySize + ServerHandshakeSize

	TCPConnectionTimeout = 10
	TCPPingFrequency     = 30
	TCPPingTimeout       = 10
)

type handshakeState struct {
	serverPK  [PublicKeySize]byte
	selfPK    [PublicKeySize]byte
	selfSK    [SecretKeySize]byte
	initShr   [SharedKeySize]byte
	tempSK    [SecretKeySize]byte
	tempPK    [PublicKeySize]byte
	initNonce [24]byte
	sentNonce [24]byte
}

func newHandshakeState(serverPK, selfPK, selfSK *[32]byte) *handshakeState {
	hs := &handshakeState{}
	copy(hs.serverPK[:], serverPK[:])
	copy(hs.selfPK[:], selfPK[:])
	copy(hs.selfSK[:], selfSK[:])
	shr := beforeNm(serverPK, selfSK)
	copy(hs.initShr[:], shr[:])
	return hs
}

func (hs *handshakeState) generateClientPacket() ([]byte, error) {
	pk, sk, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	copy(hs.tempPK[:], pk[:])
	copy(hs.tempSK[:], sk[:])

	sn := randomNonce()
	in := randomNonce()
	copy(hs.sentNonce[:], sn[:])
	copy(hs.initNonce[:], in[:])

	var plain [HandshakePlainSize]byte
	copy(plain[:], hs.tempPK[:])
	copy(plain[PublicKeySize:], hs.sentNonce[:])

	enc := encryptDataSymmetric(&hs.initShr, in, plain[:])

	pkt := make([]byte, ClientHandshakeSize)
	copy(pkt[:PublicKeySize], hs.selfPK[:])
	copy(pkt[PublicKeySize:], hs.initNonce[:])
	copy(pkt[PublicKeySize+NonceSize:], enc)

	return pkt, nil
}

func (hs *handshakeState) handleServerResponse(resp []byte) (*[32]byte, *[24]byte, error) {
	if len(resp) < ServerHandshakeSize {
		return nil, nil, errors.New("handshake response too short")
	}

	var tmpNonce [24]byte
	copy(tmpNonce[:], resp[:NonceSize])

	plain, ok := decryptDataSymmetric(&hs.initShr, &tmpNonce, resp[NonceSize:ServerHandshakeSize])
	if !ok {
		return nil, nil, errors.New("handshake decryption failed")
	}

	var servTempPK [PublicKeySize]byte
	copy(servTempPK[:], plain[:PublicKeySize])

	var recvNonce [24]byte
	copy(recvNonce[:], plain[PublicKeySize:])

	sessionKey := beforeNm(&servTempPK, &hs.tempSK)

	var sessionKeyOut [32]byte
	copy(sessionKeyOut[:], sessionKey[:])

	var recvNonceOut [24]byte
	copy(recvNonceOut[:], recvNonce[:])

	return &sessionKeyOut, &recvNonceOut, nil
}

func generateSelfKeys() (*[32]byte, *[32]byte, error) {
	return generateKeyPair()
}

func randomUint64() uint64 {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return bytesToUint64(b)
}
