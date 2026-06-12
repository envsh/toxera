package tcpclient

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	NumReservedPorts     = 16
	NumClientConnections = 256 - NumReservedPorts
	MaxPacketSize        = 2048
	MaxOOBDataLength     = 1024
)

const (
	PacketRoutingRequest         = 0
	PacketRoutingResponse        = 1
	PacketConnectionNotification = 2
	PacketDisconnectNotification = 3
	PacketPing                   = 4
	PacketPong                   = 5
	PacketOOBSend                = 6
	PacketOOBRecv                = 7
	PacketOnionRequest           = 8
	PacketOnionResponse          = 9
)

func encodePacket(shrkey *[32]byte, nonce *[24]byte, plain []byte) ([]byte, error) {
	if len(plain) > MaxPacketSize {
		return nil, errors.New("packet too large")
	}
	cipher := encryptDataSymmetric(shrkey, nonce, plain)
	pkt := make([]byte, 2+len(cipher))
	binary.BigEndian.PutUint16(pkt[:2], uint16(len(cipher)))
	copy(pkt[2:], cipher)
	incrNonce(nonce)
	return pkt, nil
}

func decodePacket(shrkey *[32]byte, nonce *[24]byte, cipher []byte) ([]byte, error) {
	if len(cipher) < MacSize {
		return nil, errors.New("ciphertext too short")
	}
	plain, ok := decryptDataSymmetric(shrkey, nonce, cipher)
	if !ok {
		return nil, errors.New("decryption failed")
	}
	incrNonce(nonce)
	return plain, nil
}

type PacketReader struct {
	r   io.Reader
	buf []byte
}

func NewPacketReader(r io.Reader) *PacketReader {
	return &PacketReader{r: r, buf: make([]byte, MaxPacketSize+2)}
}

func (pr *PacketReader) ReadPacket() ([]byte, error) {
	if _, err := io.ReadFull(pr.r, pr.buf[:2]); err != nil {
		return nil, err
	}
	encLen := binary.BigEndian.Uint16(pr.buf[:2])
	if encLen > MaxPacketSize {
		return nil, errors.New("packet too large")
	}
	if _, err := io.ReadFull(pr.r, pr.buf[:encLen]); err != nil {
		return nil, err
	}
	out := make([]byte, encLen)
	copy(out, pr.buf[:encLen])
	return out, nil
}

func buildRoutingRequest(destPK []byte) []byte {
	pkt := make([]byte, 1+PublicKeySize)
	pkt[0] = PacketRoutingRequest
	copy(pkt[1:], destPK[:PublicKeySize])
	return pkt
}

func buildRoutingResponse(connID uint8, pk []byte) []byte {
	pkt := make([]byte, 1+1+PublicKeySize)
	pkt[0] = PacketRoutingResponse
	pkt[1] = connID + NumReservedPorts
	copy(pkt[2:], pk[:PublicKeySize])
	return pkt
}

func buildConnNotification(connID uint8) []byte {
	return []byte{PacketConnectionNotification, connID}
}

func buildDisconnNotification(connID uint8) []byte {
	return []byte{PacketDisconnectNotification, connID}
}

func buildPing(id uint64) []byte {
	pkt := make([]byte, 1+8)
	pkt[0] = PacketPing
	binary.BigEndian.PutUint64(pkt[1:], id)
	return pkt
}

func buildPong(id uint64) []byte {
	pkt := make([]byte, 1+8)
	pkt[0] = PacketPong
	binary.BigEndian.PutUint64(pkt[1:], id)
	return pkt
}

func buildOOBSend(destPK []byte, data []byte) ([]byte, error) {
	if len(data) > MaxOOBDataLength {
		return nil, errors.New("OOB data too large")
	}
	pkt := make([]byte, 1+PublicKeySize+len(data))
	pkt[0] = PacketOOBSend
	copy(pkt[1:], destPK[:PublicKeySize])
	copy(pkt[1+PublicKeySize:], data)
	return pkt, nil
}

func buildOOBRecv(srcPK []byte, data []byte) []byte {
	pkt := make([]byte, 1+PublicKeySize+len(data))
	pkt[0] = PacketOOBRecv
	copy(pkt[1:], srcPK[:PublicKeySize])
	copy(pkt[1+PublicKeySize:], data)
	return pkt
}

func buildOnionRequest(data []byte) []byte {
	pkt := make([]byte, 1+len(data))
	pkt[0] = PacketOnionRequest
	copy(pkt[1:], data)
	return pkt
}

func buildOnionResponse(data []byte) []byte {
	pkt := make([]byte, 1+len(data))
	pkt[0] = PacketOnionResponse
	copy(pkt[1:], data)
	return pkt
}

func buildDataPacket(connID uint8, data []byte) ([]byte, error) {
	if connID >= NumClientConnections {
		return nil, errors.New("invalid connection ID")
	}
	pkt := make([]byte, 1+len(data))
	pkt[0] = connID + NumReservedPorts
	copy(pkt[1:], data)
	return pkt, nil
}

func parseRoutingResponse(plain []byte) (connID uint8, pk []byte, ok bool) {
	if len(plain) < 1+1+PublicKeySize || plain[0] != PacketRoutingResponse {
		return 0, nil, false
	}
	return plain[1], plain[2 : 2+PublicKeySize], true
}

func parseConnNotification(plain []byte) (connID uint8, ok bool) {
	if len(plain) < 2 || plain[0] != PacketConnectionNotification {
		return 0, false
	}
	return plain[1], true
}

func parseDisconnNotification(plain []byte) (connID uint8, ok bool) {
	if len(plain) < 2 || plain[0] != PacketDisconnectNotification {
		return 0, false
	}
	return plain[1], true
}

func parsePing(plain []byte) (id uint64, ok bool) {
	if len(plain) < 1+8 || plain[0] != PacketPing {
		return 0, false
	}
	return bytesToUint64(plain[1:9]), true
}

func parsePong(plain []byte) (id uint64, ok bool) {
	if len(plain) < 1+8 || plain[0] != PacketPong {
		return 0, false
	}
	return bytesToUint64(plain[1:9]), true
}

func parseOOBRecv(plain []byte) (pk []byte, data []byte, ok bool) {
	if len(plain) < 1+PublicKeySize || plain[0] != PacketOOBRecv {
		return nil, nil, false
	}
	return plain[1 : 1+PublicKeySize], plain[1+PublicKeySize:], true
}

func parseOnionResponse(plain []byte) (data []byte, ok bool) {
	if len(plain) < 1 || plain[0] != PacketOnionResponse {
		return nil, false
	}
	return plain[1:], true
}

func isDataPacket(plain []byte) bool {
	return len(plain) > 0 && plain[0] >= NumReservedPorts
}

func parseDataPacket(plain []byte) (connID uint8, data []byte, ok bool) {
	if len(plain) < 1 || plain[0] < NumReservedPorts {
		return 0, nil, false
	}
	return plain[0] - NumReservedPorts, plain[1:], true
}
