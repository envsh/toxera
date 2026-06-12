package tcpclient

import (
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/nacl/box"
)

func generateKeyPair() (pub, sec *[32]byte, err error) {
	return box.GenerateKey(rand.Reader)
}

func beforeNm(pub, sec *[32]byte) *[32]byte {
	out := new([32]byte)
	box.Precompute(out, pub, sec)
	return out
}

func encryptDataSymmetric(shrkey *[32]byte, nonce *[24]byte, plain []byte) []byte {
	return box.SealAfterPrecomputation(nil, plain, nonce, shrkey)
}

func decryptDataSymmetric(shrkey *[32]byte, nonce *[24]byte, cipher []byte) ([]byte, bool) {
	return box.OpenAfterPrecomputation(nil, cipher, nonce, shrkey)
}

func randomNonce() *[24]byte {
	n := new([24]byte)
	if _, err := rand.Read(n[:]); err != nil {
		panic(err)
	}
	return n
}

func incrNonce(nonce *[24]byte) {
	for i := 23; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func bytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}
