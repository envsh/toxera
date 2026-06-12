package tcpclient

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestGenerateKeyPair(t *testing.T) {
	pk, sk, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}
	if pk == nil || sk == nil {
		t.Fatal("got nil key")
	}
	if len(pk) != 32 || len(sk) != 32 {
		t.Fatalf("unexpected key size: pub=%d sec=%d", len(pk), len(sk))
	}
}

func TestBeforeNmDeterministic(t *testing.T) {
	alicePub, aliceSec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bobPub, bobSec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sk1 := beforeNm(bobPub, aliceSec)
	sk2 := beforeNm(alicePub, bobSec)

	if !bytes.Equal(sk1[:], sk2[:]) {
		t.Fatal("shared keys do not match (DH property not satisfied)")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	_, sec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	shr := beforeNm(pub, sec)

	nonce := randomNonce()
	plain := []byte("hello tox tcp relay")

	cipher := encryptDataSymmetric(shr, nonce, plain)
	if len(cipher) != len(plain)+box.Overhead {
		t.Fatalf("unexpected cipher length: got %d, expected %d", len(cipher), len(plain)+box.Overhead)
	}

	decrypted, ok := decryptDataSymmetric(shr, nonce, cipher)
	if !ok {
		t.Fatal("decryption failed")
	}
	if !bytes.Equal(plain, decrypted) {
		t.Fatalf("round trip failed: got %x, expected %x", decrypted, plain)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	_, sec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	shr := beforeNm(pub, sec)

	nonce := randomNonce()
	plain := []byte("test data")
	cipher := encryptDataSymmetric(shr, nonce, plain)

	wrongPub, wrongSec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrongShr := beforeNm(wrongPub, wrongSec)

	_, ok := decryptDataSymmetric(wrongShr, nonce, cipher)
	if ok {
		t.Fatal("decryption should have failed with wrong key")
	}
}

func TestRandomNonce(t *testing.T) {
	n1 := randomNonce()
	n2 := randomNonce()

	if bytes.Equal(n1[:], n2[:]) {
		t.Fatal("two random nonces should not be equal")
	}

	if len(n1) != 24 {
		t.Fatalf("nonce has wrong length: %d", len(n1))
	}
}

func TestIncrNonce(t *testing.T) {
	n := randomNonce()
	orig := *n

	incrNonce(n)

	if bytes.Equal(n[:], orig[:]) {
		t.Fatal("nonce should change after increment")
	}
}

func TestIncrNonceWraparound(t *testing.T) {
	var n [24]byte
	for i := 0; i < 24; i++ {
		n[i] = 0xFF
	}
	incrNonce(&n)

	var expected [24]byte
	if !bytes.Equal(n[:], expected[:]) {
		t.Fatalf("wraparound failed: got %x, expected zeros", n[:])
	}
}

func TestIncrNonceLastByte(t *testing.T) {
	var n [24]byte
	n[23] = 0x01
	incrNonce(&n)

	if n[23] != 0x02 {
		t.Fatalf("expected last byte 0x02, got 0x%02x", n[23])
	}

	var n2 [24]byte
	n2[23] = 0xFF
	incrNonce(&n2)
	if n2[23] != 0x00 || n2[22] != 0x01 {
		t.Fatalf("carry failed: expected [22]=1 [23]=0, got [22]=%d [23]=%d", n2[22], n2[23])
	}
}

func TestMultipleEncryptDecrypt(t *testing.T) {
	_, sec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	shr := beforeNm(pub, sec)

	nonce := randomNonce()
	messages := []string{"msg1", "msg2", "msg3", "a longer message for testing"}

	for _, msg := range messages {
		plain := []byte(msg)
		cipher := encryptDataSymmetric(shr, nonce, plain)
		decrypted, ok := decryptDataSymmetric(shr, nonce, cipher)
		if !ok {
			t.Fatalf("decryption failed for %q", msg)
		}
		if !bytes.Equal(plain, decrypted) {
			t.Fatalf("mismatch for %q", msg)
		}
	}
}

func TestKeyConsistencyAfterNonceIncrement(t *testing.T) {
	_, sec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	shr := beforeNm(pub, sec)

	nonce1 := randomNonce()
	nonce2 := *nonce1
	incrNonce(&nonce2)

	plain1 := []byte("first")
	plain2 := []byte("second")

	c1 := encryptDataSymmetric(shr, nonce1, plain1)
	d1, ok := decryptDataSymmetric(shr, nonce1, c1)
	if !ok || !bytes.Equal(d1, plain1) {
		t.Fatal("first encrypt/decrypt failed")
	}

	c2 := encryptDataSymmetric(shr, &nonce2, plain2)
	d2, ok := decryptDataSymmetric(shr, &nonce2, c2)
	if !ok || !bytes.Equal(d2, plain2) {
		t.Fatal("second encrypt/decrypt failed")
	}

	_, ok = decryptDataSymmetric(shr, nonce1, c2)
	if ok {
		t.Fatal("should not decrypt second cipher with first nonce")
	}
}

func TestUint64ToBytesRoundTrip(t *testing.T) {
	vals := []uint64{0, 1, 255, 65535, 4294967295, 18446744073709551615}
	for _, v := range vals {
		b := uint64ToBytes(v)
		got := bytesToUint64(b)
		if got != v {
			t.Fatalf("round trip failed: %d -> %x -> %d", v, b, got)
		}
	}
	if len(uint64ToBytes(0)) != 8 {
		t.Fatal("uint64ToBytes should return 8 bytes")
	}
}

func TestGenerateSelfKeys(t *testing.T) {
	pk, sk, err := generateSelfKeys()
	if err != nil {
		t.Fatalf("generateSelfKeys failed: %v", err)
	}
	if pk == nil || sk == nil {
		t.Fatal("got nil key")
	}

	shr := beforeNm(pk, sk)
	nonce := randomNonce()
	plain := []byte("self encrypt test")
	cipher := encryptDataSymmetric(shr, nonce, plain)
	decrypted, ok := decryptDataSymmetric(shr, nonce, cipher)
	if !ok || !bytes.Equal(plain, decrypted) {
		t.Fatal("self key encrypt/decrypt failed")
	}
}

func TestRandomUint64(t *testing.T) {
	v1 := randomUint64()
	v2 := randomUint64()
	if v1 == v2 {
		t.Log("warning: random values collided (extremely unlikely)")
	}
	_ = v1
	_ = v2
}

func TestLargePlaintextEncrypt(t *testing.T) {
	_, sec, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	shr := beforeNm(pub, sec)
	nonce := randomNonce()

	plain := make([]byte, 2048)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}

	cipher := encryptDataSymmetric(shr, nonce, plain)
	decrypted, ok := decryptDataSymmetric(shr, nonce, cipher)
	if !ok || !bytes.Equal(plain, decrypted) {
		t.Fatal("large plaintext round trip failed")
	}
}
