package fedbase

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/kilic/bls12-381"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

const (
	SeedBytes = 48
	KeyBytes  = 32
)

type KeyRing struct {
	seed [SeedBytes]byte
}

func GenerateKeyRing() (*KeyRing, error) {
	kr := new(KeyRing)
	_, err := rand.Read(kr.seed[:])
	if err != nil {
		return nil, err
	}
	return kr, nil
}

func LoadKeyRing(path string) (*KeyRing, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kr := new(KeyRing)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "seed=") {
			s := strings.TrimSpace(line[5:])
			if len(s) != SeedBytes*2 {
				return nil, errors.New("invalid seed hex length")
			}
			_, err := hex.Decode(kr.seed[:], []byte(s))
			if err != nil {
				return nil, fmt.Errorf("invalid seed hex: %v", err)
			}
			return kr, nil
		}
	}
	return nil, errors.New("no seed= line in key file")
}

func (kr *KeyRing) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "seed=%s\n", hex.EncodeToString(kr.seed[:]))
	return err
}

func (kr *KeyRing) raw() []byte {
	return kr.seed[:KeyBytes]
}

func (kr *KeyRing) NostrKey() (*secp256k1.PrivateKey, *secp256k1.PublicKey) {
	priv := secp256k1.PrivKeyFromBytes(kr.raw())
	return priv, priv.PubKey()
}

func (kr *KeyRing) BTDHTKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(kr.raw())
}

func (kr *KeyRing) OpenDHTKey() (*rsa.PrivateKey, error) {
	block, err := aes.NewCipher(kr.seed[:KeyBytes])
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, kr.seed[KeyBytes:])
	return deterministicRSA4096(stream)
}

func deterministicRSA4096(stream cipher.Stream) (*rsa.PrivateKey, error) {
	rand := &ctrStream{stream: stream}

	p, err := bigPrime(rand, 2048)
	if err != nil {
		return nil, err
	}
	q, err := bigPrime(rand, 2048)
	if err != nil {
		return nil, err
	}
	if p.Cmp(q) == 0 {
		q, err = bigPrime(rand, 2048)
		if err != nil {
			return nil, err
		}
	}
	if p.Cmp(q) < 0 {
		p, q = q, p
	}

	n := new(big.Int).Mul(p, q)
	e := big.NewInt(65537)

	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	totient := new(big.Int).Mul(pMinus1, qMinus1)

	d := new(big.Int).ModInverse(e, totient)
	if d == nil {
		return nil, errors.New("modular inverse failed")
	}

	dp := new(big.Int).Mod(d, pMinus1)
	dq := new(big.Int).Mod(d, qMinus1)
	qInv := new(big.Int).ModInverse(q, p)

	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: 65537},
		D:         d,
		Primes:    []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{
			Dp:   dp,
			Dq:   dq,
			Qinv: qInv,
		},
	}, nil
}

type ctrStream struct {
	stream  cipher.Stream
	zeroBuf [4096]byte
}

func (r *ctrStream) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		chunk := len(p) - n
		if chunk > len(r.zeroBuf) {
			chunk = len(r.zeroBuf)
		}
		r.stream.XORKeyStream(r.zeroBuf[:chunk], r.zeroBuf[:chunk])
		n += copy(p[n:], r.zeroBuf[:chunk])
	}
	return len(p), nil
}

var smallPrimes = []uint{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
	59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
	131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
	211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
	293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
	389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
	479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
	587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
	673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
	773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
	881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
	991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
	1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181,
	1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
	1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
	1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487,
	1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583,
	1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693,
	1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
	1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907,
	1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017,
	2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,
	2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243,
	2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347,
	2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441,
	2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579,
	2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
	2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777,
	2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887,
	2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011,
	3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
	3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257,
	3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361,
	3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491,
	3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583,
	3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697,
	3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821,
	3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923,
	3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
	4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157,
	4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271,
	4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409,
	4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
	4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649,
	4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783,
	4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909,
	4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999,
}

func trialDiv(p *big.Int) bool {
	for _, prime := range smallPrimes {
		r := new(big.Int).Rem(p, big.NewInt(int64(prime)))
		if r.Sign() == 0 {
			return false
		}
	}
	return true
}

func bigPrime(r io.Reader, bits int) (*big.Int, error) {
	bytes := (bits + 7) / 8
	b := make([]byte, bytes)
	excess := bytes*8 - bits
	for {
		_, err := io.ReadFull(r, b)
		if err != nil {
			return nil, err
		}
		b[0] &= byte(0xFF >> excess)
		b[0] |= 0x80
		b[bytes-1] |= 1
		p := new(big.Int).SetBytes(b)
		if !trialDiv(p) {
			continue
		}
		if p.ProbablyPrime(6) {
			return p, nil
		}
	}
}

func (kr *KeyRing) ToxKey() [KeyBytes]byte {
	var sk [KeyBytes]byte
	copy(sk[:], kr.raw())
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	return sk
}

func (kr *KeyRing) I2PDKeys() (ed25519.PrivateKey, *ecdh.PrivateKey) {
	ed := ed25519.NewKeyFromSeed(kr.raw())
	x, err := ecdh.X25519().NewPrivateKey(kr.raw())
	if err != nil {
		panic(err)
	}
	return ed, x
}

func (kr *KeyRing) String() string {
	var b strings.Builder

	_, nostrPub := kr.NostrKey()
	xonly := nostrPub.SerializeCompressed()[1:]
	fmt.Fprintf(&b, "Nostr  (secp256k1): %X\n", xonly)

	ed := kr.BTDHTKey()
	fmt.Fprintf(&b, "BT-DHT (ed25519):   %X\n", []byte(ed.Public().(ed25519.PublicKey)))

	toxSK := kr.ToxKey()
	xpriv, _ := ecdh.X25519().NewPrivateKey(toxSK[:])
	fmt.Fprintf(&b, "Tox    (X25519):    %X\n", xpriv.PublicKey().Bytes())

	ed2, x2 := kr.I2PDKeys()
	fmt.Fprintf(&b, "I2PD   (Ed25519):  %X\n", []byte(ed2.Public().(ed25519.PublicKey)))
	fmt.Fprintf(&b, "I2PD   (X25519):   %X\n", x2.PublicKey().Bytes())

	return b.String()
}

// ------- internal helpers -------

func (kr *KeyRing) ed25519Pub() []byte {
	return []byte(kr.BTDHTKey().Public().(ed25519.PublicKey))
}

func (kr *KeyRing) secp256k1Priv() *secp256k1.PrivateKey {
	priv, _ := kr.NostrKey()
	return priv
}

func (kr *KeyRing) secp256k1Pub() []byte {
	_, pub := kr.NostrKey()
	return pub.SerializeCompressed()
}

func (kr *KeyRing) secp256k1PubUncompressed() []byte {
	_, pub := kr.NostrKey()
	return pub.SerializeUncompressed()
}

func (kr *KeyRing) x25519Priv() []byte {
	return kr.raw()
}

func (kr *KeyRing) x25519Pub() []byte {
	x, err := ecdh.X25519().NewPrivateKey(kr.x25519Priv())
	if err != nil {
		panic(err)
	}
	return x.PublicKey().Bytes()
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func blake2b256(key, data []byte) []byte {
	h, err := blake2b.New256(key)
	if err != nil {
		panic(err)
	}
	h.Write(data)
	return h.Sum(nil)
}

func blake2b512(key, data []byte) []byte {
	h, err := blake2b.New512(key)
	if err != nil {
		panic(err)
	}
	h.Write(data)
	return h.Sum(nil)
}

func base32Encode(data []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(data), "=")
}

var yggdrasilAlphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

func base32YggdrasilEncode(data []byte) string {
	bits := 0
	buffer := 0
	var out strings.Builder
	for _, b := range data {
		buffer = (buffer << 8) | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(yggdrasilAlphabet[(buffer>>bits)&0x1F])
		}
	}
	if bits > 0 {
		out.WriteByte(yggdrasilAlphabet[(buffer<<(5-bits))&0x1F])
	}
	return out.String()
}

var base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(data []byte) string {
	n := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	var digits []byte
	for n.Cmp(zero) > 0 {
		mod := new(big.Int)
		n.DivMod(n, base, mod)
		digits = append(digits, base58Alphabet[mod.Int64()])
	}
	for _, b := range data {
		if b != 0 {
			break
		}
		digits = append(digits, base58Alphabet[0])
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk []byte, length int) []byte {
	var t []byte
	var out []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

func ripemd160Hash(data []byte) []byte {
	h := ripemd160.New()
	h.Write(data)
	return h.Sum(nil)
}

func sha256d(data []byte) []byte {
	h := sha256.Sum256(data)
	h2 := sha256.Sum256(h[:])
	return h2[:]
}

func base58Check(version byte, data []byte) string {
	payload := append([]byte{version}, data...)
	checksum := sha256d(payload)[:4]
	return base58Encode(append(payload, checksum...))
}

func bitcoinAddress(pubKeyCompressed []byte) string {
	sha := sha256.Sum256(pubKeyCompressed)
	ripe := ripemd160Hash(sha[:])
	return base58Check(0x00, ripe)
}

// ====== Group A: Ed25519 Protocols ======

func (kr *KeyRing) TorV3OnionAddress() string {
	pub := kr.ed25519Pub()
	ver := byte(0x03)
	checksumInput := append([]byte(".onion checksum"), pub...)
	checksumInput = append(checksumInput, ver)
	checksum := sha256.Sum256(checksumInput)
	addrData := append(pub, checksum[:2]...)
	addrData = append(addrData, ver)
	return strings.ToLower(base32Encode(addrData)) + ".onion"
}

func (kr *KeyRing) TorV3SecretKey() []byte {
	return kr.raw()
}

func (kr *KeyRing) SSBFeedID() string {
	pub := kr.ed25519Pub()
	return "@" + base64.StdEncoding.EncodeToString(pub) + ".ed25519"
}

func (kr *KeyRing) HypercoreDiscoveryKey256() []byte {
	return blake2b256([]byte("HYPERCORE"), kr.ed25519Pub())
}

func (kr *KeyRing) HypercoreDiscoveryKey512() []byte {
	return blake2b512([]byte("HYPERCORE"), kr.ed25519Pub())
}

func (kr *KeyRing) CjdnsIPv6() string {
	h := sha512.Sum512(kr.ed25519Pub())
	addr := make([]byte, 16)
	copy(addr, h[:16])
	addr[0] = (addr[0] & 0x0F) | 0xFC
	var parts []string
	for i := 0; i < 16; i += 2 {
		parts = append(parts, fmt.Sprintf("%02x%02x", addr[i], addr[i+1]))
	}
	return "fc" + strings.Join(parts, ":")[2:]
}

func (kr *KeyRing) YggdrasilIPv6() string {
	h := sha512.Sum512(kr.ed25519Pub())
	enc := base32YggdrasilEncode(h[1:16])
	if len(enc) > 26 {
		enc = enc[:26]
	}
	var parts []string
	for i := 0; i < len(enc); i += 4 {
		end := i + 4
		if end > len(enc) {
			end = len(enc)
		}
		parts = append(parts, enc[i:end])
	}
	return "200:" + strings.Join(parts, ":")
}

func (kr *KeyRing) NKNNodeID() string {
	h := sha256.Sum256(kr.ed25519Pub())
	return hex.EncodeToString(h[:])
}

func (kr *KeyRing) GNUnetPeerID() string {
	h := sha512.Sum512(kr.ed25519Pub())
	return hex.EncodeToString(h[:])
}

func (kr *KeyRing) BitcoinTorKey() []byte {
	return kr.raw()
}

func (kr *KeyRing) SiaNodeKey() string {
	return "ed25519:" + hex.EncodeToString(kr.ed25519Pub())
}

func (kr *KeyRing) TahoeNodeID() string {
	return "v0-" + base32Encode(kr.ed25519Pub())
}

func (kr *KeyRing) TriblerPeerID() string {
	return hex.EncodeToString(kr.ed25519Pub())
}

func (kr *KeyRing) StellarNodeID() string {
	return hex.EncodeToString(kr.ed25519Pub())
}

func (kr *KeyRing) HandshakeNodeKey() []byte {
	return kr.raw()
}

func (kr *KeyRing) OxenServiceNodeKey() []byte {
	return kr.raw()
}

func (kr *KeyRing) KayakNetNodeID() string {
	return hex.EncodeToString(kr.ed25519Pub())
}

func (kr *KeyRing) CardanoKESKey() []byte {
	return kr.raw()
}

func (kr *KeyRing) CardanoVRFKey() []byte {
	return kr.raw()
}

func (kr *KeyRing) UrbitNetKey() []byte {
	return kr.raw()
}

func (kr *KeyRing) UrbitCryptKey() []byte {
	// X25519, no clamping required by Urbit's Ames protocol
	return kr.raw()
}

func (kr *KeyRing) TailscaleNodeKey() []byte {
	return kr.raw()
}

func (kr *KeyRing) TailscaleMachineKey() []byte {
	return kr.raw()
}

func (kr *KeyRing) TailscaleTLK() []byte {
	return kr.raw()
}

// ====== Group B: secp256k1 Protocols ======

func (kr *KeyRing) BitcoinV2Key() []byte {
	return kr.secp256k1Priv().Serialize()
}

func (kr *KeyRing) EthNodeKeyHex() string {
	return hex.EncodeToString(kr.secp256k1Priv().Serialize())
}

func (kr *KeyRing) EthNodeID() string {
	raw := kr.secp256k1PubUncompressed()
	// skip 0x04 prefix, take x||y (64 bytes)
	return hex.EncodeToString(raw[1:])
}

func (kr *KeyRing) EthENRNodeID() []byte {
	raw := kr.secp256k1PubUncompressed()
	return keccak256(raw[1:])
}

func (kr *KeyRing) LightningNodeID() string {
	return hex.EncodeToString(kr.secp256k1Pub())
}

func (kr *KeyRing) BitmessageAddress() string {
	signPriv := kr.secp256k1Priv()
	_, signPub := signPriv.PubKey().SerializeUncompressed(), signPriv.PubKey()
	// encryption key derived from SHA256(seed[32:48])
	encSeed := sha256.Sum256(kr.seed[KeyBytes:])
	encPriv := secp256k1.PrivKeyFromBytes(encSeed[:])
	encPub := encPriv.PubKey().SerializeUncompressed()
	signPubRaw := signPub.SerializeUncompressed()
	merged := append(signPubRaw, encPub...)
	sha := sha512.Sum512(merged)
	ripe := ripemd160Hash(sha[:])
	return base58Check(0x00, ripe)
}

func (kr *KeyRing) ZeroNetAddress() string {
	return bitcoinAddress(kr.secp256k1Pub())
}

func (kr *KeyRing) AvalancheNodeID() string {
	h := sha256.Sum256(kr.secp256k1Pub())
	return "NodeID-" + base58Encode(h[:20])
}

// ====== Group C: RSA Protocols ======

func (kr *KeyRing) ArweaveAddress() string {
	rsaKey, err := kr.OpenDHTKey()
	if err != nil {
		return ""
	}
	nBytes := rsaKey.N.Bytes()
	h := sha256.Sum256(nBytes)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (kr *KeyRing) StorjIdentityKey() string {
	// NOTE: Storj requires proof-of-work (>=36 zero bits).
	// This returns the raw identity key; caller must perform PoW.
	h := sha256.Sum256(kr.secp256k1Pub())
	return hex.EncodeToString(h[:])
}

// ====== Group D: BLS12-381 Protocols ======

func blsKeyGen(ikm []byte) ([]byte, []byte) {
	salt := []byte("BLS-SIG-KEYGEN-SALT-")
	prk := hkdfExtract(salt, ikm)
	okm := hkdfExpand(prk, 48)
	sk := new(big.Int).SetBytes(okm)
	q, _ := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	sk.Mod(sk, q)
	skBytes := make([]byte, 32)
	sk.FillBytes(skBytes)

	g1 := bls12381.NewG1()
	gen := g1.One()
	fr := new(bls12381.Fr)
	frFromBytes(fr, skBytes)
	pub := g1.New()
	g1.MulScalar(pub, gen, fr)
	pubBytes := g1.ToCompressed(pub)

	return skBytes, pubBytes
}

func frFromBytes(fr *bls12381.Fr, b []byte) {
	// Represent b as big-endian bytes, convert to Fr via library internals
	// kilic/bls12-381 uses [4]uint64 little-endian limbs
	var limbs [4]uint64
	for i := 0; i < 4 && i*8 < len(b); i++ {
		for j := 0; j < 8 && i*8+j < len(b); j++ {
			limbs[i] |= uint64(b[len(b)-1-(i*8+j)]) << (j * 8)
		}
	}
	*fr = bls12381.Fr(limbs)
}

func (kr *KeyRing) ChiaFarmerKey() ([]byte, []byte) {
	return blsKeyGen(kr.raw())
}

func (kr *KeyRing) ETH2ValidatorKey() ([]byte, []byte) {
	sk, pk := blsKeyGen(kr.raw())
	return sk, pk
}

func (kr *KeyRing) AvalancheBLSKey() ([]byte, []byte) {
	sk, pk := blsKeyGen(kr.raw())
	return sk, pk
}

// ====== Group E: libp2p ======

const (
	Libp2pEd25519   = iota
	Libp2pSecp256k1
	Libp2pRSA
)

func protoVarint(v uint64) []byte {
	var b []byte
	for v > 0x7F {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func protoLenDelim(field uint64, data []byte) []byte {
	var buf []byte
	buf = append(buf, protoVarint(field*8+2)...)  // wire type 2 (length-delimited)
	buf = append(buf, protoVarint(uint64(len(data)))...)
	buf = append(buf, data...)
	return buf
}

func protoVarintField(field uint64, value uint64) []byte {
	var buf []byte
	buf = append(buf, protoVarint(field*8+0)...)  // wire type 0 (varint)
	buf = append(buf, protoVarint(value)...)
	return buf
}

func multihashEncode(code uint64, data []byte) []byte {
	var buf []byte
	buf = append(buf, protoVarint(code)...)
	buf = append(buf, protoVarint(uint64(len(data)))...)
	buf = append(buf, data...)
	return buf
}

func (kr *KeyRing) Libp2pPeerID(kind int) string {
	var pubKeyData []byte
	var keyType uint64
	switch kind {
	case Libp2pEd25519:
		pubKeyData = kr.ed25519Pub()
		keyType = 1
	case Libp2pSecp256k1:
		pubKeyData = kr.secp256k1Pub()
		keyType = 2
	case Libp2pRSA:
		rsaKey, err := kr.OpenDHTKey()
		if err != nil {
			return ""
		}
		pubKeyData = rsaKey.N.Bytes()
		keyType = 0
	default:
		return ""
	}
	pubProto := append(protoVarintField(1, keyType), protoLenDelim(2, pubKeyData)...)
	if len(pubProto) <= 42 {
		return base58Encode(multihashEncode(0x00, pubProto))
	}
	h := sha256.Sum256(pubProto)
	return base58Encode(multihashEncode(0x12, h[:]))
}
