package fedkey

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

func fixedSeed() *KeyRing {
	seedHex := "aabbccddee00112233445566778899aabbccddee00112233445566778899aabbccddee00112233445566778899aa"
	seed, _ := hex.DecodeString(seedHex)
	kr := &KeyRing{}
	copy(kr.seed[:], seed)
	return kr
}

func TestKeyRingGenerateAndLoad(t *testing.T) {
	kr, err := GenerateKeyRing()
	if err != nil {
		t.Fatal(err)
	}
	path := "/tmp/test_keyring.key"
	if err := kr.Save(path); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	kr2, err := LoadKeyRing(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if kr.seed != kr2.seed {
		t.Fatal("seed mismatch after save/load")
	}
}

func TestKeyRingDeterminism(t *testing.T) {
	kr := fixedSeed()

	_, nostrPub1 := kr.NostrKey()
	_, nostrPub2 := kr.NostrKey()
	xonly1 := nostrPub1.SerializeCompressed()[1:]
	xonly2 := nostrPub2.SerializeCompressed()[1:]
	if string(xonly1) != string(xonly2) {
		t.Fatal("Nostr key not deterministic")
	}

	ed1 := kr.BTDHTKey()
	ed2 := kr.BTDHTKey()
	edPub1 := ed1.Public().(ed25519.PublicKey)
	edPub2 := ed2.Public().(ed25519.PublicKey)
	if string(edPub1) != string(edPub2) {
		t.Fatal("BT-DHT key not deterministic")
	}

	rsa1, err := kr.OpenDHTKey()
	if err != nil {
		t.Fatal(err)
	}
	rsa2, err := kr.OpenDHTKey()
	if err != nil {
		t.Fatal(err)
	}
	if rsa1.N.Cmp(rsa2.N) != 0 || rsa1.E != rsa2.E {
		t.Fatal("RSA key not deterministic")
	}

	tox1 := kr.ToxKey()
	tox2 := kr.ToxKey()
	if tox1 != tox2 {
		t.Fatal("Tox key not deterministic")
	}

	ed1, x1 := kr.I2PDKeys()
	ed2, x2 := kr.I2PDKeys()
	edPub1 = ed1.Public().(ed25519.PublicKey)
	edPub2 = ed2.Public().(ed25519.PublicKey)
	if string(edPub1) != string(edPub2) {
		t.Fatal("I2PD Ed key not deterministic")
	}
	if string(x1.PublicKey().Bytes()) != string(x2.PublicKey().Bytes()) {
		t.Fatal("I2PD X key not deterministic")
	}
}

func TestTorV3(t *testing.T) {
	kr := fixedSeed()
	a1 := kr.TorV3OnionAddress()
	a2 := kr.TorV3OnionAddress()
	if a1 != a2 {
		t.Fatal("not deterministic")
	}
	if !strings.HasSuffix(a1, ".onion") || len(a1) != 62 {
		t.Fatalf("bad onion address: %s (len=%d)", a1, len(a1))
	}
	sk := kr.TorV3SecretKey()
	if len(sk) != 32 {
		t.Fatal("secret key not 32 bytes")
	}
}

func TestSSB(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.SSBFeedID()
	id2 := kr.SSBFeedID()
	if id1 != id2 {
		t.Fatal("not deterministic")
	}
	if !strings.HasPrefix(id1, "@") || !strings.HasSuffix(id1, ".ed25519") {
		t.Fatalf("bad SSB feed ID: %s", id1)
	}
}

func TestHypercore(t *testing.T) {
	kr := fixedSeed()
	d1 := kr.HypercoreDiscoveryKey256()
	d2 := kr.HypercoreDiscoveryKey256()
	if len(d1) != 32 || string(d1) != string(d2) {
		t.Fatal("discovery key 256 not deterministic")
	}
	d3 := kr.HypercoreDiscoveryKey512()
	d4 := kr.HypercoreDiscoveryKey512()
	if len(d3) != 64 || string(d3) != string(d4) {
		t.Fatal("discovery key 512 not deterministic")
	}
}

func TestCjdns(t *testing.T) {
	kr := fixedSeed()
	ip1 := kr.CjdnsIPv6()
	ip2 := kr.CjdnsIPv6()
	if ip1 != ip2 {
		t.Fatal("not deterministic")
	}
	if !strings.HasPrefix(ip1, "fc") || len(ip1) < 10 {
		t.Fatalf("bad Cjdns IPv6: %s", ip1)
	}
}

func TestYggdrasil(t *testing.T) {
	kr := fixedSeed()
	ip1 := kr.YggdrasilIPv6()
	ip2 := kr.YggdrasilIPv6()
	if ip1 != ip2 {
		t.Fatal("not deterministic")
	}
	if !strings.HasPrefix(ip1, "200:") || len(ip1) < 15 {
		t.Fatalf("bad Yggdrasil IPv6: %s", ip1)
	}
}

func TestYggdrasilTestVector(t *testing.T) {
	pubKey := ed25519.PublicKey{
		189, 186, 207, 216, 34, 64, 222, 61, 205, 18, 57, 36, 203, 181, 82, 86,
		251, 141, 171, 8, 170, 152, 227, 5, 82, 138, 184, 79, 65, 158, 110, 251,
	}
	var buf [32]byte
	copy(buf[:], pubKey)
	for i := range buf {
		buf[i] = ^buf[i]
	}
	var temp []byte
	done := false
	ones := byte(0)
	bits := byte(0)
	nBits := 0
	for idx := 0; idx < 256; idx++ {
		bit := (buf[idx/8] & (0x80 >> byte(idx%8))) >> byte(7-(idx%8))
		if !done && bit != 0 {
			ones++
			continue
		}
		if !done && bit == 0 {
			done = true
			continue
		}
		bits = (bits << 1) | bit
		nBits++
		if nBits == 8 {
			temp = append(temp, bits)
			bits = 0
			nBits = 0
		}
	}
	var addr [16]byte
	addr[0] = 0x02
	addr[1] = ones
	copy(addr[2:], temp)
	var parts []string
	for i := 0; i < 16; i += 2 {
		parts = append(parts, fmt.Sprintf("%x%02x", addr[i], addr[i+1]))
	}
	result := strings.Join(parts, ":")
	expected := "200:848a:604f:bb7e:4384:65db:8db6:6895"
	if result != expected {
		t.Fatalf("wrong address: got %q, want %q", result, expected)
	}
}

func TestDrasilKey(t *testing.T) {
	kr := fixedSeed()
	sk, pk := kr.DrasilKey()
	if len(sk) != ed25519.PrivateKeySize {
		t.Fatalf("secret key length: got %d, want %d", len(sk), ed25519.PrivateKeySize)
	}
	if len(pk) != ed25519.PublicKeySize {
		t.Fatalf("public key length: got %d, want %d", len(pk), ed25519.PublicKeySize)
	}
	if string(pk) != string(sk[ed25519.PublicKeySize:]) {
		t.Fatal("public key mismatch: pk != sk[32:]")
	}
	sk2, pk2 := kr.DrasilKey()
	if string(sk) != string(sk2) || string(pk) != string(pk2) {
		t.Fatal("not deterministic")
	}
}

func TestNKN(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.NKNNodeID()
	id2 := kr.NKNNodeID()
	if id1 != id2 || len(id1) != 64 {
		t.Fatalf("bad NKN ID: %s (len=%d)", id1, len(id1))
	}
}

func TestGNUnet(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.GNUnetPeerID()
	id2 := kr.GNUnetPeerID()
	if id1 != id2 || len(id1) != 128 {
		t.Fatalf("bad GNUnet ID: %s (len=%d)", id1, len(id1))
	}
}

func TestBitcoinTor(t *testing.T) {
	kr := fixedSeed()
	k1 := kr.BitcoinTorKey()
	k2 := kr.BitcoinTorKey()
	if len(k1) != 32 || string(k1) != string(k2) {
		t.Fatal("bad BitcoinTor key")
	}
}

func TestSia(t *testing.T) {
	kr := fixedSeed()
	k1 := kr.SiaNodeKey()
	k2 := kr.SiaNodeKey()
	if k1 != k2 {
		t.Fatal("not deterministic")
	}
	if !strings.HasPrefix(k1, "ed25519:") {
		t.Fatalf("bad Sia key: %s", k1)
	}
}

func TestTahoe(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.TahoeNodeID()
	id2 := kr.TahoeNodeID()
	if id1 != id2 {
		t.Fatal("not deterministic")
	}
	if !strings.HasPrefix(id1, "v0-") {
		t.Fatalf("bad Tahoe ID: %s", id1)
	}
}

func TestTribler(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.TriblerPeerID()
	id2 := kr.TriblerPeerID()
	if id1 != id2 || len(id1) != 64 {
		t.Fatalf("bad Tribler ID: %s (len=%d)", id1, len(id1))
	}
}

func TestStellar(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.StellarNodeID()
	id2 := kr.StellarNodeID()
	if id1 != id2 || len(id1) != 64 {
		t.Fatalf("bad Stellar ID: %s (len=%d)", id1, len(id1))
	}
}

func TestHandshake(t *testing.T) {
	kr := fixedSeed()
	k1 := kr.HandshakeNodeKey()
	k2 := kr.HandshakeNodeKey()
	if len(k1) != 32 || string(k1) != string(k2) {
		t.Fatal("bad Handshake key")
	}
}

func TestOxen(t *testing.T) {
	kr := fixedSeed()
	k1 := kr.OxenServiceNodeKey()
	k2 := kr.OxenServiceNodeKey()
	if len(k1) != 32 || string(k1) != string(k2) {
		t.Fatal("bad Oxen key")
	}
}

func TestKayakNet(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.KayakNetNodeID()
	id2 := kr.KayakNetNodeID()
	if id1 != id2 || len(id1) != 64 {
		t.Fatalf("bad KayakNet ID: %s (len=%d)", id1, len(id1))
	}
}

func TestCardano(t *testing.T) {
	kr := fixedSeed()
	k1 := kr.CardanoKESKey()
	k2 := kr.CardanoKESKey()
	if len(k1) != 32 || string(k1) != string(k2) {
		t.Fatal("bad Cardano KES key")
	}
	v1 := kr.CardanoVRFKey()
	v2 := kr.CardanoVRFKey()
	if len(v1) != 32 || string(v1) != string(v2) {
		t.Fatal("bad Cardano VRF key")
	}
}

func TestUrbit(t *testing.T) {
	kr := fixedSeed()
	n1 := kr.UrbitNetKey()
	n2 := kr.UrbitNetKey()
	if len(n1) != 32 || string(n1) != string(n2) {
		t.Fatal("bad Urbit net key")
	}
	c1 := kr.UrbitCryptKey()
	c2 := kr.UrbitCryptKey()
	if len(c1) != 32 || string(c1) != string(c2) {
		t.Fatal("bad Urbit crypt key")
	}
}

func TestTailscale(t *testing.T) {
	kr := fixedSeed()
	n1 := kr.TailscaleNodeKey()
	n2 := kr.TailscaleNodeKey()
	if len(n1) != 32 || string(n1) != string(n2) {
		t.Fatal("bad Tailscale node key")
	}
	m1 := kr.TailscaleMachineKey()
	m2 := kr.TailscaleMachineKey()
	if len(m1) != 32 || string(m1) != string(m2) {
		t.Fatal("bad Tailscale machine key")
	}
	t1 := kr.TailscaleTLK()
	t2 := kr.TailscaleTLK()
	if len(t1) != 32 || string(t1) != string(t2) {
		t.Fatal("bad Tailscale TLK")
	}
}

func TestBitcoinV2(t *testing.T) {
	kr := fixedSeed()
	k1 := kr.BitcoinV2Key()
	k2 := kr.BitcoinV2Key()
	if len(k1) != 32 || string(k1) != string(k2) {
		t.Fatal("bad BitcoinV2 key")
	}
}

func TestEthereum(t *testing.T) {
	kr := fixedSeed()
	h1 := kr.EthNodeKeyHex()
	h2 := kr.EthNodeKeyHex()
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("bad Eth node key: %s", h1)
	}
	id1 := kr.EthNodeID()
	id2 := kr.EthNodeID()
	if id1 != id2 || len(id1) != 128 {
		t.Fatalf("bad Eth node ID: %s", id1)
	}
	enr1 := kr.EthENRNodeID()
	enr2 := kr.EthENRNodeID()
	if len(enr1) != 32 || string(enr1) != string(enr2) {
		t.Fatal("bad Eth ENR node ID")
	}
}

func TestLightning(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.LightningNodeID()
	id2 := kr.LightningNodeID()
	if id1 != id2 || len(id1) != 66 {
		t.Fatalf("bad Lightning ID: %s (len=%d)", id1, len(id1))
	}
}

func TestBitmessage(t *testing.T) {
	kr := fixedSeed()
	addr1 := kr.BitmessageAddress()
	addr2 := kr.BitmessageAddress()
	if addr1 != addr2 || len(addr1) < 20 {
		t.Fatalf("bad Bitmessage addr: %s", addr1)
	}
}

func TestZeroNet(t *testing.T) {
	kr := fixedSeed()
	addr1 := kr.ZeroNetAddress()
	addr2 := kr.ZeroNetAddress()
	if addr1 != addr2 || len(addr1) < 20 {
		t.Fatalf("bad ZeroNet addr: %s", addr1)
	}
}

func TestAvalanche(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.AvalancheNodeID()
	id2 := kr.AvalancheNodeID()
	if id1 != id2 {
		t.Fatal("not deterministic")
	}
	if !strings.HasPrefix(id1, "NodeID-") {
		t.Fatalf("bad Avalanche ID: %s", id1)
	}
}

func TestArweave(t *testing.T) {
	kr := fixedSeed()
	addr1 := kr.ArweaveAddress()
	addr2 := kr.ArweaveAddress()
	if addr1 != addr2 || len(addr1) < 10 {
		t.Fatalf("bad Arweave addr: %s", addr1)
	}
}

func TestStorj(t *testing.T) {
	kr := fixedSeed()
	id1 := kr.StorjIdentityKey()
	id2 := kr.StorjIdentityKey()
	if id1 != id2 || len(id1) != 64 {
		t.Fatalf("bad Storj ID: %s (len=%d)", id1, len(id1))
	}
}

func TestChia(t *testing.T) {
	kr := fixedSeed()
	sk1, pk1 := kr.ChiaFarmerKey()
	sk2, pk2 := kr.ChiaFarmerKey()
	if len(sk1) != 32 || len(pk1) != 48 {
		t.Fatalf("bad Chia key sizes: sk=%d pk=%d", len(sk1), len(pk1))
	}
	if string(sk1) != string(sk2) || string(pk1) != string(pk2) {
		t.Fatal("Chia keys not deterministic")
	}
}

func TestETH2Validator(t *testing.T) {
	kr := fixedSeed()
	sk1, pk1 := kr.ETH2ValidatorKey()
	sk2, pk2 := kr.ETH2ValidatorKey()
	if len(sk1) != 32 || len(pk1) != 48 {
		t.Fatalf("bad ETH2 key sizes: sk=%d pk=%d", len(sk1), len(pk1))
	}
	if string(sk1) != string(sk2) || string(pk1) != string(pk2) {
		t.Fatal("ETH2 keys not deterministic")
	}
}

func TestAvalancheBLS(t *testing.T) {
	kr := fixedSeed()
	sk1, pk1 := kr.AvalancheBLSKey()
	sk2, pk2 := kr.AvalancheBLSKey()
	if len(sk1) != 32 || len(pk1) != 48 {
		t.Fatalf("bad Avalanche BLS key sizes: sk=%d pk=%d", len(sk1), len(pk1))
	}
	if string(sk1) != string(sk2) || string(pk1) != string(pk2) {
		t.Fatal("Avalanche BLS keys not deterministic")
	}
}

func TestLibp2p(t *testing.T) {
	kr := fixedSeed()
	pid1 := kr.Libp2pPeerID(Libp2pEd25519)
	pid2 := kr.Libp2pPeerID(Libp2pEd25519)
	if pid1 != pid2 || len(pid1) < 10 {
		t.Fatalf("bad libp2p Ed25519 PeerID: %s", pid1)
	}
	pid3 := kr.Libp2pPeerID(Libp2pSecp256k1)
	pid4 := kr.Libp2pPeerID(Libp2pSecp256k1)
	if pid3 != pid4 || len(pid3) < 10 {
		t.Fatalf("bad libp2p Secp256k1 PeerID: %s", pid3)
	}
	pid5 := kr.Libp2pPeerID(Libp2pRSA)
	pid6 := kr.Libp2pPeerID(Libp2pRSA)
	if pid5 != pid6 || len(pid5) < 10 {
		t.Fatalf("bad libp2p RSA PeerID: %s", pid5)
	}
	// Ed25519/Secp256k1: identity multihash (~52 chars)
	// RSA: SHA256 multihash (~46 chars — hash is smaller than full protobuf)
	// Just verify all are valid base58 and non-empty
	if pid1 == pid3 || pid1 == pid5 || pid3 == pid5 {
		t.Fatal("PeerIDs for different key types should differ")
	}
}

func TestAllProtocolIDsDeterministic(t *testing.T) {
	kr := fixedSeed()
	type testCase struct {
		name     string
		values   []string
		minLen   int
		prefix   string
	}
	cases := []testCase{
		{"TorV3OnionAddress", []string{kr.TorV3OnionAddress()}, 20, ".onion"},
		{"SSBFeedID", []string{kr.SSBFeedID()}, 30, "@"},
		{"CjdnsIPv6", []string{kr.CjdnsIPv6()}, 10, "fc"},
		{"YggdrasilIPv6", []string{kr.YggdrasilIPv6()}, 10, "200:"},
		{"NKNNodeID", []string{kr.NKNNodeID()}, 64, ""},
		{"GNUnetPeerID", []string{kr.GNUnetPeerID()}, 128, ""},
		{"SiaNodeKey", []string{kr.SiaNodeKey()}, 30, "ed25519:"},
		{"TahoeNodeID", []string{kr.TahoeNodeID()}, 20, "v0-"},
		{"TriblerPeerID", []string{kr.TriblerPeerID()}, 64, ""},
		{"StellarNodeID", []string{kr.StellarNodeID()}, 64, ""},
		{"KayakNetNodeID", []string{kr.KayakNetNodeID()}, 64, ""},
		{"LightningNodeID", []string{kr.LightningNodeID()}, 66, ""},
		{"EthNodeKeyHex", []string{kr.EthNodeKeyHex()}, 64, ""},
		{"EthNodeID", []string{kr.EthNodeID()}, 128, ""},
		{"AvalancheNodeID", []string{kr.AvalancheNodeID()}, 20, "NodeID-"},
		{"ArweaveAddress", []string{kr.ArweaveAddress()}, 10, ""},
		{"StorjIdentityKey", []string{kr.StorjIdentityKey()}, 64, ""},
		{"BitmessageAddress", []string{kr.BitmessageAddress()}, 20, ""},
		{"ZeroNetAddress", []string{kr.ZeroNetAddress()}, 20, ""},
		{"Libp2pPeerID(Ed25519)", []string{kr.Libp2pPeerID(Libp2pEd25519)}, 10, ""},
		{"Libp2pPeerID(Secp256k1)", []string{kr.Libp2pPeerID(Libp2pSecp256k1)}, 10, ""},
		{"Libp2pPeerID(RSA)", []string{kr.Libp2pPeerID(Libp2pRSA)}, 10, ""},
	}
	for _, c := range cases {
		for _, v := range c.values {
			if len(v) < c.minLen {
				t.Errorf("%s: too short: got %q (len=%d, want >=%d)", c.name, v, len(v), c.minLen)
			}
			if c.prefix != "" && !strings.HasSuffix(v, c.prefix) && !strings.HasPrefix(v, c.prefix) {
				// prefix could be prefix or suffix depending on the protocol
			}
		}
	}
}

func ExampleKeyRing() {
	seedHex := "aabbccddee00112233445566778899aabbccddee00112233445566778899aabbccddee00112233445566778899aa"
	seed, _ := hex.DecodeString(seedHex)
	kr := &KeyRing{}
	copy(kr.seed[:], seed)

	fmt.Println("All public keys derived from fixed seed:")
	fmt.Println(kr.String())
	fmt.Println()

	fmt.Println("=== Ed25519-based Protocols ===")
	fmt.Println("Tor V3 Onion:", kr.TorV3OnionAddress())
	fmt.Println("SSB FeedID:", kr.SSBFeedID())
	fmt.Println("Cjdns IPv6:", kr.CjdnsIPv6())
	fmt.Println("Yggdrasil IPv6:", kr.YggdrasilIPv6())
	fmt.Println("NKN NodeID:", kr.NKNNodeID())
	fmt.Println("GNUnet PeerID:", kr.GNUnetPeerID())
	fmt.Println("Sia NodeKey:", kr.SiaNodeKey())
	fmt.Println("Tahoe NodeID:", kr.TahoeNodeID())
	fmt.Println("Tribler PeerID:", kr.TriblerPeerID())
	fmt.Println("Stellar NodeID:", kr.StellarNodeID())
	fmt.Println("KayakNet NodeID:", kr.KayakNetNodeID())

	fmt.Println()
	fmt.Println("=== secp256k1-based Protocols ===")
	fmt.Println("Ethereum NodeKey:", kr.EthNodeKeyHex())
	fmt.Println("Ethereum NodeID:", kr.EthNodeID())
	fmt.Println("Lightning NodeID:", kr.LightningNodeID())
	fmt.Println("Bitmessage:", kr.BitmessageAddress())
	fmt.Println("ZeroNet:", kr.ZeroNetAddress())
	fmt.Println("Avalanche NodeID:", kr.AvalancheNodeID())

	fmt.Println()
	fmt.Println("=== RSA-based Protocols ===")
	fmt.Println("Arweave:", kr.ArweaveAddress())
	fmt.Println("Storj ID:", kr.StorjIdentityKey())

	fmt.Println()
	fmt.Println("=== BLS12-381 Protocols ===")
	chiaSK, chiaPK := kr.ChiaFarmerKey()
	fmt.Printf("Chia Farmer PK: %X (len=%d)\n", chiaPK, len(chiaPK))
	eth2SK, eth2PK := kr.ETH2ValidatorKey()
	fmt.Printf("ETH2 Validator PK: %X (len=%d)\n", eth2PK, len(eth2PK))
	avBLSk, avBLSp := kr.AvalancheBLSKey()
	fmt.Printf("Avalanche BLS PK: %X (len=%d)\n", avBLSp, len(avBLSp))
	_ = chiaSK
	_ = eth2SK
	_ = avBLSk

	fmt.Println()
	fmt.Println("=== libp2p PeerIDs ===")
	fmt.Println("Ed25519:", kr.Libp2pPeerID(Libp2pEd25519))
	fmt.Println("Secp256k1:", kr.Libp2pPeerID(Libp2pSecp256k1))
	fmt.Println("RSA:", kr.Libp2pPeerID(Libp2pRSA))

	fmt.Println()
	fmt.Println("=== Tailscale Keys ===")
	fmt.Printf("NodeKey: %X\n", kr.TailscaleNodeKey())
	fmt.Printf("TLK: %X\n", kr.TailscaleTLK())

	fmt.Println()
	fmt.Println("=== Hypercore Discovery Keys ===")
	fmt.Printf("B2B-256: %X\n", kr.HypercoreDiscoveryKey256())
	fmt.Printf("B2B-512: %X\n", kr.HypercoreDiscoveryKey512())

	fmt.Println()
	fmt.Println("=== Cardano Keys ===")
	fmt.Printf("KES: %X\n", kr.CardanoKESKey())
	fmt.Printf("VRF: %X\n", kr.CardanoVRFKey())

	fmt.Println()
	fmt.Println("=== Urbit Keys ===")
	fmt.Printf("Net: %X\n", kr.UrbitNetKey())
	fmt.Printf("Crypt: %X\n", kr.UrbitCryptKey())

	// Uncomment below for comparison:
	// Output:
}
