# KeyRing — Deterministic Key Derivation for P2P Protocols

A deterministic keyring that derives **identities and keys for 25+ P2P protocols** from a single 48-byte seed. Available in **C** and **Go**.

## How It Works

A 48-byte seed deterministically generates the key for every supported protocol. The same seed always produces the same keys. Seeds can be generated, saved, and loaded from a file.

```
Seed (48 bytes)
├── Nostr          (secp256k1)
├── BT-DHT         (Ed25519)
│   └── DrasilKey  (Ed25519 — yggdrasil-go v0.4+)
├── Tox            (X25519)
├── I2PD           (Ed25519 + X25519)
├── OpenDHT        (RSA-4096)
├── Group A: Ed25519 protocols (17 protocols)
├── Group B: secp256k1 protocols (7 protocols)
├── Group C: RSA protocols (2 protocols)
├── Group D: BLS12-381 protocols (3 protocols)
└── Group E: libp2p (Ed25519 / secp256k1 / RSA)
```

## Supported Protocols

### Base Protocols

| Function | Curve | Network | 入网认证 | Bootstrap 节点 |
|---|---|---|---|---|
| `keyring_nostr` | secp256k1 | Nostr | 无需 | `wss://relay.damus.io`、`wss://nos.lol`、`wss://relay.snort.social` |
| `keyring_btdht` | Ed25519 | Mainline BT-DHT | 无需 | `router.bittorrent.com:6881`、`dht.transmissionbt.com:6881`、`router.utorrent.com:6881` |
| `keyring_opendht` | RSA-4096 | OpenDHT | 无需 | `bootstrap.opendht.org:4222`、`bootstrap.jami.net:4222`、`bootstrap.ring.cx:4222` |
| `keyring_tox` | X25519 | Tox | 无需 | `tox.initramfs.io:33445`、`tox.abilinski.com:33445`、`tox.contact.place:33445` |
| `keyring_i2pd_ed` / `keyring_i2pd_x` | Ed25519 + X25519 | I2P (Java) | 无需 | 内置 floodfill 路由器列表 |

### Group A — Ed25519 Protocols

| Function | Network | 入网认证 | Bootstrap 节点 |
|---|---|---|---|
| `keyring_torv3_onion` / `keyring_torv3_secret` | Tor v3 Onion Service | 无需 | `tor26.grmrle.com`、`dizum.com`、`moria.csail.mit.edu`（目录权威） |
| `keyring_ssb_feedid` | Secure Scuttlebutt (SSB) | 无需 | `pub.andrewdo.es:8008`、`ssb.pub:8008`、`hermies.net:8008` |
| `keyring_hypercore_dk256` / `keyring_hypercore_dk512` | Hypercore (Dat) | 无需 | `bootstrap1.hypercore.dev:49737`、`bootstrap2.hypercore.dev:49737`、内置 Hyperswarm DHT |
| `keyring_cjdns_ipv6` | Cjdns | **无需**（v22 起自动 DNS 发现） | DNS seed: `seed.cjdns.ca`、`seed.mesh.jfod.org`、`seeder.cjdns.fr` |
| `keyring_yggdrasil_ipv6` / `keyring_drasil_key` | Yggdrasil | 无需 | `tcp://ygg1.mk16.de:1337`、`tcp://yggdrasil.su:62486`、`tcp://37.186.113.100:1514` |
| `keyring_nkn_nodeid` | NKN | **需注册**（挖矿需链上注册） | `seed.nkn.org:30001`、`seed.nkn.io:30001`、`seed2.nkn.org:30001` |
| `keyring_gnunet_peerid` | GNUnet | 无需 | `http://v10.gnunet.org/hostlist`（默认 hostlist）、gossip 发现 |
| `keyring_bitcoin_tor_key` | Bitcoin over Tor | 无需 | `seed.bitcoin.sipa.be`、`dnsseed.bluematt.me`、`seed.bitcoinstats.com` |
| `keyring_sia_nodekey` | Sia | 无需 | `gateway.sia.tech:9981`、`siad.tech:9981`、`bootstrap.sia.tech:9981` |
| `keyring_tahoe_nodeid` | Tahoe-LAFS | 无需 | 需自建或获取 introducer URL（无公共固定节点） |
| `keyring_tribler_peerid` | Tribler | 无需 | 内置 DHT 追踪器自动发现 |
| `keyring_stellar_nodeid` | Stellar | **需激活**（最低 1 XLM 激活账户） | `https://horizon.stellar.org`、`https://horizon.publicnode.org` |
| `keyring_handshake_nodekey` | Handshake | 无需（节点）/ **需 HNS**（挖矿/拍卖） | `a.ns.handshake.org`、`b.ns.handshake.org`、`ns1.dns-nodes.com` |
| `keyring_oxen_service_nodekey` | Oxen (Service Node) | **需质押**（25000 OXEN） | `seed1.oxen.io:22020`、`seed2.oxen.io:22020`、`seed3.oxen.io:22020` |
| `keyring_kayaknet_nodeid` | KayakNet | 无需 | 无公开固定节点（实验性网络，需手动 peering） |
| `keyring_cardano_kes_key` / `keyring_cardano_vrf_key` | Cardano (KES + VRF) | **需质押**（ADA 委托池出块） | `relays-new.cardano-mainnet.iohk.io:3001`、`relay1.mainnet.gomaestro.org:3001` |
| `keyring_urbit_net_key` / `keyring_urbit_crypt_key` | Urbit (Ames) | **需购买 Azimuth ID**（NFT 星球/恒星） | 通过 `~bus` 等星际节点发现（无需传统 bootstrap） |
| `keyring_tailscale_node_key` / `keyring_tailscale_machine_key` / `keyring_tailscale_tlk` | Tailscale | **需登录** Tailscale 账号 | `control.tailscale.com`（中心化协调服务器） |

### Group B — secp256k1 Protocols

| Function | Network | 入网认证 | Bootstrap 节点 |
|---|---|---|---|
| `keyring_bitcoin_v2_key` | Bitcoin (v2 P2P) | 无需 | `seed.bitcoin.sipa.be`、`dnsseed.bluematt.me`、`seed.bitcoinstats.com` |
| `keyring_eth_nodekey_hex` / `keyring_eth_nodeid` / `keyring_eth_enr_nodeid` | Ethereum (devp2p + ENR) | 无需 | `enode://...@bootnode.ethereum.org:30303`、`bootnode-aws.ethereum.org:30303`、`bootnode.dencun.ethereum.org:30303` |
| `keyring_lightning_nodeid` | Lightning Network | 无需 | 需 Bitcoin 全节点 + `0330bea1...@137.184.223.143:9735` 等公开 LN 节点 |
| `keyring_bitmessage_address` | Bitmessage | 无需 | `bootstrap1.bitmessage.org:8444`、`bootstrap2.bitmessage.org:8444`、`bootstrap3.bitmessage.org:8444` |
| `keyring_zeronet_address` | ZeroNet | 无需 | `zero://bootnode.zeronet.io:15441`、`bootnode.zeronet.io:15441` |
| `keyring_avalanche_nodeid` | Avalanche | 无需 | `api.avax.network:9651`、`seed1.avalabs.org:9651`、`seed2.avalabs.org:9651` |

### Group C — RSA Protocols

| Function | Network | 入网认证 | Bootstrap 节点 |
|---|---|---|---|
| `keyring_arweave_address` | Arweave | **需 AR 代币**（交易费用） | `arweave.net:1984`、`arweave.dev:1984`、`ar.io` 网关 |
| `keyring_storj_identity` | Storj | **需注册**（存储节点需 SNO 认证） | `us1.storj.io:28967`、`eu1.storj.io:28967`、`ap1.storj.io:28967` |

### Group D — BLS12-381 Protocols

| Function | Network | 入网认证 | Bootstrap 节点 |
|---|---|---|---|
| `keyring_chia_farmer_key` | Chia | **需磁盘**（Plot 耕种） | `dns-introducer.chia.net:8443`、`introducer.chia.net:8443` |
| `keyring_eth2_validator_key` | Ethereum 2.0 (consensus layer) | **需存入 32 ETH**（验证者） | `enr:-...@bootnode1.ethdevops.io:30303` |
| `keyring_avalanche_bls_key` | Avalanche (BLS subnet) | **需质押 AVAX**（子网验证） | 同上 Avalanche 节点 |

### Group E — libp2p

| Function | Key Types | 入网认证 | Bootstrap 节点 |
|---|---|---|---|
| `keyring_libp2p_peerid` | Ed25519 / secp256k1 / RSA | 无需 | `/dnsaddr/bootstrap.libp2p.io`、`/ip4/104.131.131.82/tcp/4001/p2p/Qm...`、`/dnsaddr/bootstrap.ipfs.io` |

## Dependencies

### C
- **OpenSSL** (≥3.0) — SHA256, HMAC, AES-CTR, BIGNUM, RSA
- **libsecp256k1** — secp256k1 key operations (Schnorr, ECDH)
- **libblst** — BLS12-381 group operations
- C99 compiler

### Go
- Go 1.25+
- `github.com/decred/dcrd/dcrec/secp256k1/v4`
- `github.com/kilic/bls12-381`
- `golang.org/x/crypto` (blake2b, ripemd160, sha3)

## Building

```sh
# C test binary
make test_keyring

# C run
make run_test_keyring

# Go tests
make keyring_go_test

# Clean
make clean
```

The `DEVSYS` environment variable (default: `/tmp/opencode/devsys`) points to a directory with:
- `usr/include/` — headers (blst.h, etc.)
- `usr/lib/x86_64-linux-gnu/` — libraries (libblst.a, libsecp256k1.so, etc.)

## Seed Format

The key file is a plaintext file with a single line:
```
seed=<96-hex-chars>
```

Example:
```
seed=aabbccddee00112233445566778899aabbccddee00112233445566778899aabbccddee00112233445566778899aa
```

## Example (C)

```c
#include "keyring.h"

KeyRing kr;
keyring_load("my.key", &kr);

uint8_t sk[32], pk[48];
keyring_chia_farmer_key(&kr, sk, pk);
// pk is 48-byte compressed G1 public key
```

## Example (Go)

```go
kr, _ := LoadKeyRing("my.key")
fmt.Println(kr.String())   // base protocol keys
fmt.Println(kr.ChiaFarmerKey())

// Yggdrasil v0.4+ keypair
sk, pk := kr.DrasilKey()
fmt.Printf("Drasil PrivateKey: %X\n", sk)
fmt.Printf("Drasil PublicKey:  %X\n", pk)
fmt.Println("Drasil Address:", kr.YggdrasilIPv6())
```
