# relayhub — libp2p Circuit Relay 纯 Go 实现

## 目标
纯 Go 实现 libp2p Circuit Relay 客户端（无 libp2p 依赖），连接公共中继并通过中继路由数据到目标 peer。

## 原则
- 核心协议（multistream、protobuf、base58）手工实现，零外部依赖
- PeerID 由 `fedkey.KeyRing` 种子派生：`kr.Libp2pPeerID(kind)` → base58 → `ParsePeerID()`
- 必须使用公共中继，不自建
- 必须通过 live relay 测试验证

## 实现架构

```
TCP 连接
  ↓ Multistream-Select 版本协商 (/multistream/1.0.0)
  ↓ 安全传输 (TLS 1.3 / Noise XX)，自动协商：noise → TLS 回退
  ↓ Multistream-Select yamux 协商
  ↓ Yamux 会话
  ├── Circuit v2 HOP (CONNECT)
  ├── Circuit v1 HOP (v2 不可用时回退)
  └── Circuit v2 RESERVE (等待 STOP)
```

## 文件结构

| 文件 | 职责 |
|------|------|
| `relay.go` | `RelayClient`、`RelayedConn`、Connect/ConnectTLS/Reserve/ConnectThroughRelay |
| `tls.go` | go-libp2p 兼容的 TLS 1.3 证书生成 + `ConnectTLS()` |
| `noise.go` | Noise XX 握手 + noiseConn (net.Conn 包装) |
| `mux.go` | yamux 客户端包装 |
| `multistream.go` | 双版本 multistream 协议协商（旧版优先） |
| `circuitpb.go` | circuit v2 protobuf 手工编解码 (Hop/Stop/Reservation/Limit) |
| `circuitv1.go` | circuit v1 protobuf 手工编解码 (CircuitRelay) |
| `varint.go` | varint 编解码 |
| `base58.go` | base58 编解码 (PeerID ↔ string) |
| `cmd/demo.go` | CLI 演示入口 |
| `relayhub_test.go` | 单元测试 (12 tests) |

## 协议支持

| 协议 | 状态 |
|------|------|
| `/multistream/1.0.0` | ✅ 已实现 |
| `/multistream-select/1.0.0` | ✅ 已实现 |
| `/tls/1.0.0` | ✅ 已实现，live relay 验证通过 |
| `/noise` | ✅ 已实现 |
| `/yamux/1.0.0` | ✅ 已实现 |
| `/libp2p/circuit/relay/0.2.0/hop` | ✅ 已实现（中继不支持时回退 v1） |
| `/libp2p/circuit/relay/0.2.0/stop` | ✅ 已实现 |
| `/libp2p/circuit/relay/0.1.0` | ✅ 已实现（v2 不可用时自动回退） |

## 安全传输自动协商

`Connect()` 自动协商顺序：
1. 先尝试 `/noise`
2. 失败（协议不可用）→ 回退到 `/tls/1.0.0`

## 关键实现细节

### TLS 证书格式 (go-libp2p 兼容)

取自 `go-libp2p@v0.36.2/p2p/security/tls/crypto.go`：

- **证书密钥**: 临时 ECDSA P-256
- **自签名**: 100 年有效期
- **扩展 OID**: `1.3.6.1.4.1.53594.1.1`
- **Critical**: `false`
- **扩展值**: ASN.1 DER of `signedKey{PubKey, Signature}`:
  - `PubKey` = protobuf 编码的 Ed25519 公钥: `08 01 12 20 <32 bytes>`
  - `Signature` = Ed25519 签名于 `"libp2p-tls-handshake:" + PKIX(certPubKey)`
- **ALPN**: `NextProtos: ["libp2p"]`

### Multistream-Select 版本

旧版中继用 `/multistream/1.0.0`（先尝试），新版用 `/multistream-select/1.0.0`。

### Circuit Relay v1 protobuf

```
message CircuitRelay {
  enum Type { HOP=1; STOP=2; STATUS=3; CAN_HOP=4 }
  message Peer { required bytes id=1; repeated bytes addrs=2 }
  optional Type type=1; optional Peer srcPeer=2;
  optional Peer dstPeer=3; optional Status code=4;
}
```

## Live Relay 测试记录

| 日期 | 中继地址 | 链路 | 结果 |
|------|---------|------|------|
| 2026-05-20 | `45.32.194.49:4001` | TCP → MS → TLS → yamux | TLS 握手成功，yamux 会话建立 |
| 2026-05-20 | `45.32.194.49:4001` | + circuit v1 HOP | v1 协商成功，中继返回 HOP_CANT_SPEAK_RELAY（目标 peer 不可达） |
| 2026-05-20 | `45.32.194.49:4001` | + circuit v2 HOP | v2 不可用 → 自动回退到 v1 |
| 2026-05-20 | `104.131.131.82:4001` | TCP → MS → TLS | 仅支持 secio，TLS 不可用 |
| 2026-05-20 | `65.108.43.63:4001` | TCP 连接 | 无响应/超时 |

## 测试

```bash
go test ./... -v -count=1    # 12 tests, all pass
go vet ./...
go build ./...
```

## 依赖

- `github.com/flynn/noise v1.1.0` — Noise 协议
- `github.com/hashicorp/yamux v0.1.2` — 流多路复用
- `golang.org/x/crypto` — curve25519
- `github.com/envsh/toxera/fedkey` — 本地密钥派生 (replace)

## 下一步

- 确保目标 peer 在线并连接到同一中继，以完成端到端 circuit relay 测试
- 寻找支持 circuit relay v2 的公共中继
