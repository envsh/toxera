# relayhub — libp2p Circuit Relay 纯 Go 实现

## Goal
纯 Go 实现 libp2p Circuit Relay 客户端（无 libp2p 依赖），连接公共中继并通过中继路由数据到目标 peer，持续保持连接运行。

## Constraints & Preferences
- 核心协议（multistream、protobuf、base58）手工实现，零外部依赖
- PeerID 由 `fedkey.KeyRing` 种子派生
- 必须使用公共中继，不自建
- 必须通过 live relay 测试验证
- 不自动重连，优先从保活和协议层面保持连接

## Progress
### Done
- relayhub 完整实现：RelayClient (Connect/Reserve/RefreshReservation/AcceptRelay/ConnectThroughRelay)、安全传输 (Noise/TLS 自动协商)、yamux 会话、Circuit v2 HOP/STOP、v1 回退
- `detect.go` 新增：`DetectRelay()` 导出函数、`DetectResult` 和 `IdentifyInfo` 结构体
- `cmd/detect` 简化：748 行 → 204 行，核心调用 `relayhub.DetectRelay(ctx, a, priv)`
- `cmd/scanrelay` 简化：313 行 → 162 行，复用 `DetectRelay`，删除重复 protobuf/varint/yamux 代码
- 保活增强：mux.go yamux KeepAliveInterval 30s→10s；relay.go/tls.go TCP SetKeepAlive+SetKeepAlivePeriod(15s)；session CloseChan 监听日志
- cmd/peer/main.go：Reserve 改为同步调用，每 5min 定时 RefreshReservation()，可配 -relay 参数
- 12 个单元测试全部通过，go build/vet 无问题
- **Round 1 (P0)**: `readOnePb` 加 4096 上限；所有 relay 协议 stream（Reserve/RefreshReservation/connectV2Hop/connectV1Hop）统一设 `SetDeadline(60s)`
- **Round 2 (P0)**: Identify 响应补全 field 8 signed peer record（Envelope + PeerRecord protobuf, ed25519 签名）；`circuitpb.go` 新增 `encodeAddressInfo`/`encodePeerRecord`/`encodeEnvelope`；`detect.go` `parseIdentify` 加 `case 8` 捕获

### In Progress
- *(none)*

### Blocked
- 公共中继 `104.131.131.82:4001`（kubo/0.32.1）约 96 秒后主动 EOF 断开连接，即使 yamux keepalive 10s + TCP keepalive 15s + 每 5min refresh reservation 也无法阻止。需换中继测试。

## Implementation Architecture

```
TCP 连接
  ↓ Multistream-Select 版本协商 (/multistream/1.0.0)
  ↓ 安全传输 (TLS 1.3 / Noise XX)，自动协商：noise → TLS 回退
  ↓ Multistream-Select yamux 协商
  ↓ Yamux 会话
  ├── Circuit v2 HOP (CONNECT)
  ├── Circuit v1 HOP (v2 不可用时回退)
  ├── Circuit v2 RESERVE (等待 STOP)
  └── /ipfs/id/1.0.0 协议处理
```

## File Structure

| 文件 | 职责 |
|------|------|
| `relay.go` | `RelayClient`、`RelayedConn`、Connect/Reserve/RefreshReservation/ConnectThroughRelay/AcceptRelay |
| `detect.go` | `DetectRelay()` 导出函数、`DetectResult`、`IdentifyInfo`、`parseIdentify` |
| `tls.go` | go-libp2p 兼容的 TLS 1.3 证书生成 + `ConnectTLS()` |
| `noise.go` | Noise XX 握手 + noiseConn (net.Conn 包装) |
| `mux.go` | yamux 客户端包装 (KeepAliveInterval=10s) |
| `multistream.go` | 双版本 multistream 协议协商 + MSRespond 服务端 |
| `circuitpb.go` | circuit v2/v1 protobuf 手工编解码 + PeerRecord/Envelope 编码 |
| `circuitv1.go` | circuit v1 protobuf 手工编解码 (CircuitRelay) |
| `varint.go` | varint 编解码 |
| `base58.go` | base58 编解码 (PeerID ↔ string) |
| `relayhub_test.go` | 单元测试 (12 tests) |
| `cmd/peer/main.go` | 演示 peer 入口，连接 relay + reserve + 保活 |
| `cmd/detect/main.go` | 204 行，单中继探测 |
| `cmd/scanrelay/main.go` | 162 行，批量中继扫描 |
| `cmd/source/main.go` | 中继源聚合 |

## Protocol Support

| 协议 | 状态 |
|------|------|
| `/multistream/1.0.0` | ✅ 已实现 |
| `/multistream-select/1.0.0` | ✅ 已实现 |
| `/tls/1.0.0` | ✅ 已实现，live relay 验证通过 |
| `/noise` | ✅ 已实现 |
| `/yamux/1.0.0` | ✅ 已实现 |
| `/libp2p/circuit/relay/0.2.0/hop` | ✅ 已实现（含 RESERVE + CONNECT） |
| `/libp2p/circuit/relay/0.2.0/stop` | ✅ 已实现 |
| `/libp2p/circuit/relay/0.1.0` | ✅ 已实现（v2 不可用时自动回退） |
| `/ipfs/id/1.0.0` | ✅ 已实现（含 field 8 signed peer record） |
| `/ipfs/id/push/1.0.0` | ✅ 已实现（读取并 log 忽略） |
| `/ipfs/ping/1.0.0` | ✅ 已实现（echo responder） |

## Key Implementation Details

### Identify 响应 (field 8 signed peer record)

`buildIdentifyResponse()` 构造 signed Envelope 放入 field 8：
- `payload_type`: `0x81 0x06`（multicodec peer-record 0x0301 的 varint）
- `payload`: 序列化 `PeerRecord{seq, AddressInfo{id=PeerID}}`（addrs 为空列表）
- `signature`: `ed25519.Sign(key, "libp2p-envelope" + pubKey + payloadType + payload)`

### 安全传输自动协商

`Connect()` 自动协商顺序：
1. 先尝试 `/noise`（当前使用 noiseConn 而非噪声下的 yamux，需注意）
2. 失败（协议不可用）→ 回退到 `/tls/1.0.0`

### Stream I/O 安全

- `readOnePb` 限制最大消息 4096 bytes（防 DOS）
- 所有 relay 协议 stream（Reserve/RefreshReservation/connectV2Hop/connectV1Hop）统一 `SetDeadline(60s)`

## Identity 检测 (DetectRelay)

`DetectRelay()` 返回 `*DetectResult`：

| 字段 | 含义 |
|------|------|
| `TCPOK` / `TCPDuration` | TCP 连接状态 / 耗时 |
| `TLSOK` | TLS 握手成功 |
| `YamuxOK` | yamux 会话建立 |
| `IdentifyOK` / `Identify` | 中继 `/ipfs/id/1.0.0` 响应 |
| `V1OK` / `V1Code` / `V1Status` | Circuit v1 CAN_HOP 探测 |
| `V2HopOK` / `V2Status` / `V2Expire` | Circuit v2 RESERVE 探测 |
| `V2ConnectOK` / `V2ConnectStatus` / `V2ConnectDuration` | Circuit v2 CONNECT 回环 |
| `V2StopOK` | Circuit v2 STOP 协议可用 |

## Live Relay Test Records

| 日期 | 中继地址 | 链路 | 结果 |
|------|---------|------|------|
| 2026-05-20 | `45.32.194.49:4001` | TCP → MS → TLS → yamux | TLS 握手成功，yamux 会话建立 |
| 2026-05-20 | `45.32.194.49:4001` | + circuit v1 HOP | v1 协商成功，中继返回 HOP_CANT_SPEAK_RELAY |
| 2026-05-20 | `45.32.194.49:4001` | + circuit v2 HOP | v2 不可用 → 自动回退 v1 |
| 2026-05-20 | `104.131.131.82:4001` | TCP → MS → secio | 仅支持 secio，TLS/Noise 均不可用 |
| 2026-05-20 | `65.108.43.63:4001` | TCP 连接 | 无响应/超时 |
| 2026-05-21 | `104.131.131.82:4001` | TCP → MS → Noise → yamux → v2 HOP | Reserve OK (expire=120s, limit 128KB), ~96s 后被 relay EOF 断开 |

## Testing

```bash
go test ./... -v -count=1    # 12 tests, all pass
go vet ./...
go build ./...
```

## Dependencies

- `github.com/flynn/noise v1.1.0` — Noise 协议
- `github.com/hashicorp/yamux v0.1.2` — 流多路复用
- `golang.org/x/crypto` — curve25519
- `github.com/envsh/toxera/fedkey` — 本地密钥派生 (replace)

## Next Steps

1. 换中继测试（如 `34.59.243.77:4001`，summary 记录 "Circuit v2 hop OK"）
2. 补充缺失子协议：
   - Circuit v2 Reservation Voucher（签名验证，HopMessage.Reservation.Voucher）
   - Circuit v2 Limit 执行（客户端侧强制 duration/data 上限）
   - DCUtR（打洞升级）
   - AutoNAT（NAT 类型探测）
   - Kademlia DHT responder
3. 在 `RelayedConn` 中实现 Limit 计数器
