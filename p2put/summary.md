# p2put — libp2p 带宽优化总结

## Goal
优化 go-toxcore/p2put (libp2p v0.36.2) 节点带宽 + 电池消耗，目标覆盖桌面和手机两种场景。

## Constraints & Preferences
- 所有节点 behind NAT；直接 TCP 不可能无 HolePunching
- 必须保持 Pub/Sub 收发能力
- 单 seed identity（`key.txt` → fedkey → Ed25519 → libp2p）
- `go-libp2p-kad-dht` v0.26.0，默认 `/ipfs` prefix（BucketSize=20 由 Validate() 强制）
- REST API on `:4004/p2pin/`
- **手机场景**：常驻后台 + 实时 Pub/Sub 收发，目标减少无线电唤醒

## Parameter Reference

### DHT Defaults (go-libp2p-kad-dht v0.26.0)
| 参数 | 默认值 | 说明 |
|---|---|---|
| BucketSize | 20 | `/ipfs` prefix 强制 |
| Concurrency | 10 | 并行查询数 |
| AutoRefresh | true | 自动刷新路由表 |
| RefreshInterval | 10min | 路由表刷新间隔 |

### GossipSub Defaults
| 参数 | 默认值 | 说明 |
|---|---|---|
| HeartbeatInterval | 1s | mesh 心跳间隔 |
| D | 6 | 期望 mesh 度 |
| Dlo | 4 | mesh 下限 |
| Dhi | 12 | mesh 上限 |
| Dlazy | 6 | 空闲时 gossip 目标数 |
| GossipFactor | 0.25 | IHAVE 发送比例 |
| HistoryLength | 5 | 消息历史窗口数 |
| HistoryGossip | 3 | 每个窗口 gossip 数 |
| DirectConnectTicks | 600 | ❗ 不能为 0，否则除零 panic |

## Changes Made

### 文件: `config.go`

| 改动 | 行 | 桌面值 | 手机值 |
|---|---|---|---|
| `myGossipSubParams()` `HeartbeatInterval` | 98 | 10s | **60s** |
| `myGossipSubParams()` `D` | 93 | 3 | **2** |
| `myGossipSubParams()` `Dlo` | 94 | 2 | **1** |
| `myGossipSubParams()` `Dhi` | 95 | 4 | **3** |
| `myGossipSubParams()` `Dlazy` | 96 | 2 | **1** |
| `myGossipSubParams()` `GossipFactor` | 97 | 0.02 | **0.005** |
| `myGossipSubParams()` `HistoryLength` | 99 | 2 | **1** |
| `myGossipSubParams()` `HistoryGossip` | 100 | 1 | **0** |

### 文件: `libp2p_bs.go`

| 改动 | 行 | 桌面值 | 手机值 |
|---|---|---|---|
| HolePunching | 321 | ✅ 启用 | 同左 |
| AutoRelay `WithNumRelays` | 307 | 3 | **1** |
| DHT `ModeClient` | 381 | ✅ | 同左 |
| DHT `DisableAutoRefresh` | 383 | ✅ | 同左 |
| DHT `Concurrency` | 384 | 3 | **1** |
| DHT `RoutingTableRefreshPeriod` | 385 | 15min | 同左 |
| DHT bootstrap timeout | 378 | 32s | 同左 |
| `BandwidthReporter` | 326 | ✅ 启用 | **禁用** |
| `PeerScoreInspect` interval | 430 | 30s | **300s** |
| Discovery 循环间隔 | 454-456 | 3s+150s | **3s+300s** |
| `findAndConnect` 跳过阈值 | 502 | >9 | **>3** |
| `findAndConnect` 停止阈值 | 518 | >12 | **>5** |
| `findAndConnect` `Limit()` | 507 | 5 | **2** |
| `findAndConnect` 连接间延迟 | 521 | 3s | **5s** |

### 文件: `cmd/demo.go`

| 改动 | 说明 |
|---|---|
| 新增 `-mobile` flag | `cfg.IsMobile = true` 自动应用所有手机参数 |

## Current State

桌面稳态带宽实测 ~0 B/s（rate_in ≈ 0），GossipSub 控制消息 + yamux keepalive 合计 ~53 B/s。

手机参数应用后预期：
- 连接数 20+ → **3-5**
- Heartbeat 10s → **60s**（无线电唤醒减 6x）
- yamux keepalive 碰撞 ~1.5s → **~12s**（路由省 8x）
- IHAVE 闲置不发（Dlazy=1 + GossipFactor=0.005 → mesh 3 节点时 ≈ 0）

## Next Steps

1. 实现手机模式代码改动：
   - `config.go`: `myResourceManager()` 用 `cfg.IsMobile`；`myGossipSubParams()` 用 `cfg.IsMobile` 分支
   - `libp2p_bs.go`: `IsMobile` 分发到 DHT/AutoRelay/Discovery/BandwidthReporter/PeerScoreInspect
   - `cmd/demo.go`: `-mobile` flag
2. 测试桌面模式无退化
3. 测试手机模式连接数、带宽、预期唤醒频率
4. 可选：添加运行时 REST API `/p2pin/config` 支持在线切换部分参数

## 手机无线电路径

```
┌────────────────────────────────────┐
│  App 发消息                        │
│  → PublishTopic                    │
│    → getOrSubscribeTopic(Join+Sub) │
│      → GossipSub heartbeat 60s     │
│        → mesh: 3 peers             │
│          → 收消息                     │
└────────────────────────────────────┘
         ↓
┌────────────────────────────────────┐
│  连接管理                           │
│  myDiscoveryV3: 每 300s            │
│  → FindPeers(Limit=2)              │
│  → 连接数 >3 跳过, >5 停止           │
│  → 每 5s 连一个                       │
│  DHT: Client + Concurrency=1       │
│  AutoRelay: 1 relay                │
└────────────────────────────────────┘
         ↓
┌────────────────────────────────────┐
│  yamux keepalive × 3-5 连接        │
│  → 每 ~12s 一次合计无线电唤醒         │
│  → 突发 30s 内完成收发 → 无线电休眠    │
└────────────────────────────────────┘
```

## 运行时可调参数 vs. 创建时不可变

### 一创不可变（必须重启）

| 子系统 | 不可变参数 | 代码位置 |
|---|---|---|
| **GossipSub** | `HeartbeatInterval`, `D`, `Dlo`, `Dhi`, `Dlazy`, `GossipFactor`, `HistoryLength`, `HistoryGossip` 等全部 31 个 | `GossipSubRouter.params`（全 unexported，仅 `WithGossipSubParams()` 构造时设置） |
| **DHT** | `Concurrency`, `BucketSize`, `AutoRefresh`, `RefreshInterval`, `Mode`, `Resiliency`, `QueryPeerFilter` 等全部 | `IpfsDHT` struct（全 unexported，`Config.Apply()` 一次后回拷贝） |
| **AutoRelay** | `WithNumRelays`, `WithMinCandidates`, `WithMaxCandidates`, `bootDelay`, `backoff` | `relayFinder.conf` 永不 mutate |
| **BandwidthReporter** | 开关 / Reporter 实例 | `Swarm.bwc` unexported + no setter |
| **PeerScoreInspect** | 回调间隔 | `WithPeerScoreInspect()` 只构造时传一次 |
| **Swarm timeouts** | `dialTimeout`, `dialTimeoutLocal`, `dialRanker` 等 | `Swarm` struct unexported fields |
| **yamux keepalive** | `KeepAliveInterval` 30s/连接 | yamux session 创建时的配置，无法动态修改 |

### 可以运行时改

| 子系统 | 可调参数 | API | 文件:行 |
|---|---|---|---|
| **rcmgr 资源限流** | 任意 scope 的 Conns/Streams/Memory/FD 上限 | `ResourceScopeLimiter.SetLimit(Limit)` | `p2p/host/resource-manager/extapi.go:47` |
| **rcmgr allowlist** | IP/子网白名单 | `Allowlist.Add()` / `Remove()` | `allowlist.go:107` |
| **ConnectionGater** | 封禁/解禁 peer、IP、子网 | `BlockPeer/UnblockPeer/BlockAddr/BlockSubnet` | `p2p/net/conngater/conngater.go` |
| **ConnMgr** | peer 标签、保护、强制修剪 | `TagPeer/UntagPeer/UpsertTag/Protect/Unprotect/TrimOpenConns` | `p2p/net/connmgr/connmgr.go` |
| **地址过滤** | 哪些地址对外宣告 | `BasicHost.AddrsFactory`（public struct field） | `p2p/host/basic/basic_host.go:73` |
| **监听地址** | 运行时增减监听端口/传输 | `Swarm.Listen()` / `ListenClose()` | `p2p/net/swarm/swarm.go:417` |
| **协议处理器** | 注册/移除协议 handler | `SetStreamHandler` / `RemoveStreamHandler` | `basic_host.go` |
| **Dial 限速** | 全局并发 FD dials、per-peer 速率 | package vars: `ConcurrentFdDials`, `DefaultPerPeerRateLimit` | `p2p/net/swarm/swarm_dial.go:90` |
| **AutoNAT** | 替换 NAT 检测策略 | `BasicHost.SetAutoNat(autonat.AutoNAT)` | `basic_host.go:1039` |
| **地址变更信号** | 触发 NAT 重评估 | `BasicHost.SignalAddressChange()` | `basic_host.go:1014` |
| **PubSub Topic 评分** | 每个 topic 的评分参数 | `Topic.SetScoreParams(*TopicScoreParams)` | `go-libp2p-pubsub/topic.go:44` |
| **PubSub 黑名单** | 封禁 peer 消息 | `PubSub.BlacklistPeer(peer.ID)` | `pubsub.go:1388` |
| **PubSub 消息验证器** | 注册/注销 topic validator | `RegisterTopicValidator` / `UnregisterTopicValidator` | `pubsub.go:1399` |

### 运行时开关切换方案

对所有需要重启的参数，设计上只能是 `IsMobile` 启动时选择。但 rcmgr `SetLimit()` 可以做**运行时连接数急救**：

```go
// REST API: POST /p2pin/config
// body: {"mode": "mobile", "max_conns": 5}
func setMobileLimits(rcmgr network.ResourceManager) {
    rcmgr.ViewSystem(func(s network.ResourceScope) error {
        if sl, ok := s.(rcmgr.ResourceScopeLimiter); ok {
            sl.SetLimit(rcmgr.BaseLimit{
                Conns:         8,
                ConnsInbound:  4,
                ConnsOutbound: 4,
                Streams:       16,
                Memory:        64 << 20,
                FD:            64,
            })
        }
        return nil
    })
}
```

配合 `ConnMgr.TrimOpenConns()` 立即裁剪超标连接。这是**唯一不需要重启**就能减少连接数的路径。

### 为什么无法做成纯运行时切换

GossipSub/DHT/Relay 的设计哲学是 **configuration is immutable**——参数在 `New()` 时从 `Option` 拷贝到 struct 的 unexported 字段，之后没有任何 public setter。这是 libp2p 的架构选择，不是代码遗漏。

唯一例外是 `pubsub` 包的测试代码会通过 `PubSub.eval`（unexported channel）向事件循环提交闭包直接改 `GossipSubRouter.params.D`，但外部 package 做不到。

## Relevant Files

| 文件 | 职责 |
|---|---|
| `config.go` | Config struct, ResourceManager, GossipSubParams |
| `libp2p_bs.go` | Host creation, DHT/Relay/GossipSub setup, discovery findAndConnect |
| `utapi.go` | Event broadcast, topic sub/pub, PublishTopic |
| `restapi.go` | REST endpoints `/p2pin/` |
| `stable_peers.go` | Peer connection tracking/eviction |
| `multidns.go` | Static relay DNS resolution |
| `cmd/demo.go` | Main entry point |

## 能耗模型（LTE 手机）

| 事件 | 每次能耗 | 桌面频率 | 手机频率 |
|---|---|---|---|
| 无线电尾随 tail | ~200mJ/次 | 每 ~1.5s → ~1000 mJ/min | **每 ~12s → ~16 mJ/min** |
| GossipSub heartbeat | ~10 mJ/次 | 每 10s → ~60 mJ/min | **每 60s → ~10 mJ/min** |
| FindPeers 突发 | ~500 mJ/次 | 每 150s → ~200 mJ/min | **每 300s → ~1.6 mJ/min** |
| 预计总能耗 | | **~1260 mJ/min** | **~28 mJ/min** |
