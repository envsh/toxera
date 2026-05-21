relays:

34.59.243.77:4001 — Circuit v2 hop OK

141.95.145.190:4001

45.63.61.139:4001


139.59.119.94:4001

104.131.131.82:4001 96s disconnect

建议的补全顺序
1. 
Limit 强制执行 — 在 RelayedConn 读写时计数，超限时报错
2. 
Identify 补全 signedPeerRecord — 添加 field 8（签名路由记录）
3. 
Stream 超时 — 给所有 protobuf IO 加 1min 超时
4. 
最大消息大小 — readOnePb 加 4096 上限
5. 
Reservation 地址 — 解析 addrs、voucher 并暴露
6. 
AutoNAT responder — 简单拒绝即可，让 relay 知道我们不支持
7. 
DCUtR responder — 返回拒绝/未实现
8. 
Kademlia responder — 返回拒绝/未实现
是否按这个优先级逐个实施？

轮次	文件	改动
Round 1	relay.go	readOnePb 加 4096 限制 + stream I/O 超时 (P0 #2-3)
Round 2	relay.go, circuitpb.go	Identify 补全 field 7+8 (P0 #1)
Round 3	relay.go	RelayedConn Limit 强制执行 (P1 #4) + Reservation addrs 暴露 (P1 #5)
Round 4	relay.go	AutoNAT / DCUtR / Kademlia responder (P2 #6-8)


8. P2 — Kademlia 拒绝回复（relay.go handleIncoming）
当前 /ipfs/kad/1.0.0 只 log+忽略，不回复。go-libp2p 的 DHT 请求会等待回复。
- 
读取 protobuf 消息后回复空的 Kademlia protobuf 或直接关闭 stream
- 
最简单：readOnePb + 忽略，不发送回复（relay 超时后放弃）
9. P3 — ping 改进（relay.go:627）
当前 handlePing 用 io.ReadFull 读 32 字节，但 ping 消息不是固定长度。应改为：
- 
先读取 protobuf varint length-prefixed 数据
- 
回复相同内容
但当前实现似乎对 kubo 有效（handlePing 被正确调用），可暂不改。


