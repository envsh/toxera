package p2put

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	discovery2 "github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/multiformats/go-multiaddr"
)

var bootres *Libp2pBootResult

//////////////

type Event struct {
	Type  string
	Topic string
	Value any
}

var (
	rawChan       chan any
	clients       map[chan Event]struct{}
	clientsMu     sync.RWMutex
	clientTopics  map[chan Event][]string
	topicSubs     sync.Map // map[string]*pubsub.Topic
	discoveryTags sync.Map // set[string]
)

func init() {
	rawChan = make(chan any, 100)
	clients = make(map[chan Event]struct{})
	clientTopics = make(map[chan Event][]string)
	go broadcastLoop()
	discoveryTags.Store("libp2p-bootstrap-test", struct{}{})
}

func AddDiscoveryTag(tag string) {
	discoveryTags.Store(tag, struct{}{})
}

func RemoveDiscoveryTag(tag string) {
	discoveryTags.Delete(tag)
}

func broadcastLoop() {
	for raw := range rawChan {
		evt := Event{
			Type:  reflect.TypeOf(raw).String(),
			Value: raw,
		}
		clientsMu.RLock()
		for ch := range clients {
			select {
			case ch <- evt:
			default:
			}
		}
		clientsMu.RUnlock()
	}
}//

func hasTopic(topics []string, topic string) bool {
	for _, t := range topics {
		if t == topic {
			return true
		}
	}
	return false
}

func getOrSubscribeTopic(topic string) (*pubsub.Topic, error) {
	if bootres == nil || bootres.PSO == nil {
		return nil, fmt.Errorf("pso not ready")
	}
	if val, ok := topicSubs.Load(topic); ok {
		return val.(*pubsub.Topic), nil
	}

	t, err := bootres.PSO.Join(topic)
	if err != nil {
		if val, ok := topicSubs.Load(topic); ok {
			return val.(*pubsub.Topic), nil
		}
		return nil, err
	}

	topicSubs.Store(topic, t)

	sub, err := t.Subscribe()
	if err != nil {
		topicSubs.Delete(topic)
		return nil, err
	}
	go topicListener(sub, topic)
	return t, nil
}

func substr(s string, maxRunes int) string {
    runes := []rune(s)
    if len(runes) > maxRunes {
        runes = runes[:maxRunes]
    }
    return string(runes)
}

func topicListener(sub *pubsub.Subscription, topic string) {
	ctx := context.Background()
	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return
		}
		isme := msg.ReceivedFrom == bootres.PeerID
		log.Println("<< submsg", isme, msg.ReceivedFrom.ShortString(), topic, len(msg.Data), substr(string(msg.Data), 48))
		evt := Event{Type: "pubsub", Topic: topic, Value: msg}
		clientsMu.RLock()
		for ch, topics := range clientTopics {
			if hasTopic(topics, topic) {
				select {
				case ch <- evt:
				default:
				}
			}
		}
		clientsMu.RUnlock()
	}
}

const maxPublishSize = 1 << 20 // 1MB, matches DefaultMaxMessageSize

func UnsubscribeTopic(topic string) error {
	if bootres == nil || bootres.PSO == nil {
		return fmt.Errorf("pso not ready")
	}
	val, ok := topicSubs.Load(topic)
	if !ok {
		return fmt.Errorf("topic %s not subscribed", topic)
	}
	t := val.(*pubsub.Topic)
	if err := t.Close(); err != nil {
		return err
	}
	topicSubs.Delete(topic)
	log.Printf("[pso] unsubscribed: %s", topic)
	return nil
}

func PublishTopic(topic string, data []byte) error {
	t, err := getOrSubscribeTopic(topic)
	if err != nil {
		return err
	}
	log.Printf("[pso] subscribe topic=%q, peers=%d", topic, len(bootres.PSO.ListPeers(topic)))
	if len(data) > maxPublishSize {
		return fmt.Errorf("payload too large: %d bytes, max %d", len(data), maxPublishSize)
	}
	err = t.Publish(context.Background(), data)
	if err == nil && len(bootres.PSO.ListPeers(topic)) == 0 {
		return fmt.Errorf("no pso.ListPeers for %v", topic)
	}
	return err
}

type BoardResp struct {
	PeerID    string         `json:"peer_id"`
	Pubkey    string         `json:"pubkey"`
	NATStatus string         `json:"nat_status"`
	Relays0   int            `json:"relays0"`
	Relays1   int            `json:"relays1"`
	Conns     int            `json:"connections"`
	Addrs     int            `json:"listening_addrs"`
	Bandwidth *BandwidthResp `json:"bandwidth"`
	Resources *ResourcesResp `json:"resources,omitempty"`
}

type ResourcesResp struct {
	System    ScopeStatResp `json:"system"`
	Transient ScopeStatResp `json:"transient"`
}

type ScopeStatResp struct {
	StreamsIn  int   `json:"streams_in"`
	StreamsOut int   `json:"streams_out"`
	ConnsIn    int   `json:"connections_in"`
	ConnsOut   int   `json:"connections_out"`
	FD         int   `json:"fd"`
	Memory     int64 `json:"memory_bytes"`
}

type BandwidthResp struct {
	TotalIn  int64   `json:"total_in_bytes"`
	TotalOut int64   `json:"total_out_bytes"`
	RateIn   float64 `json:"rate_in"`
	RateOut  float64 `json:"rate_out"`
}

type RelayResp struct {
	Candidates []string `json:"candidates"`
	Connected  []string `json:"connected"`
}

type AddrResp struct {
	Addr  string `json:"addr"`
	Relay bool   `json:"is_relay"`
	Priv  bool   `json:"is_private"`
}

type ConnResp struct {
	PeerID      string   `json:"peer_id"`
	Addr        string   `json:"addr"`
	Direction   string   `json:"direction"`
	IsRelay     bool     `json:"is_relay"`
	RelayPeer   string   `json:"relay_peer,omitempty"`
	DirectAddrs []string `json:"direct_addrs,omitempty"`
}

type DHTResp struct {
	Size   int      `json:"size"`
	Peers  []string `json:"peers"`
	Topics []string `json:"topics"`
}

type StorePeerEntry struct {
	PeerID string   `json:"peer_id"`
	Addrs  []string `json:"addrs"`
}

type TopicEntry struct {
	Topic      string   `json:"topic"`
	Peers      []string `json:"peers"`
	Subscribed bool     `json:"subscribed"`
	IsTag      bool     `json:"is_tag"`
}

type NoopValidator struct {}
func (NoopValidator) Validate(key string, value []byte) error { return nil }
func (NoopValidator) Select(key string, values [][]byte) (int, error) {
	return len(values)-1, nil
}

type FoundPeer struct {
	PeerID string   `json:"peer_id"`
	Addrs  []string `json:"addrs"`
}

func FindPeers(tag string, limit int) ([]FoundPeer, error) {
	if tag == "" {
		tag = currConfig.HubName
	}
	if limit <= 0 {
		limit = 5
	}
	if bootres == nil || bootres.Discovery == nil {
		return nil, fmt.Errorf("discovery not ready")
	}
	findCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	peerChan, err := bootres.Discovery.FindPeers(findCtx, tag, discovery2.Limit(limit))
	if err != nil {
		return nil, err
	}
	var out []FoundPeer
	for p := range peerChan {
		if p.ID == bootres.PeerID || p.ID == "" {
			continue
		}
		addrs := make([]string, len(p.Addrs))
		for i, a := range p.Addrs {
			addrs[i] = a.String()
		}
		out = append(out, FoundPeer{PeerID: p.ID.String(), Addrs: addrs})
	}
	if out == nil {
		out = []FoundPeer{}
	}
	return out, nil
}

func toPeerID(v any) (peer.ID, error) {
	switch p := v.(type) {
	case peer.ID:
		return p, nil
	case string:
		return peer.Decode(p)
	default:
		return "", fmt.Errorf("expected peer.ID or string, got %T", v)
	}
}

func IsPeerInTopic(pid any, topic string) bool {
	p, err := toPeerID(pid)
	if err != nil {
		return false
	}
	if bootres == nil || bootres.PSO == nil {
		return false
	}
	for _, q := range bootres.PSO.ListPeers(topic) {
		if q == p {
			return true
		}
	}
	return false
}

func IsPeerInAnyTopic(pid any) bool {
	p, err := toPeerID(pid)
	if err != nil {
		return false
	}
	if bootres == nil || bootres.PSO == nil {
		return false
	}
	for _, topic := range bootres.PSO.GetTopics() {
		for _, q := range bootres.PSO.ListPeers(topic) {
			if q == p {
				return true
			}
		}
	}
	return false
}

func IsPeerConnected(pid any) bool {
	p, err := toPeerID(pid)
	if err != nil {
		return false
	}
	if bootres == nil || bootres.Host == nil {
		return false
	}
	for _, c := range bootres.Host.Network().Conns() {
		if c.RemotePeer() == p {
			return true
		}
	}
	return false
}

func IsPeerInStore(pid any) bool {
	p, err := toPeerID(pid)
	if err != nil {
		return false
	}
	if bootres == nil || bootres.Host == nil {
		return false
	}
	for _, q := range bootres.Host.Peerstore().Peers() {
		if q == p {
			return true
		}
	}
	return false
}

func FindPeer(pid any) (FoundPeer, error) {
	p, err := toPeerID(pid)
	if err != nil {
		return FoundPeer{}, err
	}
	if bootres == nil || bootres.DHT == nil {
		return FoundPeer{}, fmt.Errorf("dht not ready")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	info, err := bootres.DHT.FindPeer(ctx, p)
	if err != nil {
		return FoundPeer{}, err
	}
	addrs := make([]string, len(info.Addrs))
	for i, a := range info.Addrs {
		addrs[i] = a.String()
	}
	return FoundPeer{PeerID: info.ID.String(), Addrs: addrs}, nil
}

func PutKV(ctx context.Context, key string, value []byte) error {
	if bootres == nil || bootres.Host == nil || bootres.DHT == nil {
		return fmt.Errorf("libp2p not ready")
	}

	// not support put custom key, opendht does
	// {"error":"create temp dht: protocol prefix /ipfs must have exactly two namespaced validators - /pk and /ipns"}
	tempDHT, err := dht.New(ctx, bootres.Host, dht.Mode(dht.ModeClient),
		// dht.ProtocolPrefix("/mychat"),
		// dht.Validator(record.NamespacedValidator{
		// 	"kv": NoopValidator{},
		// 	"pk": record.PublicKeyValidator{},
		// 	"ipns": ipns.PublicKeyValidator{},
		// })
	)
	if err != nil {
		return fmt.Errorf("create temp dht: %w", err)
	}
	defer tempDHT.Close()

	_ = tempDHT.Bootstrap(ctx)

	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	for {
		if tempDHT.RoutingTable().Size() >= 3 {
			break
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("routing table too small: %d, need >= 3", tempDHT.RoutingTable().Size())
		case <-time.After(500 * time.Millisecond):
		}
	}

	putCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// mh, _ := multihash.Sum([]byte(key), multihash.SHA2_256, -1)
	// key = "/ipns/"+key // pk
	key2 := "/pk/"+key
	println(key2)
	if err := tempDHT.PutValue(putCtx, key2, value); err != nil {
		return fmt.Errorf("put value: %w", err)
	}

	getCtx, cancel2 := context.WithTimeout(ctx, 15*time.Second)
	defer cancel2()
	if _, err := bootres.DHT.GetValue(getCtx, key2); err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}

	return nil
}

func GetKV(ctx context.Context, key string) ([]byte, error) {
	if bootres == nil || bootres.DHT == nil {
		return nil, fmt.Errorf("libp2p not ready")
	}

	getCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	val, err := bootres.DHT.GetValue(getCtx, key)
	if err != nil {
		return nil, err
	}
	if len(val) == 0 {
		return nil, routing.ErrNotFound
	}
	return val, nil
}

func DelKV(ctx context.Context, key string) error {
	if bootres == nil || bootres.Host == nil || bootres.DHT == nil {
		return fmt.Errorf("libp2p not ready")
	}

	putCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := bootres.DHT.PutValue(putCtx, key, []byte{}); err != nil {
		return fmt.Errorf("del value: %w", err)
	}
	return nil
}

func CollectBoard() (BoardResp, error) {
	if bootres == nil || bootres.Host == nil {
		return BoardResp{}, fmt.Errorf("libp2p not ready")
	}
	h := bootres.Host

	var addrs []AddrResp
	for _, a := range h.Addrs() {
		addrs = append(addrs, AddrResp{
			Addr:  a.String(),
			Relay: isRelayAddr(a),
			Priv:  isPrivateIP(extractIPFromAddr(a)),
		})
	}

	conns, _ := CollectConns()
	relays, _ := CollectRelays()

	var bw *BandwidthResp
	if bootres.Bwc != nil {
		s := bootres.Bwc.GetBandwidthTotals()
		bw = &BandwidthResp{
			TotalIn:  s.TotalIn,
			TotalOut: s.TotalOut,
			RateIn:   s.RateIn,
			RateOut:  s.RateOut,
		}
	}

	var res *ResourcesResp
	if rm := h.Network().ResourceManager(); rm != nil {
		var sys, trans ScopeStatResp
		rm.ViewSystem(func(s network.ResourceScope) error {
			st := s.Stat()
			sys = ScopeStatResp{
				StreamsIn:  st.NumStreamsInbound,
				StreamsOut: st.NumStreamsOutbound,
				ConnsIn:    st.NumConnsInbound,
				ConnsOut:   st.NumConnsOutbound,
				FD:         st.NumFD,
				Memory:     st.Memory,
			}
			return nil
		})
		rm.ViewTransient(func(s network.ResourceScope) error {
			st := s.Stat()
			trans = ScopeStatResp{
				StreamsIn:  st.NumStreamsInbound,
				StreamsOut: st.NumStreamsOutbound,
				ConnsIn:    st.NumConnsInbound,
				ConnsOut:   st.NumConnsOutbound,
				FD:         st.NumFD,
				Memory:     st.Memory,
			}
			return nil
		})
		res = &ResourcesResp{System: sys, Transient: trans}
	}

	return BoardResp{
		PeerID:    h.ID().String(),
		Pubkey:    bootres.PubkeyHex,
		NATStatus: bootres.NATStatus.String(),
		Relays0:    len(relays.Candidates),
		Relays1:    len(relays.Connected),
		Conns:     len(conns),
		Addrs:     len(addrs),
		Bandwidth: bw,
		Resources: res,
	}, nil
}

func CollectConns() ([]ConnResp, error) {
	if bootres == nil || bootres.Host == nil {
		return nil, fmt.Errorf("libp2p not ready")
	}
	var out []ConnResp
	for _, c := range bootres.Host.Network().Conns() {
		if isBootstrapPeer(c.RemotePeer()) {
			continue
		}
		dir := "outbound"
		if c.Stat().Direction == network.DirInbound {
			dir = "inbound"
		}
		entry := ConnResp{
			PeerID:    c.RemotePeer().String(),
			Addr:      c.RemoteMultiaddr().String(),
			Direction: dir,
		}
		if c.Stat().Limited {
			entry.IsRelay = true
			if rpid, err := extractRelayPeerID(c.RemoteMultiaddr()); err == nil {
				entry.RelayPeer = rpid.String()
			}
			for _, a := range bootres.Host.Peerstore().Addrs(c.RemotePeer()) {
				if !isRelayAddr(a) {
					entry.DirectAddrs = append(entry.DirectAddrs, a.String())
				}
			}
			if entry.DirectAddrs == nil {
				entry.DirectAddrs = []string{}
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

func CollectDHT() (DHTResp, error) {
	if bootres == nil || bootres.Host == nil {
		return DHTResp{}, fmt.Errorf("libp2p not ready")
	}
	if bootres.DHT == nil {
		return DHTResp{}, nil
	}
	rt := bootres.DHT.RoutingTable()
	peers := rt.ListPeers()
	strs := make([]string, len(peers))
	for i, p := range peers {
		strs[i] = p.String()
	}

	topics := bootres.PSO.GetTopics()
	log.Println(topics)

	return DHTResp{
		Size:  rt.Size(),
		Peers: strs,
		Topics: topics,
	}, nil
}

func CollectRelays() (RelayResp, error) {
	if bootres == nil || bootres.Host == nil {
		return RelayResp{}, fmt.Errorf("libp2p not ready")
	}
	h := bootres.Host

	var candidates []string
	candidatePeers := make(map[peer.ID]struct{})
	for _, a := range h.Addrs() {
		if !isRelayAddr(a) {
			continue
		}
		addrStr := a.String()
		candidates = append(candidates, addrStr)

		trimmed := strings.TrimSuffix(addrStr, "/p2p-circuit")
		ma, err := multiaddr.NewMultiaddr(trimmed)
		if err != nil {
			continue
		}
		pidStr, err := ma.ValueForProtocol(multiaddr.P_P2P)
		if err != nil {
			continue
		}
		pid, err := peer.Decode(pidStr)
		if err != nil {
			continue
		}
		candidatePeers[pid] = struct{}{}
	}

	var connected []string
	for _, c := range h.Network().Conns() {
		if _, ok := candidatePeers[c.RemotePeer()]; ok {
			connected = append(connected, c.RemoteMultiaddr().String()+"/p2p/"+c.RemotePeer().String())
		}
	}

	if candidates == nil {
		candidates = []string{}
	}
	if connected == nil {
		connected = []string{}
	}

	return RelayResp{
		Candidates: candidates,
		Connected:  connected,
	}, nil
}

func CollectStorePeers() []StorePeerEntry {
	if bootres == nil || bootres.Host == nil {
		return nil
	}
	ps := bootres.Host.Peerstore()
	var out []StorePeerEntry
	for _, p := range ps.Peers() {
		addrs := ps.Addrs(p)
		if len(addrs) == 0 {
			continue
		}
		var as []string
		for _, a := range addrs {
			s := a.String()
			if strings.Contains(s, "/ip6/") ||
				strings.Contains(s, "/udp/") ||
				strings.Contains(s, "/quic") ||
				strings.Contains(s, "webrtc") ||
				strings.Contains(s, "/dns/") {
				continue
			}
			as = append(as, s)
		}
		if len(as) == 0 {
			continue
		}
		out = append(out, StorePeerEntry{
			PeerID: p.String(),
			Addrs:  as,
		})
	}
	if out == nil {
		out = []StorePeerEntry{}
	}
	return out
}

func CollectTopics() []TopicEntry {
	if bootres == nil || bootres.Host == nil || bootres.PSO == nil {
		return []TopicEntry{}
	}
	seen := make(map[string]*TopicEntry)
	for _, t := range bootres.PSO.GetTopics() {
		seen[t] = &TopicEntry{Topic: t}
	}
	topicSubs.Range(func(key, val any) bool {
		t := key.(string)
		topic := val.(*pubsub.Topic)
		if _, ok := seen[t]; !ok {
			seen[t] = &TopicEntry{Topic: t}
		}
		seen[t].Subscribed = true
		for _, p := range topic.ListPeers() {
			seen[t].Peers = append(seen[t].Peers, p.String())
		}
		return true
	})
	discoveryTags.Range(func(key, _ any) bool {
		t := key.(string)
		if _, ok := seen[t]; !ok {
			seen[t] = &TopicEntry{Topic: t}
		}
		seen[t].IsTag = true
		return true
	})
	out := make([]TopicEntry, 0, len(seen))
	for _, v := range seen {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Topic < out[j].Topic
	})
	return out
}
