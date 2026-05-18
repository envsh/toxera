package p2put

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"strings"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
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
	topicSubs     sync.Map // map[string]*pubsub.Subscription
)

func init() {
	rawChan = make(chan any, 100)
	clients = make(map[chan Event]struct{})
	clientTopics = make(map[chan Event][]string)
	go broadcastLoop()
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

func getOrSubscribeTopic(topic string) error {
	if bootres == nil {
		log.Printf("[pso] bootres is nil")
		return fmt.Errorf("bootres nil")
	}
	if bootres.PSO == nil {
		log.Printf("[pso] PSO is nil")
		return fmt.Errorf("pso not ready")
	}
	for _, t := range bootres.PSO.GetTopics() {
		if t == topic {
			log.Printf("[pso] already subscribed: %s", topic)
			return nil
		}
	}
	log.Printf("[pso] subscribing to: %s", topic)
	sub, err := bootres.PSO.Subscribe(topic)
	if err != nil {
		log.Printf("[pso] subscribe error: %v", err)
		return err
	}
	topicSubs.Store(topic, sub)
	go topicListener(sub, topic)
	log.Printf("[pso] subscribed: %s, GetTopics now: %v", topic, bootres.PSO.GetTopics())
	return nil
}

func topicListener(sub *pubsub.Subscription, topic string) {
	ctx := context.Background()
	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			topicSubs.Delete(topic)
			return
		}
		evt := Event{Type: "pubsub", Topic: topic, Value: string(msg.Data)}
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
	PeerID    string `json:"peer_id"`
	Addr      string `json:"addr"`
	Direction string `json:"direction"`
}

type DHTResp struct {
	Size  int      `json:"size"`
	Peers []string `json:"peers"`
	Topics []string `json:"topics"`
}


type NoopValidator struct {}
func (NoopValidator) Validate(key string, value []byte) error { return nil }
func (NoopValidator) Select(key string, values [][]byte) (int, error) {
	return len(values)-1, nil
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
		dir := "outbound"
		if c.Stat().Direction == network.DirInbound {
			dir = "inbound"
		}
		out = append(out, ConnResp{
			PeerID:    c.RemotePeer().String(),
			Addr:      c.RemoteMultiaddr().String(),
			Direction: dir,
		})
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
