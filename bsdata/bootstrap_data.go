package bsdata

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	_ "embed"
)

func init() {}

func load_data() {}

//go:embed bootstrap_data.toml
var data_toml []byte

//go:embed bootstrap.json
var data_full_json []byte

// from https://github.com/TokTok/qTox
var GroupBot = "648BF2EEE794E94444B848F8FC6AD3BA029C9BC2649BA761EF556DA17F549022A8D7596E7DBA"

// WIP maybe change !!!
// runby envsh/fedind https://github.com/envsh/fedind/releases/tag/cloudappfs
var EchoBots = []string{
	"BDC903530CA703EEFF078612835D150EE174BD4C3CEC682525AEF2816F20CB4E9F69B4D90E95",
	"3A7557F38C3CFCE1FDC94A7D186E9911A310D5ACFC0018B36F3C97B209021527128148DD0768",
	"83F090EAF802AFB7FCD21822111A05A9A1C713F97A5FBC9726AD60A116910A6519EC31AFB2A1",
	"6C759F9E015BA8E78FBCB0B9B82DCC4E530FF02DA40D41FF84A7F16C3206A947E41913184E6A",
	"8D6B5552B84A42443DAE9BA7E65E187259AAD09AD93FDEAC895818CD81F53F043A0099CF781A",
	"9A8FB4515BAD255AD1D5552A3F647C6447D7FE0CF97A94A28097C9DCB49637665E328FDA5886",
}

var ToxmeBots = []string{}

type BSNode struct {
	Host   string
	Ports  []uint16
	Pubkey string
	Motd   string
}

var BSNodes = []BSNode{
	{"104.225.141.59", []uint16{33445}, "933BA20B2E258B4C0D475B6DECE90C7E827FE83EFA9655414E7841251B19A72C", ""},
	{"43.198.227.166", []uint16{3389}, "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E", ""},
	{"3.0.24.15", []uint16{33445}, "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D", ""},
}

type jsonNode struct {
	IPv4     string   `json:"ipv4"`
	IPv6     string   `json:"ipv6"`
	Port     uint16   `json:"port"`
	TCPPorts []uint16 `json:"tcp_ports"`
	Pubkey   string   `json:"public_key"`
	Motd     string   `json:"motd"`
}

type jsonRoot struct {
	Nodes []jsonNode `json:"nodes"`
}

var (
	bsNodesOnce  sync.Once
	bsNodesCache []BSNode
	bsNodesErr   error
)

func LoadBSNodes() ([]BSNode, error) {
	bsNodesOnce.Do(func() {
		var root jsonRoot
		if err := json.Unmarshal(data_full_json, &root); err != nil {
			bsNodesErr = err
			return
		}
		for _, n := range root.Nodes {
			host := n.IPv4
			if host == "" || host == "-" || host == "NONE" {
				host = n.IPv6
			}
			ports := []uint16{n.Port}
			for _, p := range n.TCPPorts {
				if p != n.Port {
					ports = append(ports, p)
				}
			}
			bsNodesCache = append(bsNodesCache, BSNode{
				Host:   host,
				Ports:  ports,
				Pubkey: n.Pubkey,
				Motd:   n.Motd,
			})
		}
	})
	return bsNodesCache, bsNodesErr
}

type WeightedBSNode struct {
	BSNode
	weight    int
	alive     bool
	lastCheck time.Time
	latency   time.Duration
}

type NodePool struct {
	mu        sync.Mutex
	nodes     []*WeightedBSNode
	cancel    context.CancelFunc
	startOnce sync.Once
}

const (
	checkInterval  = 2 * time.Minute
	checkBatchSize = 5
	healthTTL      = 10 * time.Minute
	dialTimeout    = 3 * time.Second
	baseWeight     = 100
)

func newPool() *NodePool {
	nodes, _ := LoadBSNodes()
	pool := &NodePool{}
	for _, n := range nodes {
		pool.nodes = append(pool.nodes, &WeightedBSNode{
			BSNode: n,
			weight: baseWeight,
			alive:  true,
		})
	}
	return pool
}

func (p *NodePool) start() {
	p.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		p.cancel = cancel
		go p.CheckLoop(ctx)
	})
}

func (p *NodePool) updateWeight(n *WeightedBSNode, ok bool, latency time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n.lastCheck = time.Now()
	if ok {
		n.alive = true
		n.latency = (n.latency*3 + latency) / 4
	}
	aliveFactor := 1.0
	if !ok {
		aliveFactor = 0.1
	}
	latMs := float64(n.latency / time.Millisecond)
	latencyFactor := 100.0 / (latMs + 100.0)
	n.weight = int(float64(baseWeight) * aliveFactor * latencyFactor)
	if n.weight < 1 {
		n.weight = 1
	}
}

func (p *NodePool) checkBatch() {
	p.mu.Lock()
	var candidates []*WeightedBSNode
	now := time.Now()
	for _, n := range p.nodes {
		if now.Sub(n.lastCheck) >= healthTTL {
			candidates = append(candidates, n)
		}
	}
	batch := candidates
	if len(batch) > checkBatchSize {
		batch = batch[:checkBatchSize]
	}
	p.mu.Unlock()

	for _, n := range batch {
		start := time.Now()
		addr := net.JoinHostPort(n.Host, fmt.Sprint(n.Ports[0]))
		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		ok := err == nil
		if ok {
			conn.Close()
		}
		p.updateWeight(n, ok, time.Since(start))
	}
}

func (p *NodePool) CheckLoop(ctx context.Context) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkBatch()
		}
	}
}

func (p *NodePool) Select() BSNode {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, n := range p.nodes {
		total += n.weight
	}
	r := rand.Intn(total)
	for _, n := range p.nodes {
		r -= n.weight
		if r < 0 {
			return n.BSNode
		}
	}
	return p.nodes[0].BSNode
}

var (
	defaultPoolOnce sync.Once
	defaultPool     *NodePool
)

func defaultPoolInstance() *NodePool {
	defaultPoolOnce.Do(func() {
		defaultPool = newPool()
		defaultPool.start()
	})
	return defaultPool
}

func SelectOne() (BSNode, error) {
	pool := defaultPoolInstance()
	pool.mu.Lock()
	count := len(pool.nodes)
	pool.mu.Unlock()
	if count == 0 {
		return BSNode{}, fmt.Errorf("no bootstrap nodes available")
	}
	return pool.Select(), nil
}

func StopCheckLoop() {
	if defaultPool != nil && defaultPool.cancel != nil {
		defaultPool.cancel()
	}
}

// https://nodes.tox.chat/json
