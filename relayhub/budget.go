package relayhub

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type pendingCircuit struct {
	conn *RelayedConn
	cid  string
}

type CircuitDispatcher struct {
	client     *RelayClient
	sessions   map[string]chan *RelayedConn
	closeChans map[string]chan struct{}
	unmatched  chan pendingCircuit
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
}

func NewCircuitDispatcher(ctx context.Context, client *RelayClient) *CircuitDispatcher {
	ctx, cancel := context.WithCancel(ctx)
	return &CircuitDispatcher{
		client:     client,
		sessions:   make(map[string]chan *RelayedConn),
		closeChans: make(map[string]chan struct{}),
		unmatched:  make(chan pendingCircuit, 8),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (d *CircuitDispatcher) Loop() error {
	for {
		rc, err := d.client.AcceptRelay(d.ctx)
		if err != nil {
			if d.ctx.Err() != nil {
				return d.ctx.Err()
			}
			continue
		}

		data, err := readOnePb(rc)
		if err != nil {
			rc.Close()
			continue
		}
		cid := string(data)

		if strings.HasPrefix(cid, "close.") {
			openCid := "open0." + cid[6:]
			d.mu.Lock()
			ch := d.closeChans[openCid]
			d.mu.Unlock()
			if ch != nil {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
			rc.Close()
			continue
		}

		if !strings.HasPrefix(cid, "open0.") {
			rc.Close()
			continue
		}

		d.mu.Lock()
		ch, exists := d.sessions[cid]
		d.mu.Unlock()

		if exists {
			select {
			case ch <- rc:
			default:
				rc.Close()
			}
		} else {
			select {
			case d.unmatched <- pendingCircuit{conn: rc, cid: cid}:
			default:
				rc.Close()
			}
		}
	}
}

func (d *CircuitDispatcher) AcceptOne(ctx context.Context) (*RelayedConn, string, chan *RelayedConn, error) {
	select {
	case p := <-d.unmatched:
		d.mu.Lock()
		ch, exists := d.sessions[p.cid]
		if exists {
			d.mu.Unlock()
			ch <- p.conn
			return d.AcceptOne(ctx)
		}
		ch = make(chan *RelayedConn, 4)
		d.sessions[p.cid] = ch
		d.mu.Unlock()
		return p.conn, p.cid, ch, nil

	case <-ctx.Done():
		return nil, "", nil, ctx.Err()
	}
}

func (d *CircuitDispatcher) Register(cid string) chan *RelayedConn {
	ch := make(chan *RelayedConn, 4)
	d.mu.Lock()
	d.sessions[cid] = ch
	d.mu.Unlock()
	return ch
}

func (d *CircuitDispatcher) RegisterClose(cid string, ch chan struct{}) {
	d.mu.Lock()
	d.closeChans[cid] = ch
	d.mu.Unlock()
}

func (d *CircuitDispatcher) Unregister(cid string) {
	d.mu.Lock()
	delete(d.sessions, cid)
	delete(d.closeChans, cid)
	d.mu.Unlock()
}

func (d *CircuitDispatcher) Close() {
	d.cancel()
}

type relayCircuit struct {
	conn       *RelayedConn
	readBytes  atomic.Int64
	writeBytes atomic.Int64
}

func (c *relayCircuit) remaining(limit int64) int64 {
	if limit <= 0 {
		return 1 << 62
	}
	return limit - (c.readBytes.Load() + c.writeBytes.Load())
}

var (
	lastID string
	idMu   sync.Mutex
)

func generateConnID() string {
	idMu.Lock()
	defer idMu.Unlock()

	ts := time.Now().Format("20060102.150405.000000000")
	cid := "open0." + ts
	for cid == lastID {
		log.Printf("WARNING: conn ID collision: %s", cid)
		time.Sleep(time.Nanosecond)
		ts = time.Now().Format("20060102.150405.000000000")
		cid = "open0." + ts
	}
	lastID = cid
	return cid
}

type BudgetedConn struct {
	pool   []*relayCircuit
	poolMu sync.Mutex

	limitBytes int64
	activeR    int
	activeW    int

	client     *RelayClient
	dstPeer    PeerID
	connCh     chan *RelayedConn
	connID     string
	closeCh    chan struct{}
	dispatcher *CircuitDispatcher

	prebuilding atomic.Bool
	ctx         context.Context
	cancel      context.CancelFunc
	closeOnce   sync.Once
	closed      atomic.Bool

	readTotal  atomic.Int64
	writeTotal atomic.Int64
	rotCount   atomic.Int64
}

func NewBudgetedConn(ctx context.Context, client *RelayClient, dst PeerID) (*BudgetedConn, error) {
	connID := generateConnID()

	rc, err := client.ConnectThroughRelay(ctx, dst)
	if err != nil {
		return nil, err
	}
	if err := writePbMessage(rc, []byte(connID)); err != nil {
		rc.Close()
		return nil, fmt.Errorf("send session ID: %w", err)
	}

	client.mu.Lock()
	limit := client.limit
	client.mu.Unlock()

	var limitBytes int64
	if limit != nil {
		limitBytes = int64(limit.Data)
	}

	ctx, cancel := context.WithCancel(ctx)
	s := &BudgetedConn{
		limitBytes: limitBytes,
		client:     client,
		dstPeer:    dst,
		connID:  connID,
		ctx:        ctx,
		cancel:     cancel,
	}
	s.pool = append(s.pool, &relayCircuit{conn: rc})
	return s, nil
}

func NewBudgetedConnAcceptor(ctx context.Context,
	client *RelayClient, dispatcher *CircuitDispatcher) (*BudgetedConn, error) {

	rc, sid, ch, err := dispatcher.AcceptOne(ctx)
	if err != nil {
		return nil, err
	}

	client.mu.Lock()
	limit := client.limit
	client.mu.Unlock()

	var limitBytes int64
	if limit != nil {
		limitBytes = int64(limit.Data)
	}

	ctx, cancel := context.WithCancel(ctx)
	s := &BudgetedConn{
		limitBytes: limitBytes,
		client:     client,
		connCh:     ch,
		connID:     sid,
		closeCh:    make(chan struct{}, 1),
		dispatcher: dispatcher,
		ctx:        ctx,
		cancel:     cancel,
	}
	dispatcher.RegisterClose(sid, s.closeCh)
	s.startCloseWatcher()
	s.pool = append(s.pool, &relayCircuit{conn: rc})
	return s, nil
}

func (s *BudgetedConn) Read(p []byte) (int, error) {
	for {
		s.poolMu.Lock()
		if len(s.pool) == 0 {
			s.poolMu.Unlock()
			if err := s.prebuildSync(); err != nil {
				return 0, err
			}
			continue
		}
		if s.activeR >= len(s.pool) {
			s.activeR = 0
		}
		c := s.pool[s.activeR]
		s.poolMu.Unlock()

		n, err := c.conn.Read(p)
		c.readBytes.Add(int64(n))
		s.readTotal.Add(int64(n))

		if err == nil {
			return n, nil
		}
		if err == io.EOF {
			s.poolMu.Lock()
			s.pool = append(s.pool[:s.activeR], s.pool[s.activeR+1:]...)
			if s.activeR > 0 && s.activeR >= len(s.pool) {
				s.activeR--
			}
			s.rotCount.Add(1)
			s.poolMu.Unlock()
			continue
		}
		if s.closed.Load() {
			return n, err
		}
		if err := s.prebuildSync(); err != nil {
			return n, err
		}
	}
}

func (s *BudgetedConn) Write(p []byte) (int, error) {
	c, writeIdx, err := s.getOrCreateWriter()
	if err != nil {
		return 0, err
	}

	n, err := c.conn.Write(p)
	c.writeBytes.Add(int64(n))
	s.writeTotal.Add(int64(n))

	if err == nil {
		if c.remaining(s.limitBytes) < 64<<10 {
			go s.tryPrebuild()
		}
		return n, nil
	}

	if s.closed.Load() {
		return n, err
	}

	newC, _, swErr := s.replaceCircuit(writeIdx)
	if swErr != nil {
		return n, err
	}
	n2, err2 := newC.conn.Write(p[n:])
	newC.writeBytes.Add(int64(n2))
	s.writeTotal.Add(int64(n2))
	return n + n2, err2
}

func (s *BudgetedConn) getOrCreateWriter() (*relayCircuit, int, error) {
	s.poolMu.Lock()
	for {
		if len(s.pool) == 0 {
			s.poolMu.Unlock()
			if err := s.prebuildSync(); err != nil {
				return nil, 0, err
			}
			s.poolMu.Lock()
			continue
		}

		if s.activeW >= len(s.pool) {
			s.activeW = 0
		}

		start := s.activeW
		for i := 0; i < len(s.pool); i++ {
			idx := (start + i) % len(s.pool)
			c := s.pool[idx]
			if c.remaining(s.limitBytes) > 64<<10 || (len(s.pool) == 1 && c.remaining(s.limitBytes) > 0) {
				s.activeW = idx
				s.poolMu.Unlock()
				return c, idx, nil
			}
		}

		s.poolMu.Unlock()
		if err := s.prebuildSync(); err != nil {
			return nil, 0, err
		}
		s.poolMu.Lock()
	}
}

func (s *BudgetedConn) replaceCircuit(idx int) (*relayCircuit, int, error) {
	s.poolMu.Lock()
	old := s.pool[idx]
	s.pool = append(s.pool[:idx], s.pool[idx+1:]...)
	s.poolMu.Unlock()

	old.conn.Close()

	newC, err := s.newCircuit()
	if err != nil {
		return nil, 0, err
	}

	s.poolMu.Lock()
	s.pool = append(s.pool, newC)
	newIdx := len(s.pool) - 1
	s.activeW = newIdx
	if s.activeR >= len(s.pool) {
		s.activeR = 0
	}
	s.rotCount.Add(1)
	s.poolMu.Unlock()

	return newC, newIdx, nil
}

func (s *BudgetedConn) tryPrebuild() {
	if s.client == nil && s.connCh == nil {
		return
	}
	if !s.prebuilding.CompareAndSwap(false, true) {
		return
	}
	go s.prebuild()
}

func (s *BudgetedConn) prebuild() {
	defer s.prebuilding.Store(false)

	if s.closed.Load() {
		return
	}
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	if !s.wantMore() {
		return
	}

	c, err := s.newCircuit()
	if err != nil {
		if !s.closed.Load() && s.ctx.Err() == nil {
			log.Printf("BudgetedConn: prebuild error: %v", err)
		}
		return
	}

	s.poolMu.Lock()
	s.pool = append(s.pool, c)
	log.Printf("BudgetedConn: prebuilt circuit (pool=%d)", len(s.pool))
	s.poolMu.Unlock()
}

func (s *BudgetedConn) prebuildSync() error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}

	for {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
		}

		c, err := s.newCircuit()
		if err != nil {
			return err
		}

		s.poolMu.Lock()
		s.pool = append(s.pool, c)
		s.poolMu.Unlock()
		s.rotCount.Add(1)

		s.poolMu.Lock()
		enough := s.hasBudgetLocked()
		s.poolMu.Unlock()
		if enough {
			return nil
		}
	}
}

func (s *BudgetedConn) hasBudgetLocked() bool {
	for _, c := range s.pool {
		if c.remaining(s.limitBytes) > 0 {
			return true
		}
	}
	return false
}

func (s *BudgetedConn) wantMore() bool {
	s.poolMu.Lock()
	defer s.poolMu.Unlock()

	if len(s.pool) < 2 {
		return true
	}
	for _, c := range s.pool {
		if c.remaining(s.limitBytes) > 128<<10 {
			return false
		}
	}
	return true
}

func (s *BudgetedConn) newCircuit() (*relayCircuit, error) {
	if len(s.dstPeer) > 0 {
		rc, err := s.client.ConnectThroughRelay(s.ctx, s.dstPeer)
		if err != nil {
			return nil, err
		}
		if err := writePbMessage(rc, []byte(s.connID)); err != nil {
			rc.Close()
			return nil, fmt.Errorf("send session ID: %w", err)
		}
		return &relayCircuit{conn: rc}, nil
	}

	if s.connCh != nil {
		select {
		case rc := <-s.connCh:
			return &relayCircuit{conn: rc}, nil
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		}
	}

	return nil, io.ErrClosedPipe
}

func (s *BudgetedConn) Remaining() int64 {
	s.poolMu.Lock()
	defer s.poolMu.Unlock()

	var total int64
	for _, c := range s.pool {
		total += c.remaining(s.limitBytes)
	}
	return total
}

func (s *BudgetedConn) ReadTotal() int64  { return s.readTotal.Load() }
func (s *BudgetedConn) WriteTotal() int64 { return s.writeTotal.Load() }
func (s *BudgetedConn) Rotations() int64  { return s.rotCount.Load() }
func (s *BudgetedConn) PoolSize() int     { s.poolMu.Lock(); defer s.poolMu.Unlock(); return len(s.pool) }
func (s *BudgetedConn) ConnID() string { return s.connID }

func (s *BudgetedConn) startCloseWatcher() {
	go func() {
		select {
		case <-s.closeCh:
			s.Close()
		case <-s.ctx.Done():
		}
	}()
}

func (s *BudgetedConn) Close() error {
	var err error
	s.closeOnce.Do(func() {
		// fire-and-forget close signal to remote
		if len(s.dstPeer) > 0 && s.client != nil && s.ctx.Err() == nil {
			closeID := "close." + s.connID[6:]
			rc, cerr := s.client.ConnectThroughRelay(s.ctx, s.dstPeer)
			if cerr == nil {
				if pberr := writePbMessage(rc, []byte(closeID)); pberr == nil {
					rc.Close()
				}
			}
		}

		s.closed.Store(true)
		s.cancel()

		if s.dispatcher != nil {
			s.dispatcher.Unregister(s.connID)
		}

		s.poolMu.Lock()
		for _, c := range s.pool {
			if ce := c.conn.Close(); ce != nil {
				err = ce
			}
		}
		s.pool = nil
		s.poolMu.Unlock()
	})
	return err
}
