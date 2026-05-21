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
		time.Sleep(time.Nanosecond)
		ts = time.Now().Format("20060102.150405.000000000")
		cid = "open0." + ts
	}
	lastID = cid
	return cid
}

type BudgetedConn struct {
	client     *RelayClient
	dstPeer    PeerID
	limitBytes int64
	connID     string

	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool

	closeOnce sync.Once
	cur       *RelayedConn

	writeOnCur int64

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
		client:     client,
		dstPeer:    dst,
		limitBytes: limitBytes,
		connID:     connID,
		ctx:        ctx,
		cancel:     cancel,
		cur:        rc,
		writeOnCur: int64(len(connID) + 1),
	}
	return s, nil
}

func NewBudgetedListener(ctx context.Context, client *RelayClient) (*BudgetedConn, error) {
	client.mu.Lock()
	limit := client.limit
	client.mu.Unlock()

	var limitBytes int64
	if limit != nil {
		limitBytes = int64(limit.Data)
	}

	ctx, cancel := context.WithCancel(ctx)
	s := &BudgetedConn{
		client:     client,
		limitBytes: limitBytes,
		ctx:        ctx,
		cancel:     cancel,
	}
	return s, nil
}

func (s *BudgetedConn) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	if s.cur == nil || (s.limitBytes > 0 && s.writeOnCur >= s.limitBytes) {
		if err := s.rotateWrite(); err != nil {
			return 0, err
		}
	}

	avail := int64(len(p))
	if s.limitBytes > 0 {
		if rem := s.limitBytes - s.writeOnCur; rem < avail {
			avail = rem
		}
	}

	n, err := s.cur.Write(p[:avail])
	s.writeOnCur += int64(n)
	s.writeTotal.Add(int64(n))
	if err != nil {
		s.cur.Close()
		s.cur = nil
		s.rotCount.Add(1)
	}
	return n, err
}

func (s *BudgetedConn) rotateWrite() error {
	if s.cur != nil {
		s.cur.Close()
		s.rotCount.Add(1)
	}
	if s.client == nil {
		return fmt.Errorf("BudgetedConn: no relay client")
	}

	rc, err := s.client.ConnectThroughRelay(s.ctx, s.dstPeer)
	if err != nil {
		return err
	}
	if err := writePbMessage(rc, []byte(s.connID)); err != nil {
		rc.Close()
		return err
	}
	s.cur = rc
	s.writeOnCur = int64(len(s.connID) + 1)
	return nil
}

func (s *BudgetedConn) Read(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	for {
		if s.cur == nil {
			if err := s.acceptNext(); err != nil {
				return 0, err
			}
		}

		n, err := s.cur.Read(p)
		s.readTotal.Add(int64(n))

		if err == io.EOF {
			s.cur.Close()
			s.cur = nil
			s.rotCount.Add(1)
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (s *BudgetedConn) acceptNext() error {
	if s.client == nil {
		return fmt.Errorf("BudgetedConn: no relay client")
	}
	for {
		timeoutCtx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()
		rc, err := s.client.AcceptRelay(timeoutCtx)
		if err != nil {
			if err == context.DeadlineExceeded {
				return io.EOF
			}
			return err
		}

		data, err := readOnePb(rc)
		if err != nil {
			rc.Close()
			continue
		}

		cid := string(data)
		if strings.HasPrefix(cid, "close.") {
			rc.Close()
			log.Printf("BudgetedConn: received close signal for conn %s", cid[6:])
			return io.EOF
		}
		if !strings.HasPrefix(cid, "open0.") {
			rc.Close()
			continue
		}

		s.cur = rc
		s.connID = cid
		return nil
	}
}

func (s *BudgetedConn) Remaining() int64 {
	if s.limitBytes <= 0 {
		return 1 << 62
	}
	return s.limitBytes - s.writeOnCur
}

func (s *BudgetedConn) ReadTotal() int64  { return s.readTotal.Load() }
func (s *BudgetedConn) WriteTotal() int64 { return s.writeTotal.Load() }
func (s *BudgetedConn) Rotations() int64  { return s.rotCount.Load() }
func (s *BudgetedConn) ConnID() string    { return s.connID }

func (s *BudgetedConn) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)

		if len(s.dstPeer) > 0 && s.client != nil && s.cur != nil {
			closeID := "close." + s.connID[6:]
			writePbMessage(s.cur, []byte(closeID))
		}

		s.cancel()

		if s.cur != nil {
			s.cur.Close()
			s.cur = nil
		}
	})
	return nil
}
