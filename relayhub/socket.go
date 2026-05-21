package relayhub

import (
	"context"
	"fmt"
	"io"
	"log"
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
	cid := "sock." + ts
	for cid == lastID {
		time.Sleep(time.Nanosecond)
		ts = time.Now().Format("20060102.150405.000000000")
		cid = "sock." + ts
	}
	lastID = cid
	return cid
}

type RelaySocket struct {
	id      string
	ch      chan *RelayedConn
	client  *RelayClient
	dstPeer PeerID

	limitBytes int64
	cur        *RelayedConn
	writeOnCur int64

	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool

	closeOnce sync.Once
	connOnce  sync.Once

	readTotal  atomic.Int64
	writeTotal atomic.Int64
	rotCount   atomic.Int64
}

func newRelaySocket(client *RelayClient) *RelaySocket {
	id := generateConnID()
	sock := &RelaySocket{
		id:     id,
		ch:     make(chan *RelayedConn, 8),
		client: client,
	}

	client.mu.Lock()
	limit := client.limit
	client.mu.Unlock()

	if limit != nil {
		sock.limitBytes = int64(limit.Data)
	}

	return sock
}

func (s *RelaySocket) ID() string { return s.id }

func (s *RelaySocket) Listen() {
	log.Printf("RelaySocket %s: listening", s.id)
}

func (s *RelaySocket) Connect(ctx context.Context, dst PeerID) (*RelayedConn, error) {
	s.connOnce.Do(func() {
		s.ctx, s.cancel = context.WithCancel(ctx)
	})
	s.dstPeer = dst

	rc, err := s.client.ConnectThroughRelay(ctx, dst)
	if err != nil {
		return nil, err
	}
	if err := writePbMessage(rc, []byte(s.id)); err != nil {
		rc.Close()
		return nil, fmt.Errorf("send socket ID: %w", err)
	}

	s.cur = rc
	s.writeOnCur = int64(len(s.id) + 1)

	return rc, nil
}

func (s *RelaySocket) Accept(ctx context.Context) (*RelayedConn, error) {
	s.connOnce.Do(func() {
		s.ctx, s.cancel = context.WithCancel(ctx)
	})

	select {
	case conn := <-s.ch:
		s.cur = conn
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *RelaySocket) Write(p []byte) (int, error) {
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

func (s *RelaySocket) rotateWrite() error {
	if s.cur != nil {
		s.cur.Close()
		s.rotCount.Add(1)
	}
	if s.client == nil {
		return fmt.Errorf("RelaySocket: no relay client")
	}

	rc, err := s.client.ConnectThroughRelay(s.ctx, s.dstPeer)
	if err != nil {
		return err
	}
	if err := writePbMessage(rc, []byte(s.id)); err != nil {
		rc.Close()
		return err
	}
	s.cur = rc
	s.writeOnCur = int64(len(s.id) + 1)
	return nil
}

func (s *RelaySocket) Read(p []byte) (int, error) {
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

func (s *RelaySocket) acceptNext() error {
	if s.client == nil {
		return fmt.Errorf("RelaySocket: no relay client")
	}
	for {
		timeoutCtx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()

		select {
		case conn := <-s.ch:
			cancel()
			s.cur = conn
			return nil
		case <-timeoutCtx.Done():
			if s.ctx.Err() != nil {
				return io.EOF
			}
			continue
		}
	}
}

func (s *RelaySocket) Remaining() int64 {
	if s.limitBytes <= 0 {
		return 1 << 62
	}
	return s.limitBytes - s.writeOnCur
}

func (s *RelaySocket) ReadTotal() int64  { return s.readTotal.Load() }
func (s *RelaySocket) WriteTotal() int64 { return s.writeTotal.Load() }
func (s *RelaySocket) Rotations() int64  { return s.rotCount.Load() }

func (s *RelaySocket) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)

		if len(s.dstPeer) > 0 && s.client != nil && s.cur != nil {
			closeID := "close." + s.id[5:]
			writePbMessage(s.cur, []byte(closeID))
		}

		if s.cancel != nil {
			s.cancel()
		}

		if s.client != nil {
			s.client.socketMu.Lock()
			delete(s.client.sockets, s.id)
			s.client.socketMu.Unlock()
		}

		if s.cur != nil {
			s.cur.Close()
			s.cur = nil
		}
	})
	return nil
}

func (s *RelaySocket) dispatchIncoming(conn *RelayedConn) {
	select {
	case s.ch <- conn:
	default:
		log.Printf("RelaySocket %s: channel full, dropping incoming connection", s.id)
		conn.Close()
	}
}
