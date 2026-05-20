package relayhub

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

type noiseConn struct {
	conn net.Conn
	enc  *noise.CipherState
	dec  *noise.CipherState
	buf  []byte
}

func (n *noiseConn) Read(p []byte) (int, error) {
	if len(n.buf) > 0 {
		cp := copy(p, n.buf)
		n.buf = n.buf[cp:]
		return cp, nil
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(n.conn, lenBuf[:]); err != nil {
		return 0, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if msgLen > 65535 {
		return 0, errors.New("noise frame too large")
	}
	ciphertext := make([]byte, msgLen)
	if _, err := io.ReadFull(n.conn, ciphertext); err != nil {
		return 0, err
	}
	plaintext, err := n.dec.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return 0, fmt.Errorf("noise decrypt: %w", err)
	}
	cp := copy(p, plaintext)
	if cp < len(plaintext) {
		n.buf = make([]byte, len(plaintext)-cp)
		copy(n.buf, plaintext[cp:])
	}
	return cp, nil
}

func (n *noiseConn) Write(p []byte) (int, error) {
	maxPlain := 65535 - 16
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlain {
			chunk = chunk[:maxPlain]
		}
		ciphertext, err := n.enc.Encrypt(nil, nil, chunk)
		if err != nil {
			return total, fmt.Errorf("noise encrypt: %w", err)
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(ciphertext)))
		if _, err := n.conn.Write(lenBuf[:]); err != nil {
			return total, err
		}
		if _, err := n.conn.Write(ciphertext); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (n *noiseConn) Close() error                       { return n.conn.Close() }
func (n *noiseConn) LocalAddr() net.Addr                { return n.conn.LocalAddr() }
func (n *noiseConn) RemoteAddr() net.Addr               { return n.conn.RemoteAddr() }
func (n *noiseConn) SetDeadline(t time.Time) error      { return n.conn.SetDeadline(t) }
func (n *noiseConn) SetReadDeadline(t time.Time) error  { return n.conn.SetReadDeadline(t) }
func (n *noiseConn) SetWriteDeadline(t time.Time) error { return n.conn.SetWriteDeadline(t) }

func writeNoiseMsg(w io.Writer, msg []byte) error {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(len(msg)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

func readNoiseMsg(r io.Reader) ([]byte, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(buf[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func noiseHandshake(conn net.Conn, localPriv ed25519.PrivateKey) (*noiseConn, error) {
	x25519Priv := make([]byte, 32)
	copy(x25519Priv, localPriv.Seed())
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64

	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Pattern:     noise.HandshakeXX,
		Initiator:   true,
		Prologue:    []byte("noise-libp2p-static-libs"),
		StaticKeypair: noise.DHKey{
			Private: x25519Priv,
			Public:  x25519Pub,
		},
	})
	if err != nil {
		return nil, err
	}

	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeNoiseMsg(conn, msg1); err != nil {
		return nil, fmt.Errorf("send noise msg1: %w", err)
	}

	msg2Raw, err := readNoiseMsg(conn)
	if err != nil {
		return nil, fmt.Errorf("read noise msg2: %w", err)
	}
	if _, _, _, err = hs.ReadMessage(nil, msg2Raw); err != nil {
		return nil, fmt.Errorf("process noise msg2: %w", err)
	}

	msg3, enc, dec, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create noise msg3: %w", err)
	}
	if err := writeNoiseMsg(conn, msg3); err != nil {
		return nil, fmt.Errorf("send noise msg3: %w", err)
	}

	return &noiseConn{conn: conn, enc: enc, dec: dec}, nil
}
