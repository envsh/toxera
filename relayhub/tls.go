package relayhub

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"time"
)

const certValidity = 100 * 365 * 24 * time.Hour

var libp2pTLSKeyExtOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53594, 1, 1}

type signedKeyASN1 struct {
	PubKey    []byte
	Signature []byte
}

func marshalEd25519PubKey(pub ed25519.PublicKey) []byte {
	b := make([]byte, 0, 36)
	b = append(b, 0x08, 0x01)
	b = append(b, 0x12)
	b = append(b, encodeVarint(uint64(len(pub)))...)
	b = append(b, pub...)
	return b
}

func newTlsCert(ed25519Key ed25519.PrivateKey) (*tls.Certificate, error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate cert ecdsa key: %w", err)
	}

	pub := ed25519Key.Public().(ed25519.PublicKey)
	pbPub := marshalEd25519PubKey(pub)

	certPKIX, err := x509.MarshalPKIXPublicKey(certKey.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal pkix: %w", err)
	}

	sig := ed25519.Sign(ed25519Key, append([]byte("libp2p-tls-handshake:"), certPKIX...))

	extVal, err := asn1.Marshal(signedKeyASN1{PubKey: pbPub, Signature: sig})
	if err != nil {
		return nil, fmt.Errorf("asn1 marshal: %w", err)
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	subjectSN, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: sn,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certValidity),
		Subject:      pkix.Name{SerialNumber: subjectSN.String()},
		ExtraExtensions: []pkix.Extension{
			{Id: libp2pTLSKeyExtOID, Critical: false, Value: extVal},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, certKey.Public(), certKey)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  certKey,
	}, nil
}

func ConnectTLS(ctx context.Context, relayAddr string, key ed25519.PrivateKey) (net.Conn, error) {
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", relayAddr, err)
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(15 * time.Second)
	}

	if err := MSSelect(raw, "/tls/1.0.0"); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls negotiate: %w", err)
	}

	return TLSClient(raw, key, ctx)
}

// TLSClient wraps an existing connection with TLS using the libp2p certificate.
func TLSClient(raw net.Conn, key ed25519.PrivateKey, ctx context.Context) (net.Conn, error) {
	cert, err := newTlsCert(key)
	if err != nil {
		return nil, fmt.Errorf("tls cert: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{*cert},
		NextProtos:         []string{"libp2p"},
	}

	tlsConn := tls.Client(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return tlsConn, nil
}
