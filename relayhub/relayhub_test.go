package relayhub

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

func TestBase58Roundtrip(t *testing.T) {
	cases := [][]byte{
		{0x12, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
		{0x00, 0x01, 0x02},
		{0xff},
	}
	for _, data := range cases {
		enc := base58Encode(data)
		dec, err := base58Decode(enc)
		if err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if !bytes.Equal(data, dec) {
			t.Fatalf("roundtrip failed: %x != %x", data, dec)
		}
	}
}

func TestPeerIDRoundtrip(t *testing.T) {
	raw := []byte{0x12, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	id := PeerID(raw)
	s := id.String()

	parsed, err := ParsePeerID(s)
	if err != nil {
		t.Fatalf("ParsePeerID error: %v", err)
	}
	if !bytes.Equal(raw, parsed) {
		t.Fatalf("PeerID roundtrip failed")
	}
}

func TestVarint(t *testing.T) {
	cases := []uint64{0, 1, 127, 128, 255, 1 << 16, 1 << 32, 1 << 63}
	for _, v := range cases {
		b := encodeVarint(v)
		dec, n := decodeVarint(b)
		if n != len(b) {
			t.Fatalf("varint %d: decoded length mismatch", v)
		}
		if dec != v {
			t.Fatalf("varint %d: decoded %d", v, dec)
		}
	}
}

func TestEncodeDecodeHopMessage(t *testing.T) {
	msg := &HopMessage{
		Type:   HopTypeConnect,
		Peer:   &Peer{ID: PeerID{0x01, 0x02, 0x03}},
		Status: StatusOK,
	}
	data := encodeHopMessage(msg)
	dec, err := decodeHopMessage(data)
	if err != nil {
		t.Fatalf("decode HopMessage error: %v", err)
	}
	if dec.Type != msg.Type {
		t.Fatalf("type mismatch: %d != %d", dec.Type, msg.Type)
	}
	if dec.Status != msg.Status {
		t.Fatalf("status mismatch: %d != %d", dec.Status, msg.Status)
	}
	if dec.Peer == nil || !bytes.Equal(dec.Peer.ID, msg.Peer.ID) {
		t.Fatalf("peer ID mismatch")
	}
}

func TestEncodeDecodeHopMessageReserve(t *testing.T) {
	msg := &HopMessage{Type: HopTypeReserve}
	data := encodeHopMessage(msg)
	dec, err := decodeHopMessage(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if dec.Type != HopTypeReserve {
		t.Fatalf("wrong type: %d", dec.Type)
	}
}

func TestEncodeDecodeHopMessageStatus(t *testing.T) {
	msg := &HopMessage{
		Type:   HopTypeStatus,
		Status: StatusOK,
		Limit:  &Limit{Duration: 60, Data: 1048576},
	}
	data := encodeHopMessage(msg)
	dec, err := decodeHopMessage(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if dec.Type != HopTypeStatus {
		t.Fatalf("wrong type")
	}
	if dec.Status != StatusOK {
		t.Fatalf("wrong status")
	}
	if dec.Limit == nil || dec.Limit.Duration != 60 || dec.Limit.Data != 1048576 {
		t.Fatalf("limit mismatch")
	}
}

func TestEncodeDecodeStopMessage(t *testing.T) {
	msg := &StopMessage{
		Type:   StopTypeConnect,
		Peer:   &Peer{ID: PeerID{0xaa, 0xbb}},
		Status: StatusOK,
	}
	data := encodeStopMessage(msg)
	dec, err := decodeStopMessage(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if dec.Type != StopTypeConnect {
		t.Fatalf("wrong type")
	}
	if dec.Status != StatusOK {
		t.Fatalf("wrong status")
	}
	if dec.Peer == nil || !bytes.Equal(dec.Peer.ID, PeerID{0xaa, 0xbb}) {
		t.Fatalf("peer ID mismatch")
	}
}

func TestMarshalEd25519PubKey(t *testing.T) {
	pub := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, 32))
	b := marshalEd25519PubKey(pub)
	want := []byte{0x08, 0x01, 0x12, 0x20}
	want = append(want, pub...)
	if !bytes.Equal(b, want) {
		t.Fatalf("marshalEd25519PubKey:\ngot  %x\nwant %x", b, want)
	}
}

func TestTlsCertExtension(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := newTlsCert(priv)
	if err != nil {
		t.Fatalf("newTlsCert: %v", err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	var found bool
	for _, ext := range parsed.Extensions {
		if ext.Id.Equal(libp2pTLSKeyExtOID) {
			found = true
			if ext.Critical {
				t.Error("extension should NOT be critical")
			}
			var sk signedKeyASN1
			if _, err := asn1.Unmarshal(ext.Value, &sk); err != nil {
				t.Fatalf("unmarshal extension: %v", err)
			}
			if len(sk.PubKey) == 0 {
				t.Error("PubKey is empty")
			}
			if len(sk.Signature) == 0 {
				t.Error("Signature is empty")
			}
		}
	}
	if !found {
		t.Error("libp2p key extension not found in certificate")
	}
}

func TestCircuitV1Roundtrip(t *testing.T) {
	msg := &CircuitV1Message{
		Type: CircuitV1TypeHop,
		DstPeer: &Peer{
			ID:    PeerID{0x01, 0x02, 0x03},
			Addrs: [][]byte{{0x04, 0x05}},
		},
	}
	data := encodeCircuitV1(msg)
	dec, err := decodeCircuitV1(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if dec.Type != msg.Type {
		t.Fatalf("type: %d != %d", dec.Type, msg.Type)
	}
	if dec.Code != msg.Code {
		t.Fatalf("code: %d != %d", dec.Code, msg.Code)
	}
	if dec.DstPeer == nil || !bytes.Equal(dec.DstPeer.ID, msg.DstPeer.ID) {
		t.Fatalf("dst peer ID mismatch")
	}
	if len(dec.DstPeer.Addrs) != 1 || !bytes.Equal(dec.DstPeer.Addrs[0], msg.DstPeer.Addrs[0]) {
		t.Fatalf("dst peer addrs mismatch")
	}
}

func TestCircuitV1StatusOnly(t *testing.T) {
	msg := &CircuitV1Message{
		Type: CircuitV1TypeStatus,
		Code: CircuitV1StatusHopCantSpeakRelay,
	}
	data := encodeCircuitV1(msg)
	dec, err := decodeCircuitV1(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if dec.Type != CircuitV1TypeStatus {
		t.Fatalf("wrong type: %d", dec.Type)
	}
	if dec.Code != CircuitV1StatusHopCantSpeakRelay {
		t.Fatalf("wrong code: %d", dec.Code)
	}
}

func TestWriteReadPbMessage(t *testing.T) {
	var buf bytes.Buffer
	msg := []byte{0x08, 0x01}
	if err := writePbMessage(&buf, msg); err != nil {
		t.Fatalf("write error: %v", err)
	}

	dec, err := readPbMessage(newByteReader(&buf))
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if !bytes.Equal(msg, dec) {
		t.Fatalf("data mismatch")
	}
}
