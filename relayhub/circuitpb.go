package relayhub

import (
	"errors"
	"fmt"
	"io"
)

const (
	StatusUnused                = 0
	StatusOK                    = 100
	StatusReservationRefused    = 200
	StatusResourceLimitExceeded = 201
	StatusPermissionDenied      = 202
	StatusConnectionFailed      = 203
	StatusNoReservation         = 204
	StatusMalformedMessage      = 400
	StatusUnexpectedMessage     = 401
)

type HopType int32

const (
	HopTypeReserve HopType = 0
	HopTypeConnect HopType = 1
	HopTypeStatus  HopType = 2
)

type StopType int32

const (
	StopTypeConnect StopType = 0
	StopTypeStatus  StopType = 1
)

type Peer struct {
	ID    PeerID
	Addrs [][]byte
}

type Reservation struct {
	Expire uint64
	Addrs  [][]byte
	Voucher []byte
}

type Limit struct {
	Duration uint32
	Data     uint64
}

type HopMessage struct {
	Type        HopType
	Peer        *Peer
	Reservation *Reservation
	Limit       *Limit
	Status      int32
}

type StopMessage struct {
	Type   StopType
	Peer   *Peer
	Limit  *Limit
	Status int32
}

func encodeTag(field int, wireType int) []byte {
	return encodeVarint(uint64(field<<3) | uint64(wireType))
}

func pbEncodeVarintField(field int, v uint64) []byte {
	var b []byte
	b = append(b, encodeTag(field, 0)...)
	b = append(b, encodeVarint(v)...)
	return b
}

func pbEncodeLengthDelimField(field int, data []byte) []byte {
	var b []byte
	b = append(b, encodeTag(field, 2)...)
	b = append(b, encodeVarint(uint64(len(data)))...)
	b = append(b, data...)
	return b
}

func pbEncodeLengthDelimFields(field int, items [][]byte) []byte {
	var b []byte
	for _, item := range items {
		b = append(b, encodeTag(field, 2)...)
		b = append(b, encodeVarint(uint64(len(item)))...)
		b = append(b, item...)
	}
	return b
}

func encodePeer(p *Peer) []byte {
	var b []byte
	if p != nil && p.ID != nil {
		b = append(b, pbEncodeLengthDelimField(1, p.ID)...)
	}
	if p != nil && len(p.Addrs) > 0 {
		b = append(b, pbEncodeLengthDelimFields(2, p.Addrs)...)
	}
	return b
}

func encodeReservation(r *Reservation) []byte {
	if r == nil {
		return nil
	}
	var b []byte
	if r.Expire > 0 {
		b = append(b, pbEncodeVarintField(1, r.Expire)...)
	}
	if len(r.Addrs) > 0 {
		b = append(b, pbEncodeLengthDelimFields(2, r.Addrs)...)
	}
	if r.Voucher != nil {
		b = append(b, pbEncodeLengthDelimField(3, r.Voucher)...)
	}
	return b
}

func encodeLimit(l *Limit) []byte {
	if l == nil {
		return nil
	}
	var b []byte
	if l.Duration > 0 {
		b = append(b, pbEncodeVarintField(1, uint64(l.Duration))...)
	}
	if l.Data > 0 {
		b = append(b, pbEncodeVarintField(2, l.Data)...)
	}
	return b
}

func encodeHopMessage(msg *HopMessage) []byte {
	var b []byte
	b = append(b, pbEncodeVarintField(1, uint64(msg.Type))...)
	if msg.Peer != nil {
		peerData := encodePeer(msg.Peer)
		b = append(b, pbEncodeLengthDelimField(2, peerData)...)
	}
	if msg.Reservation != nil {
		resvData := encodeReservation(msg.Reservation)
		b = append(b, pbEncodeLengthDelimField(3, resvData)...)
	}
	if msg.Limit != nil {
		limitData := encodeLimit(msg.Limit)
		b = append(b, pbEncodeLengthDelimField(4, limitData)...)
	}
	if msg.Status > 0 {
		b = append(b, pbEncodeVarintField(5, uint64(msg.Status))...)
	}
	return b
}

func encodeStopMessage(msg *StopMessage) []byte {
	var b []byte
	b = append(b, pbEncodeVarintField(1, uint64(msg.Type))...)
	if msg.Peer != nil {
		peerData := encodePeer(msg.Peer)
		b = append(b, pbEncodeLengthDelimField(2, peerData)...)
	}
	if msg.Limit != nil {
		limitData := encodeLimit(msg.Limit)
		b = append(b, pbEncodeLengthDelimField(3, limitData)...)
	}
	if msg.Status > 0 {
		b = append(b, pbEncodeVarintField(4, uint64(msg.Status))...)
	}
	return b
}

func writePbMessage(w io.Writer, data []byte) error {
	_, err := w.Write(append(encodeVarint(uint64(len(data))), data...))
	return err
}

type pbDecoder struct {
	data []byte
	pos  int
}

func newPbDecoder(data []byte) *pbDecoder {
	return &pbDecoder{data: data}
}

func (d *pbDecoder) remaining() []byte {
	return d.data[d.pos:]
}

func (d *pbDecoder) readVarint() (uint64, error) {
	v, n := decodeVarint(d.data[d.pos:])
	if n <= 0 {
		return 0, errors.New("varint decode failed")
	}
	d.pos += n
	return v, nil
}

func (d *pbDecoder) readBytes() ([]byte, error) {
	l, err := d.readVarint()
	if err != nil {
		return nil, err
	}
	if d.pos+int(l) > len(d.data) {
		return nil, errors.New("bytes overflow")
	}
	b := make([]byte, l)
	copy(b, d.data[d.pos:])
	d.pos += int(l)
	return b, nil
}

func (d *pbDecoder) decodeTag() (field int, wireType int, err error) {
	if d.pos >= len(d.data) {
		return 0, 0, io.EOF
	}
	v, err := d.readVarint()
	if err != nil {
		return 0, 0, err
	}
	field = int(v >> 3)
	wireType = int(v & 7)
	return
}

func decodePeer(data []byte) (*Peer, error) {
	dec := newPbDecoder(data)
	p := &Peer{}
	for dec.pos < len(data) {
		field, wt, err := dec.decodeTag()
		if err != nil {
			break
		}
		switch field {
		case 1:
			if wt != 2 {
				return nil, fmt.Errorf("peer.id: unexpected wire type %d", wt)
			}
			p.ID, err = dec.readBytes()
			if err != nil {
				return nil, err
			}
		case 2:
			if wt != 2 {
				return nil, fmt.Errorf("peer.addrs: unexpected wire type %d", wt)
			}
			addr, err := dec.readBytes()
			if err != nil {
				return nil, err
			}
			p.Addrs = append(p.Addrs, addr)
		default:
			switch wt {
			case 0:
				dec.readVarint()
			case 2:
				dec.readBytes()
			}
		}
	}
	return p, nil
}

func decodeReservation(data []byte) (*Reservation, error) {
	dec := newPbDecoder(data)
	r := &Reservation{}
	for dec.pos < len(data) {
		field, wt, err := dec.decodeTag()
		if err != nil {
			break
		}
		switch field {
		case 1:
			if wt != 0 {
				return nil, fmt.Errorf("reservation.expire: unexpected wire type %d", wt)
			}
			r.Expire, err = dec.readVarint()
			if err != nil {
				return nil, err
			}
		case 2:
			if wt != 2 {
				return nil, fmt.Errorf("reservation.addrs: unexpected wire type %d", wt)
			}
			addr, err := dec.readBytes()
			if err != nil {
				return nil, err
			}
			r.Addrs = append(r.Addrs, addr)
		case 3:
			if wt != 2 {
				return nil, fmt.Errorf("reservation.voucher: unexpected wire type %d", wt)
			}
			r.Voucher, err = dec.readBytes()
			if err != nil {
				return nil, err
			}
		default:
			switch wt {
			case 0:
				dec.readVarint()
			case 2:
				dec.readBytes()
			}
		}
	}
	return r, nil
}

func decodeLimit(data []byte) (*Limit, error) {
	dec := newPbDecoder(data)
	l := &Limit{}
	for dec.pos < len(data) {
		field, wt, err := dec.decodeTag()
		if err != nil {
			break
		}
		switch field {
		case 1:
			if wt != 0 {
				return nil, fmt.Errorf("limit.duration: unexpected wire type %d", wt)
			}
			v, err := dec.readVarint()
			if err != nil {
				return nil, err
			}
			l.Duration = uint32(v)
		case 2:
			if wt != 0 {
				return nil, fmt.Errorf("limit.data: unexpected wire type %d", wt)
			}
			l.Data, err = dec.readVarint()
			if err != nil {
				return nil, err
			}
		default:
			switch wt {
			case 0:
				dec.readVarint()
			case 2:
				dec.readBytes()
			}
		}
	}
	return l, nil
}

func decodeHopMessage(data []byte) (*HopMessage, error) {
	dec := newPbDecoder(data)
	msg := &HopMessage{}
	for dec.pos < len(data) {
		field, wt, err := dec.decodeTag()
		if err != nil {
			break
		}
		switch field {
		case 1:
			if wt != 0 {
				return nil, fmt.Errorf("hop.type: unexpected wire type %d", wt)
			}
			v, err := dec.readVarint()
			if err != nil {
				return nil, err
			}
			msg.Type = HopType(v)
		case 2:
			if wt != 2 {
				return nil, fmt.Errorf("hop.peer: unexpected wire type %d", wt)
			}
			b, err := dec.readBytes()
			if err != nil {
				return nil, err
			}
			peer, err := decodePeer(b)
			if err != nil {
				return nil, fmt.Errorf("hop.peer decode: %w", err)
			}
			msg.Peer = peer
		case 3:
			if wt != 2 {
				return nil, fmt.Errorf("hop.reservation: unexpected wire type %d", wt)
			}
			b, err := dec.readBytes()
			if err != nil {
				return nil, err
			}
			resv, err := decodeReservation(b)
			if err != nil {
				return nil, fmt.Errorf("hop.reservation decode: %w", err)
			}
			msg.Reservation = resv
		case 4:
			if wt != 2 {
				return nil, fmt.Errorf("hop.limit: unexpected wire type %d", wt)
			}
			b, err := dec.readBytes()
			if err != nil {
				return nil, err
			}
			limit, err := decodeLimit(b)
			if err != nil {
				return nil, fmt.Errorf("hop.limit decode: %w", err)
			}
			msg.Limit = limit
		case 5:
			if wt != 0 {
				return nil, fmt.Errorf("hop.status: unexpected wire type %d", wt)
			}
			v, err := dec.readVarint()
			if err != nil {
				return nil, err
			}
			msg.Status = int32(v)
		default:
			switch wt {
			case 0:
				dec.readVarint()
			case 2:
				dec.readBytes()
			}
		}
	}
	return msg, nil
}

func decodeStopMessage(data []byte) (*StopMessage, error) {
	dec := newPbDecoder(data)
	msg := &StopMessage{}
	for dec.pos < len(data) {
		field, wt, err := dec.decodeTag()
		if err != nil {
			break
		}
		switch field {
		case 1:
			if wt != 0 {
				return nil, fmt.Errorf("stop.type: unexpected wire type %d", wt)
			}
			v, err := dec.readVarint()
			if err != nil {
				return nil, err
			}
			msg.Type = StopType(v)
		case 2:
			if wt != 2 {
				return nil, fmt.Errorf("stop.peer: unexpected wire type %d", wt)
			}
			b, err := dec.readBytes()
			if err != nil {
				return nil, err
			}
			peer, err := decodePeer(b)
			if err != nil {
				return nil, fmt.Errorf("stop.peer decode: %w", err)
			}
			msg.Peer = peer
		case 3:
			if wt != 2 {
				return nil, fmt.Errorf("stop.limit: unexpected wire type %d", wt)
			}
			b, err := dec.readBytes()
			if err != nil {
				return nil, err
			}
			limit, err := decodeLimit(b)
			if err != nil {
				return nil, fmt.Errorf("stop.limit decode: %w", err)
			}
			msg.Limit = limit
		case 4:
			if wt != 0 {
				return nil, fmt.Errorf("stop.status: unexpected wire type %d", wt)
			}
			v, err := dec.readVarint()
			if err != nil {
				return nil, err
			}
			msg.Status = int32(v)
		default:
			switch wt {
			case 0:
				dec.readVarint()
			case 2:
				dec.readBytes()
			}
		}
	}
	return msg, nil
}

func readPbMessage(r interface {
	Read(p []byte) (int, error)
	ReadByte() (byte, error)
}) ([]byte, error) {
	l, err := readVarint(r)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func statusString(s int32) string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusReservationRefused:
		return "RESERVATION_REFUSED"
	case StatusResourceLimitExceeded:
		return "RESOURCE_LIMIT_EXCEEDED"
	case StatusPermissionDenied:
		return "PERMISSION_DENIED"
	case StatusConnectionFailed:
		return "CONNECTION_FAILED"
	case StatusNoReservation:
		return "NO_RESERVATION"
	case StatusMalformedMessage:
		return "MALFORMED_MESSAGE"
	case StatusUnexpectedMessage:
		return "UNEXPECTED_MESSAGE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}
