package relayhub

import (
	"fmt"
)

const CircuitV1ProtoID = "/libp2p/circuit/relay/0.1.0"

const (
	CircuitV1TypeHop    = 1
	CircuitV1TypeStop   = 2
	CircuitV1TypeStatus = 3
	CircuitV1TypeCanHop = 4
)

const (
	CircuitV1StatusSuccess              = 100
	CircuitV1StatusHopNoConnToDst       = 260
	CircuitV1StatusHopCantDialDst       = 261
	CircuitV1StatusHopCantOpenDstStream = 262
	CircuitV1StatusHopCantSpeakRelay    = 270
	CircuitV1StatusHopCantRelayToSelf   = 280
	CircuitV1StatusMalformedMessage     = 400
)

type CircuitV1Message struct {
	Type    int
	SrcPeer *Peer
	DstPeer *Peer
	Code    int
}

func encodeCircuitV1(msg *CircuitV1Message) []byte {
	var b []byte
	b = append(b, pbEncodeVarintField(1, uint64(msg.Type))...)
	if msg.SrcPeer != nil {
		peerData := encodePeer(msg.SrcPeer)
		b = append(b, pbEncodeLengthDelimField(2, peerData)...)
	}
	if msg.DstPeer != nil {
		peerData := encodePeer(msg.DstPeer)
		b = append(b, pbEncodeLengthDelimField(3, peerData)...)
	}
	if msg.Code > 0 {
		b = append(b, pbEncodeVarintField(4, uint64(msg.Code))...)
	}
	return b
}

func decodeCircuitV1(data []byte) (*CircuitV1Message, error) {
	dec := newPbDecoder(data)
	msg := &CircuitV1Message{}
	for dec.pos < len(data) {
		field, wt, err := dec.decodeTag()
		if err != nil {
			break
		}
		switch field {
		case 1:
			if wt != 0 {
				return nil, fmt.Errorf("v1.type: unexpected wire type %d", wt)
			}
			v, err := dec.readVarint()
			if err != nil {
				return nil, err
			}
			msg.Type = int(v)
		case 2:
			if wt != 2 {
				return nil, fmt.Errorf("v1.srcPeer: unexpected wire type %d", wt)
			}
			b, err := dec.readBytes()
			if err != nil {
				return nil, err
			}
			peer, err := decodePeer(b)
			if err != nil {
				return nil, fmt.Errorf("v1.srcPeer decode: %w", err)
			}
			msg.SrcPeer = peer
		case 3:
			if wt != 2 {
				return nil, fmt.Errorf("v1.dstPeer: unexpected wire type %d", wt)
			}
			b, err := dec.readBytes()
			if err != nil {
				return nil, err
			}
			peer, err := decodePeer(b)
			if err != nil {
				return nil, fmt.Errorf("v1.dstPeer decode: %w", err)
			}
			msg.DstPeer = peer
		case 4:
			if wt != 0 {
				return nil, fmt.Errorf("v1.code: unexpected wire type %d", wt)
			}
			v, err := dec.readVarint()
			if err != nil {
				return nil, err
			}
			msg.Code = int(v)
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

func circuitV1StatusString(code int) string {
	switch code {
	case CircuitV1StatusSuccess:
		return "SUCCESS"
	case CircuitV1StatusHopNoConnToDst:
		return "HOP_NO_CONN_TO_DST"
	case CircuitV1StatusHopCantDialDst:
		return "HOP_CANT_DIAL_DST"
	case CircuitV1StatusHopCantOpenDstStream:
		return "HOP_CANT_OPEN_DST_STREAM"
	case CircuitV1StatusHopCantSpeakRelay:
		return "HOP_CANT_SPEAK_RELAY"
	case CircuitV1StatusHopCantRelayToSelf:
		return "HOP_CANT_RELAY_TO_SELF"
	case CircuitV1StatusMalformedMessage:
		return "MALFORMED_MESSAGE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", code)
	}
}


