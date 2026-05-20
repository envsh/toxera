package relayhub

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

var msProtoIDs = []string{
	"/multistream/1.0.0\n",
	"/multistream-select/1.0.0\n",
}

var errProtocolNotAvailable = errors.New("protocol not available")

func readMsg(r io.Reader) (string, error) {
	l, err := readVarint(newByteReader(r))
	if err != nil {
		return "", err
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func writeMsg(w io.Writer, msg string) error {
	data := []byte(msg)
	packet := append(encodeVarint(uint64(len(data))), data...)
	//log.Printf("MS writeMsg: sending %d bytes: %x [%s]", len(packet), packet, data)
	_, err := w.Write(packet)
	return err
}

func msSelect(rw io.ReadWriter, protoID string) error {
	matched := false
	for _, m := range msProtoIDs {
		trimmed := m[:len(m)-1]
		if err := writeMsg(rw, m); err != nil {
			return fmt.Errorf("send multistream header: %w", err)
		}
		resp, err := readMsg(rw)
		if err != nil {
			return fmt.Errorf("read multistream header resp: %w", err)
		}

		if resp == trimmed || resp == m {
			matched = true
			break
		}

		if resp == "na" || resp == "na\n" {
			continue
		}

		for _, m2 := range msProtoIDs {
			if resp == m2 || resp == m2[:len(m2)-1] {
				matched = true
				break
			}
		}
		if matched {
			break
		}
		return fmt.Errorf("unexpected multistream resp: %q (bytes=%x)", resp, []byte(resp))
	}
	if !matched {
		return fmt.Errorf("multistream not available (peer returned na)")
	}

	req := protoID + "\n"
	if err := writeMsg(rw, req); err != nil {
		return fmt.Errorf("send proto req: %w", err)
	}

	resp, err := readMsg(rw)
	if err != nil {
		return fmt.Errorf("read proto resp: %w", err)
	}
	if resp == "na" || resp == "na\n" {
		return fmt.Errorf("%w: %s", errProtocolNotAvailable, protoID)
	}
	if resp != protoID && resp != protoID+"\n" {
		return fmt.Errorf("unexpected proto resp: got %q, want %q", resp, protoID)
	}
	return nil
}

func MSSelect(c net.Conn, protoID string) error {
	return msSelect(c, protoID)
}

func MSSelectOver(rw io.ReadWriter, protoID string) error {
	return msSelect(rw, protoID)
}

func MSRespond(rw io.ReadWriter) (string, error) {
	log.Printf("MSRespond: waiting for ms header from relay...")
	msg, err := readMsg(rw)
	if err != nil {
		return "", fmt.Errorf("read ms header: %w", err)
	}
	log.Printf("MSRespond: got ms header %q (len=%d)", msg, len(msg))

	matched := false
	for _, m := range msProtoIDs {
		trimmed := m[:len(m)-1]
		if msg == trimmed || msg == m {
			log.Printf("MSRespond: matched ms id %q, echoing back", m)
			if err := writeMsg(rw, m); err != nil {
				return "", fmt.Errorf("send ms header: %w", err)
			}
			matched = true
			break
		}
	}
	if !matched {
		return "", fmt.Errorf("unexpected ms header: %q", msg)
	}

	log.Printf("MSRespond: waiting for proto request from relay...")
	proto, err := readMsg(rw)
	if err != nil {
		return "", fmt.Errorf("read proto req: %w", err)
	}
	log.Printf("MSRespond: got proto request %q (len=%d)", proto, len(proto))

	if proto == "na" || proto == "na\n" {
		return "", fmt.Errorf("%w: client refused", errProtocolNotAvailable)
	}

	log.Printf("MSRespond: echoing proto request %q", proto)
	if err := writeMsg(rw, proto); err != nil {
		return "", fmt.Errorf("send proto resp: %w", err)
	}

	proto = trimNewline(proto)
	log.Printf("MSRespond: negotiated protocol %q", proto)
	return proto, nil
}

func trimNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		return s[:len(s)-1]
	}
	return s
}
