package relayhub

import (
	"encoding/binary"
	"io"
)

func encodeVarint(v uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, v)
	return buf[:n]
}

func decodeVarint(data []byte) (uint64, int) {
	return binary.Uvarint(data)
}

func readVarint(r io.ByteReader) (uint64, error) {
	return binary.ReadUvarint(r)
}

type byteReader struct {
	io.Reader
}

func (r *byteReader) ReadByte() (byte, error) {
	buf := make([]byte, 1)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return 0, err
	}
	return buf[0], nil
}

func newByteReader(r io.Reader) *byteReader {
	return &byteReader{r}
}
