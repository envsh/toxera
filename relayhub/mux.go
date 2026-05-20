package relayhub

import (
	"net"

	"github.com/hashicorp/yamux"
)

func newYamuxClient(conn net.Conn) (*yamux.Session, error) {
	return yamux.Client(conn, nil)
}
