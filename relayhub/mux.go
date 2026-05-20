package relayhub

import (
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

func newYamuxClient(conn net.Conn) (*yamux.Session, error) {
	config := yamux.DefaultConfig()
	config.KeepAliveInterval = 10 * time.Second
	return yamux.Client(conn, config)
}
