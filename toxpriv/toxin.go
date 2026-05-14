package toxpriv

import (
	"fmt"
	"math/rand"
	"unsafe"
)

// upstream version 0.2.22
type Messenger struct {
	Log Logger
	MonoTime_  MonoTime
	Mem   Memory
	Rng   Random
	Ns    Network

	Net  unsafe.Pointer // Networking_Core*
	NetCrypto_ unsafe.Pointer // NetCrypto
	TcpNp   unsafe.Pointer
	Dht  unsafe.Pointer // DHT*

	Forwarding unsafe.Pointer // Forwarding*
	Announce  unsafe.Pointer  //

	Onion  unsafe.Pointer
	OnionA unsafe.Pointer
	OnionC unsafe.Pointer

	FrC    unsafe.Pointer // Friend_Connections

	TcpServer unsafe.Pointer
}

func (tox *Tox) FriendGetConnectionIP(frnum uint32) (string, error) {
	m := (*Messenger)(tox.ctox)

	friendconID := GetFriendconID(unsafe.Pointer(m), int32(frnum))
	if friendconID < 0 {
		return "", fmt.Errorf("no friend connection for friend %d", frnum)
	}

	frC := FriendConnections(m.FrC)
	nc := NetCrypto(m.NetCrypto_)

	// UDP path: check direct connection via crypto_connection_status
	cryptConnID := FriendConnectionCryptConnectionID(frC, friendconID)
	if cryptConnID >= 0 {
		directConnected, _, found := CryptoConnectionStatus(nc, cryptConnID)
		if found && directConnected {
			friendConn := GetConn(frC, friendconID)
			if friendConn != nil {
				dhtIPPort := FriendConnGetDhtIPPort(friendConn)
				if dhtIPPort != nil && dhtIPPort.Ip.Family != 0 {
					s := formatIPPort(*dhtIPPort)
					if s != "" {
						return s, nil
					}
				}
			}
		}
	}

	// TCP relay fallback: pick a random connected relay
	// TODO: implement per-friend TCP relay path via Crypto_Connection.connection_number_tcp
	var node NodeFormat
	n := CopyConnectedTCPRelaysIndex(nc, &node, 1, rand.Uint32())
	if n > 0 {
		s := formatIPPort(node.IpPort)
		if s != "" {
			return s, nil
		}
	}

	return "", fmt.Errorf("no connection available for friend %d", frnum)
}
