package toxpriv

import "unsafe"

type FriendConnections unsafe.Pointer
type NetCrypto         unsafe.Pointer
type FriendConn        unsafe.Pointer

var (
	tox_m_get_friend_connectionstatus         func(m unsafe.Pointer, friendNumber int32) int32
	tox_friend_connection_crypt_connection_id func(fr_c FriendConnections, friendconID int32) int32
	tox_crypto_connection_status              func(c NetCrypto, cryptConnID int32, directConnected *bool, onlineTCPRelays *uint32) bool

	tox_getfriendcon_id              func(m unsafe.Pointer, friendNumber int32) int32
	tox_get_conn                     func(fr_c unsafe.Pointer, friendconID int32) unsafe.Pointer
	tox_friend_conn_get_dht_ip_port func(friendConn unsafe.Pointer) unsafe.Pointer
)

func MGetFriendConnectionStatus(m unsafe.Pointer, friendNumber int32) int32 {
	return tox_m_get_friend_connectionstatus(m, friendNumber)
}

func FriendConnectionCryptConnectionID(fr_c FriendConnections, friendconID int32) int32 {
	return tox_friend_connection_crypt_connection_id(fr_c, friendconID)
}

func CryptoConnectionStatus(c NetCrypto, cryptConnID int32) (directConnected bool, onlineTCPRelays uint32, found bool) {
	found = tox_crypto_connection_status(c, cryptConnID, &directConnected, &onlineTCPRelays)
	return
}

func GetFriendconID(m unsafe.Pointer, friendNumber int32) int32 {
	return tox_getfriendcon_id(m, friendNumber)
}

func GetConn(fr_c FriendConnections, friendconID int32) FriendConn {
	return FriendConn(tox_get_conn(unsafe.Pointer(fr_c), friendconID))
}

func FriendConnGetDhtIPPort(friendConn FriendConn) *IP_Port {
	ptr := tox_friend_conn_get_dht_ip_port(unsafe.Pointer(friendConn))
	if ptr == nil {
		return nil
	}
	return (*IP_Port)(ptr)
}
