package toxpriv

import (
	"unsafe"

	"github.com/ebitengine/purego"
)

type Tox struct {
	ctox unsafe.Pointer
}

func NewTox(ctox unsafe.Pointer) *Tox {
	return &Tox{ctox: ctox}
}

const GroupPeerIPStringMaxLength = 96

type ErrGroupPeerQuery int32

const (
	ErrGroupPeerQueryOK            ErrGroupPeerQuery = 0
	ErrGroupPeerQueryGroupNotFound ErrGroupPeerQuery = 1
	ErrGroupPeerQueryPeerNotFound  ErrGroupPeerQuery = 2
)

func (e ErrGroupPeerQuery) Error() string {
	p := toxErrGroupPeerQueryToString(int32(e))
	if p == nil {
		return "unknown"
	}
	return goString(p)
}

var (
	libHandle                    uintptr
	toxGroupPeerGetIPAddress     func(tox uintptr, groupNumber uint32, peerID uint32, ipAddr uintptr, errCode *int32) bool
	toxErrGroupPeerQueryToString func(code int32) unsafe.Pointer
	toxSetAVObject               func(tox uintptr, object uintptr)
	toxGetAVObject               func(tox uintptr) uintptr
	toxLock                      func(tox uintptr)
	toxUnlock                    func(tox uintptr)
)

func init() {
	var err error
	for _, name := range []string{"libtoxcore.so", "libtoxcore.so.0"} {
		libHandle, err = purego.Dlopen(name, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err == nil {
			break
		}
	}
	if err != nil {
		panic("toxpriv: cannot open libtoxcore: " + err.Error())
	}
	purego.RegisterLibFunc(&toxGroupPeerGetIPAddress, libHandle, "tox_group_peer_get_ip_address")
	purego.RegisterLibFunc(&toxErrGroupPeerQueryToString, libHandle, "tox_err_group_peer_query_to_string")
	purego.RegisterLibFunc(&toxSetAVObject, libHandle, "tox_set_av_object")
	purego.RegisterLibFunc(&toxGetAVObject, libHandle, "tox_get_av_object")
	purego.RegisterLibFunc(&toxLock, libHandle, "tox_lock")
	purego.RegisterLibFunc(&toxUnlock, libHandle, "tox_unlock")

	purego.RegisterLibFunc(&tox_os_memory, libHandle, "os_memory")
	purego.RegisterLibFunc(&tox_os_random, libHandle, "os_random")
	purego.RegisterLibFunc(&tox_os_network, libHandle, "os_network")
	purego.RegisterLibFunc(&tox_logger_new, libHandle, "logger_new")
	purego.RegisterLibFunc(&tox_mono_time_new, libHandle, "mono_time_new")
	purego.RegisterLibFunc(&tox_netprof_new, libHandle, "netprof_new")

	purego.RegisterLibFunc(&tox_new_tcp_connections, libHandle, "new_tcp_connections")
	purego.RegisterLibFunc(&tox_do_tcp_connections, libHandle, "do_tcp_connections")
	purego.RegisterLibFunc(&tox_kill_tcp_connections, libHandle, "kill_tcp_connections")

	purego.RegisterLibFunc(&tox_add_tcp_relay_global, libHandle, "add_tcp_relay_global")
	purego.RegisterLibFunc(&tox_tcp_relay_is_valid, libHandle, "tcp_relay_is_valid")
	purego.RegisterLibFunc(&tox_tcp_connected_relays_count, libHandle, "tcp_connected_relays_count")
	purego.RegisterLibFunc(&tox_tcp_connections_count, libHandle, "tcp_connections_count")
	purego.RegisterLibFunc(&tox_set_tcp_onion_status, libHandle, "set_tcp_onion_status")

	purego.RegisterLibFunc(&tox_new_tcp_connection_to, libHandle, "new_tcp_connection_to")
	purego.RegisterLibFunc(&tox_kill_tcp_connection_to, libHandle, "kill_tcp_connection_to")
	purego.RegisterLibFunc(&tox_send_packet_tcp_connection, libHandle, "send_packet_tcp_connection")
	purego.RegisterLibFunc(&tox_tcp_send_onion_request, libHandle, "tcp_send_onion_request")
	purego.RegisterLibFunc(&tox_tcp_send_oob_packet_using_relay, libHandle, "tcp_send_oob_packet_using_relay")

	purego.RegisterLibFunc(&tox_set_oob_packet_tcp_connection_callback, libHandle, "set_oob_packet_tcp_connection_callback")
	purego.RegisterLibFunc(&tox_set_packet_tcp_connection_callback, libHandle, "set_packet_tcp_connection_callback")
	purego.RegisterLibFunc(&tox_logger_callback_log, libHandle, "logger_callback_log")

	purego.RegisterLibFunc(&tox_net_family_ipv4, libHandle, "net_family_ipv4")
	purego.RegisterLibFunc(&tox_net_htons, libHandle, "net_htons")
	purego.RegisterLibFunc(&tox_addr_parse_ip, libHandle, "addr_parse_ip")

	purego.RegisterLibFunc(&tox_crypto_new_keypair, libHandle, "crypto_new_keypair")

	purego.RegisterLibFunc(&tox_m_get_friend_connectionstatus, libHandle, "m_get_friend_connectionstatus")
	purego.RegisterLibFunc(&tox_friend_connection_crypt_connection_id, libHandle, "friend_connection_crypt_connection_id")
	purego.RegisterLibFunc(&tox_crypto_connection_status, libHandle, "crypto_connection_status")

	purego.RegisterLibFunc(&tox_getfriendcon_id, libHandle, "getfriendcon_id")
	purego.RegisterLibFunc(&tox_get_conn, libHandle, "get_conn")
	purego.RegisterLibFunc(&tox_friend_conn_get_dht_ip_port, libHandle, "friend_conn_get_dht_ip_port")
	purego.RegisterLibFunc(&tox_copy_connected_tcp_relays_index, libHandle, "copy_connected_tcp_relays_index")
	purego.RegisterLibFunc(&tox_net_family_ipv6, libHandle, "net_family_ipv6")
}

func goString(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}
	var b []byte
	for i := 0; ; i++ {
		c := *(*byte)(unsafe.Add(ptr, i))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

func clen(b []byte) int {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return len(b)
}

func (tox *Tox) SetAVObject(object unsafe.Pointer) {
	toxSetAVObject(uintptr(tox.ctox), uintptr(object))
}

func (tox *Tox) GetAVObject() unsafe.Pointer {
	p := toxGetAVObject(uintptr(tox.ctox))
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

func (tox *Tox) Lock() {
	toxLock(uintptr(tox.ctox))
}

func (tox *Tox) Unlock() {
	toxUnlock(uintptr(tox.ctox))
}

func (tox *Tox) GroupPeerGetIPAddress(groupNumber, peerID uint32) (string, error) {
	buf := make([]byte, GroupPeerIPStringMaxLength)
	var errCode int32
	p := unsafe.Pointer(&buf[0])
	ok := toxGroupPeerGetIPAddress(uintptr(tox.ctox), groupNumber, peerID, uintptr(p), &errCode)
	if !ok {
		return "", ErrGroupPeerQuery(errCode)
	}
	return string(buf[:clen(buf)]), nil
}
