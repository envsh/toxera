package toxpriv

import (
	"unsafe"

	"github.com/ebitengine/purego"
)

type Tox struct {
	ctox uintptr
}

func NewTox(ctox unsafe.Pointer) *Tox {
	return &Tox{ctox: uintptr(ctox)}
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
	toxSetAVObject(tox.ctox, uintptr(object))
}

func (tox *Tox) GetAVObject() unsafe.Pointer {
	p := toxGetAVObject(tox.ctox)
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

func (tox *Tox) GroupPeerGetIPAddress(groupNumber, peerID uint32) (string, error) {
	buf := make([]byte, GroupPeerIPStringMaxLength)
	var errCode int32
	p := unsafe.Pointer(&buf[0])
	ok := toxGroupPeerGetIPAddress(tox.ctox, groupNumber, peerID, uintptr(p), &errCode)
	if !ok {
		return "", ErrGroupPeerQuery(errCode)
	}
	return string(buf[:clen(buf)]), nil
}
