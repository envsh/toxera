package toxpriv

import (
	"net"
	"strconv"
	"unsafe"
)

// C-compatible struct layouts (linux/amd64)

type Family uint8
type IP4 [4]byte
type IP6 [16]byte
type IP_Union [16]byte

type IP struct {
	Family Family
	_      [7]byte
	Ip     IP_Union
} // 24 bytes

type IP_Port struct {
	Ip   IP
	Port uint16
	_    [6]byte
}

// Opaque handle types for libtoxcore objects.

type Memory   unsafe.Pointer
type Random   unsafe.Pointer
type Network  unsafe.Pointer
type Logger   unsafe.Pointer
type MonoTime unsafe.Pointer
type NetProf  unsafe.Pointer
type TCPConns unsafe.Pointer

const KEY_SIZE = 32
const PACKET_SIZE = 1372

var (
	// system
	tox_os_memory    func() Memory
	tox_os_random    func() Random
	tox_os_network   func() Network
	tox_logger_new   func(mem Memory) Logger
	tox_mono_time_new func(mem Memory, a, b unsafe.Pointer) MonoTime
	tox_netprof_new  func(logger Logger, mem Memory) NetProf

	// tcp connections lifecycle
	tox_new_tcp_connections  func(logger Logger, mem Memory, rng Random, network Network, monTime MonoTime, selfSK, proxyInfo unsafe.Pointer, netprof NetProf) TCPConns
	tox_do_tcp_connections   func(logger Logger, tcpC TCPConns, userdata unsafe.Pointer)
	tox_kill_tcp_connections func(tcpC TCPConns)

	// tcp relay operations
	tox_add_tcp_relay_global       func(tcpC TCPConns, ipPort, relayPK unsafe.Pointer) int32
	tox_tcp_relay_is_valid         func(tcpC TCPConns, relayPK unsafe.Pointer) bool
	tox_tcp_connected_relays_count func(tcpC TCPConns) int32
	tox_tcp_connections_count      func(tcpC TCPConns) int32
	tox_set_tcp_onion_status       func(tcpC TCPConns, enabled bool) int32

	// tcp peer operations
	tox_new_tcp_connection_to              func(tcpC TCPConns, peerPK unsafe.Pointer, id int32) int32
	tox_kill_tcp_connection_to             func(tcpC TCPConns, connNum int32) int32
	tox_send_packet_tcp_connection         func(tcpC TCPConns, connNum int32, pkt unsafe.Pointer, length int16) int32
	tox_tcp_send_onion_request             func(tcpC TCPConns, connNum int32, data unsafe.Pointer, length int16) int32
	tox_tcp_send_oob_packet_using_relay    func(tcpC TCPConns, relayPK, peerPK, data unsafe.Pointer, length int16) int32

	// callback setters (C order: tcp_c, cbfn, object)
	tox_set_oob_packet_tcp_connection_callback func(tcpC TCPConns, cbfn uintptr, object unsafe.Pointer)
	tox_set_packet_tcp_connection_callback     func(tcpC TCPConns, cbfn uintptr, object unsafe.Pointer)
	tox_logger_callback_log                    func(logger Logger, logcb uintptr, a, b unsafe.Pointer)

	// network utils
	tox_net_family_ipv4 func() Family
	tox_net_htons       func(v uint16) uint16
	tox_addr_parse_ip   func(ipstr, ip unsafe.Pointer) bool

	// crypto
	tox_crypto_new_keypair func(rng Random, pk, sk unsafe.Pointer)

	// key file (lib has no toxin_ prefix variants; use pure Go SaveKeys/LoadKeys)
)

// --- utility ---

func CString(s string) unsafe.Pointer {
	b := append([]byte(s), 0)
	return unsafe.Pointer(&b[0])
}

// --- system ---

func OsMemory() Memory {
	return tox_os_memory()
}

func OsRandom() Random {
	return tox_os_random()
}

func OsNetwork() Network {
	return tox_os_network()
}

func LoggerNew(mem Memory) Logger {
	return tox_logger_new(mem)
}

func MonoTimeNew(mem Memory, a, b unsafe.Pointer) MonoTime {
	return tox_mono_time_new(mem, a, b)
}

func NetprofNew(logger Logger, mem Memory) NetProf {
	return tox_netprof_new(logger, mem)
}

// --- tcp connections lifecycle ---

func NewTCPConnections(logger Logger, mem Memory, rng Random, network Network, monTime MonoTime, selfSK, proxyInfo unsafe.Pointer, netprof NetProf) TCPConns {
	return tox_new_tcp_connections(logger, mem, rng, network, monTime, selfSK, proxyInfo, netprof)
}

func DoTCPConnections(logger Logger, tcpC TCPConns, userdata unsafe.Pointer) {
	tox_do_tcp_connections(logger, tcpC, userdata)
}

func KillTCPConnections(tcpC TCPConns) {
	tox_kill_tcp_connections(tcpC)
}

// --- tcp relay operations ---

func AddTCPRelayGlobal(tcpC TCPConns, ipPort, relayPK unsafe.Pointer) int32 {
	return tox_add_tcp_relay_global(tcpC, ipPort, relayPK)
}

func TCPRelayIsValid(tcpC TCPConns, relayPK unsafe.Pointer) bool {
	return tox_tcp_relay_is_valid(tcpC, relayPK)
}

func TCPConnectedRelaysCount(tcpC TCPConns) int32 {
	return tox_tcp_connected_relays_count(tcpC)
}

func TCPConnectionsCount(tcpC TCPConns) int32 {
	return tox_tcp_connections_count(tcpC)
}

func SetTCPOnionStatus(tcpC TCPConns, enabled bool) int32 {
	return tox_set_tcp_onion_status(tcpC, enabled)
}

// --- tcp peer operations ---

func NewTCPConnectionTo(tcpC TCPConns, peerPK unsafe.Pointer, id int32) int32 {
	return tox_new_tcp_connection_to(tcpC, peerPK, id)
}

func KillTCPConnectionTo(tcpC TCPConns, connNum int32) int32 {
	return tox_kill_tcp_connection_to(tcpC, connNum)
}

func SendPacketTCPConnection(tcpC TCPConns, connNum int32, pkt unsafe.Pointer, length int16) int32 {
	return tox_send_packet_tcp_connection(tcpC, connNum, pkt, length)
}

func TCPSendOnionRequest(tcpC TCPConns, connNum int32, data unsafe.Pointer, length int16) int32 {
	return tox_tcp_send_onion_request(tcpC, connNum, data, length)
}

func TCPSendOOBPacketUsingRelay(tcpC TCPConns, relayPK, peerPK, data unsafe.Pointer, length int16) int32 {
	return tox_tcp_send_oob_packet_using_relay(tcpC, relayPK, peerPK, data, length)
}

// --- callback setters ---
// cbfn is obtained from purego.NewCallback(fn)

func SetOOBPacketTCPConnectionCallback(tcpC TCPConns, cbfn uintptr, object unsafe.Pointer) {
	tox_set_oob_packet_tcp_connection_callback(tcpC, cbfn, object)
}

func SetPacketTCPConnectionCallback(tcpC TCPConns, cbfn uintptr, object unsafe.Pointer) {
	tox_set_packet_tcp_connection_callback(tcpC, cbfn, object)
}

func LoggerCallbackLog(logger Logger, logcb uintptr, a, b unsafe.Pointer) {
	tox_logger_callback_log(logger, logcb, a, b)
}

// --- network utils ---

func NetFamilyIPv4() Family {
	return tox_net_family_ipv4()
}

func NetHtons(v uint16) uint16 {
	return tox_net_htons(v)
}

func AddrParseIP(ipstr, ip unsafe.Pointer) bool {
	return tox_addr_parse_ip(ipstr, ip)
}

// --- crypto ---

func CryptoNewKeypair(rng Random, pk, sk unsafe.Pointer) {
	tox_crypto_new_keypair(rng, pk, sk)
}

// MakeIPPort creates an IP_Port from a string IP and port number.
func MakeIPPort(ip string, port uint16) (ipp IP_Port, err error) {
	ipp.Ip.Family = NetFamilyIPv4()
	cs := CString(ip)
	if !AddrParseIP(cs, unsafe.Pointer(&ipp.Ip)) {
		return ipp, errParseIP
	}
	ipp.Port = NetHtons(port)
	return
}

var errParseIP = &parseIPError{}

type parseIPError struct{}

func (*parseIPError) Error() string { return "toxpriv: parse ip failed" }

// NodeFormat matches C Node_format struct.
type NodeFormat struct {
	PublicKey [32]byte
	IpPort    IP_Port
}

var (
	tox_net_family_ipv6                func() Family
	tox_copy_connected_tcp_relays_index func(nc unsafe.Pointer, tcpRelays unsafe.Pointer, num uint16, idx uint32) uint32
)

func NetFamilyIPv6() Family {
	return tox_net_family_ipv6()
}

func CopyConnectedTCPRelaysIndex(nc NetCrypto, tcpRelays *NodeFormat, num uint16, idx uint32) uint32 {
	return tox_copy_connected_tcp_relays_index(unsafe.Pointer(nc), unsafe.Pointer(tcpRelays), num, idx)
}

func formatIPPort(ipp IP_Port) string {
	port := NetHtons(ipp.Port)
	switch ipp.Ip.Family {
	case NetFamilyIPv4():
		return net.JoinHostPort(net.IP(ipp.Ip.Ip[:4]).String(), strconv.Itoa(int(port)))
	case NetFamilyIPv6():
		return net.JoinHostPort(net.IP(ipp.Ip.Ip[:]).String(), strconv.Itoa(int(port)))
	default:
		return ""
	}
}
