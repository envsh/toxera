package tcpcli

import (
	"unsafe"
	"encoding/hex"
	"log"
	"fmt"
	"strings"
	"net"
	"time"
	// "math/rand"
	"runtime"
)

/*
   #cgo LDFLAGS: -ltoxcore

   #include <stdlib.h>
   #include <string.h>
   #include <dlfcn.h>
   #include "tcpclient.h"
*/
import "C"

func init() {
	f := log.Flags()|log.Lshortfile
	f = f ^ log.Ldate
	log.SetFlags(f)
}

const KEY_SIZE = C.TOX_KEY_SIZE
const PACKET_SIZE = C.TOX_PACKET_SIZE

type voidptr = unsafe.Pointer

type ConnPool struct {
	Mem  voidptr
	Rng  voidptr
	Network voidptr
	MonoTime voidptr
	Logger voidptr
	NetProf voidptr
	Proxy  voidptr

	Conns voidptr
	renew_time time.Time
	Selfpk string
	Selfsk string

	oobinch  chan oobpacket
	relays  map[string]*node // ip =>
	peerConns1 map[int]*peer_connection
	peerConns2 map[string]*peer_connection
}

func New(keyfile string) *ConnPool {
	p := new_pool(keyfile)
	p.peerConns1 = make(map[int]*peer_connection)
	p.peerConns2 = make(map[string]*peer_connection)
	p.relays = make(map[string]*node)
	p.oobinch = make(chan oobpacket, 8)

	// p.setup_callbacks()
	// C.set_tcp_onion_status(p.Conns, true)
	gp = p
	return p
}

func (p *ConnPool) Iterate() {
	C.do_tcp_connections(p.Logger, p.Conns, nil)
}

type oobpacket struct {
	data string
	peerpk string
}

type node struct {
	ip string
	port int
	pk string
}

func (p *ConnPool) AddTcpRelay(ip string, port int, pk string) error {
	pkb,_ := hex.DecodeString(pk)
	ipport := C.IP_Port{}
	ipport.ip.family = C.net_family_ipv4()
	ipb := C.CString(ip)
	defer C.free(voidptr(ipb))
	rv1 := C.addr_parse_ip(ipb, &ipport.ip)
	ipport.port = C.net_htons(C.ushort(port))
	if !rv1 {
		log.Println("parse ip error", rv1, ip)
		return nil
	}

	rv := C.add_tcp_relay_global(p.Conns, voidptr(&ipport), voidptr(&pkb[0]))
	if rv != 0{
		log.Println(rv, ip, port, unsafe.Sizeof(ipport))
		err := fmt.Errorf("err %v, %v:%v %v", ip, port, len(pk))
		return err
	}

	n := &node{ip, port, pk}
	p.relays[ip] = n

	return nil
}

type peer_connection struct {
	peerpk string
	connid int
	readch chan any
	p *ConnPool
}

func (c *peer_connection) Close() error {
	return nil
}

func (c *peer_connection) Write(buf []byte) error {
	return nil
}

func (c *peer_connection) Read(buf []byte) error {
	return nil
}

func (p *ConnPool) Dial(peerpk string) (net.Conn,error) {
	return nil,nil
}

func (p *ConnPool) send() error {
	return nil
}

/////
// must called after AddTcprelay
func (p *ConnPool) WaitConnected() time.Duration {
	btime := time.Now()
	for !p.IsConnected() {
		p.Iterate()
		time.Sleep(60*time.Millisecond)
	}
	return time.Since(btime)
}
func (p *ConnPool) IsConnected() bool {
	rc := C.tcp_connected_relays_count(p.Conns)
	return rc>0
}

var _ net.PacketConn = (*ConnPool)(nil)
func (p *ConnPool) WriteTo(buf []byte, addr net.Addr) (int, error) {
	// log.Println(addr)
	if len(buf) > PACKET_SIZE {
		return -1, fmt.Errorf("packet too long %v, <= %v", len(buf), PACKET_SIZE)
	}
	key_hex_check(addr.String())

	err := p.send_oob(addr.String(), string(buf))
	return len(buf), err
}
func (p *ConnPool) send_oob(peerpk string, data string) error {
	buf := []byte(data)
	var pk string
	for _, rl := range p.relays {
		pk = rl.pk
		break
	}
	relay_pkb := key_hex2bin(pk)
	peer_pkb := key_hex2bin(peerpk)
	var err error

	rv := C.tcp_send_oob_packet_using_relay(p.Conns, relay_pkb,
		peer_pkb, voidptr(&buf[0]), C.short(len(buf)))
	if rv < 0 {
		valid := C.tcp_relay_is_valid(p.Conns, relay_pkb)
		rc := C.tcp_connected_relays_count(p.Conns)
		err = fmt.Errorf("err %v, relay valid/count %v/%v", rv, valid, rc)
		log.Println(err, pk)
		// p.reconnect()
	}
	return err
}

func (p *ConnPool) reconnect() {
	if time.Since(p.renew_time) < 9 *time.Second {
		return
	}
	log.Println("try renew ...")
	p.renew()

	// idx := int(rand.Uint32()/2) % len(p.relays)
	// rl := p.relays[idx]
	// p.AddTcpRelay(rl.ip, rl.port, rl.pk)
}

func (p *ConnPool) ReadFrom(buf []byte) (int, net.Addr, error){
	pkt := <- p.oobinch
	addr := PeerAddr(pkt.peerpk)
	copy(buf, []byte(pkt.data))

	return len(pkt.data), addr, nil
}
func (p *ConnPool) Close() error {
	return nil
}
func (p *ConnPool) LocalAddr() net.Addr {
	return PeerAddr(p.Selfpk)
}
func (p *ConnPool) SetDeadline(v time.Time) error {
	return nil
}
func (p *ConnPool) SetReadDeadline(v time.Time) error {
	return nil
}
func (p *ConnPool) SetWriteDeadline(v time.Time) error {
	return nil
}


type PeerAddr string
func (a PeerAddr) Network() string {
	return "toxnet"
}
func (a PeerAddr) String() string {
	return string(a)
}
func (a PeerAddr) Sub7() string {
	return string(a)[:7]
}

/////

func new_pool(keyfile string) *ConnPool {

	mem := C.os_memory()
	rng := C.os_random()
	ns := C.os_network()
	mono_time := C.mono_time_new(mem, nil, nil)
	logger := C.logger_new(mem)
	np := C.netprof_new(logger, mem)
	pxy := C.malloc(256)
	C.memset(pxy, 0, 256)
	defer C.free(pxy)

	pk, sk := keyfile_neworload(keyfile, rng)
	key_hex_check(pk)
	key_hex_check(sk)

	p := &ConnPool{}
	p.Mem = mem
	p.Rng = rng
	p.Logger = logger
	p.Network = ns
	p.NetProf = np
	p.MonoTime = mono_time

	p.Selfpk = pk
	p.Selfsk = sk

	p.renew()

	return p
}
// can call multiple times now
func (p *ConnPool) renew() {
	logger := p.Logger
	mem := p.Mem
	rng := p.Rng
	ns := p.Network
	mono_time := p.MonoTime
	np := p.NetProf

	pxy := C.malloc(256)
	C.memset(pxy, 0, 256)
	defer C.free(pxy)

	skb := key_hex2bin(p.Selfsk)

	o := C.new_tcp_connections(logger, mem, rng, ns,
		mono_time, skb, pxy, np)
	old := p.Conns
	p.Conns = o
	p.renew_time = time.Now()

	p.setup_callbacks()
	C.set_tcp_onion_status(p.Conns, true)
	p.readd_relays()

	if old != nil {
		C.kill_tcp_connections(old)
	}
}

func (p *ConnPool) readd_relays() {
	for _, rl := range p.relays {
		p.AddTcpRelay(rl.ip, rl.port, rl.pk)
	}
}

func keyfile_neworload(keyfile string, rng voidptr) (string, string) {
	keyfilec := voidptr(C.CString(keyfile))
	defer C.free(voidptr(keyfilec))

	pk := [KEY_SIZE]byte{}
	sk := [KEY_SIZE]byte{}
	pkc := voidptr(&pk[0])
	skc := voidptr(&sk[0])

    if C.toxin_load_keys(keyfilec, pkc, skc) == -1 {
        C.crypto_new_keypair(rng, pkc, skc)
        C.toxin_save_keys(keyfilec, pkc, skc)
        log.Println("已生成新密钥，保存到", keyfile)
    } else {
        log.Println("已加载密钥文件", keyfile);
    }

	r0 := hex.EncodeToString(pk[:])
	r1 := hex.EncodeToString(sk[:])

	return strings.ToUpper(r0), strings.ToUpper(r1)
}

var cgopin = &runtime.Pinner{}
var gp *ConnPool

func (p *ConnPool) setup_callbacks() {
	cbobj := voidptr(p)
	cgopin.Pin(cbobj) // useless?

	f1 := dlsym0("toxin_on_oob_packet_bygo")
	C.set_oob_packet_tcp_connection_callback(p.Conns, f1, p.Conns)
	f2 := dlsym0("toxin_on_data_packet_bygo")
	C.set_packet_tcp_connection_callback(p.Conns, f2, p.Conns)
	f3 := dlsym0("toxin_on_log_line")
	C.logger_callback_log(p.Logger, f3, nil, nil)
}

func key_bin2hex(key voidptr) string {
	pkb := C.GoStringN((*C.char)(key), 32)
	val := hex.EncodeToString([]byte(pkb))
	return strings.ToUpper(val)
}
func key_hex2bin(key string) voidptr {
	key_hex_check(key)

	val, err := hex.DecodeString(key)
	if err != nil { panic(err) }
	return voidptr(&val[0])
}
func key_hex_check(key string) {
	if len(key) < 32*2 { panic("too short") }
	_, err := hex.DecodeString(key)
	if err != nil { panic(err) }
}

//export toxin_on_oob_packet_bygo
func toxin_on_oob_packet_bygo(obj voidptr, peerpk voidptr, tcp_connections_number int, packet *C.char, length uint16, userdata voidptr) {
	// log.Println("<<", tcp_connections_number, packet, length)
	pkt := C.GoStringN(packet, C.int(length))
	pk := key_bin2hex(peerpk)

	gp.on_oob_packet(obj, pk, tcp_connections_number, pkt)
}
func (p* ConnPool) on_oob_packet(obj voidptr, peerpk string, conn_num int, pkt string) {
	// log.Println("<<", pkt, peerpk)
	if len(p.oobinch)>=cap(p.oobinch) {
		<- p.oobinch
	}
	p.oobinch <- oobpacket{pkt, peerpk}
}

func dlsym0(name string) voidptr {
	namec := C.CString(name)
	defer C.free(voidptr(namec))

	f1 := C.dlsym(C.RTLD_DEFAULT, namec)
	if f1 == nil {
		log.Println("some error", name)
	}
	return f1
}

//export toxin_on_data_packet_bygo
func toxin_on_data_packet_bygo(object voidptr, crypt_connection_id int, packet voidptr, length uint16, userdata voidptr) {
	log.Println("<<", crypt_connection_id, packet, length)
	gp.on_data_packet()
}
func (p *ConnPool) on_data_packet() {
}

// -DMIN_LOGGER_LEVEL=0 recompile libtoxcore

//export toxin_on_log_line
func toxin_on_log_line(ctx voidptr, level int, file voidptr, line uint32, funcname voidptr, msg voidptr, userdata voidptr) {
	log.Println(level, line, msg)
}
