package tcpcli

import (
	"unsafe"
	"encoding/hex"
	"log"
	"fmt"
	"strings"
	"net"
	"time"
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
	Selfpk string
	Selfsk string

	relays  []*node
	peerConns1 map[int]*peer_connection
	peerConns2 map[string]*peer_connection
}

func New(keyfile string) *ConnPool {
	p := new_pool(keyfile)
	p.peerConns1 = make(map[int]*peer_connection)
	p.peerConns2 = make(map[string]*peer_connection)
	p.setup_callbacks()
	C.set_tcp_onion_status(p.Conns, true)
	return p
}

func (p *ConnPool) Iterate() {
	C.do_tcp_connections(p.Logger, p.Conns, nil)
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
	p.relays = append(p.relays, n)

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

var _ net.PacketConn = (*ConnPool)(nil)
func (p *ConnPool) WriteTo(buf []byte, addr net.Addr) (int, error) {
	// log.Println(addr)
	pk := p.relays[0].pk
	relay_pkb, err := hex.DecodeString(pk)
	peer_pkb, err := hex.DecodeString(addr.String())

	rv := C.tcp_send_oob_packet_using_relay(p.Conns, voidptr(&relay_pkb[0]),
		voidptr(&peer_pkb[0]), voidptr(&buf[0]), C.short(len(buf)))
	if rv < 0 {
		valid := C.tcp_relay_is_valid(p.Conns, voidptr(&relay_pkb[0]))
		rc := C.tcp_connected_relays_count(p.Conns)
		err = fmt.Errorf("err %v, relay valid/count %v/%v", rv, valid, rc)
		log.Println(err)
	}
	return 0, err
}

func (p *ConnPool) ReadFrom(buf []byte) (int, net.Addr, error){
	return 0, nil, nil
}
func (p *ConnPool) Close() error {
	return nil
}
func (p *ConnPool) LocalAddr() net.Addr {
	return nil
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

func (p *ConnPool) send_oob(peerpk string, data string) error {
	return nil
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
	skb, err := hex.DecodeString(sk)
	if err != nil { log.Fatalln(err) }
	// log.Printf("pk=%v\n", pk)

	o := C.new_tcp_connections(logger, mem, rng, ns,
		mono_time, voidptr(&skb[0]), pxy, np)

	p := &ConnPool{}
	p.Conns = o
	p.Mem = mem
	p.Rng = rng
	p.Logger = logger
	p.Selfpk = pk
	p.Selfsk = sk

	return p
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
	gp = p

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

//export toxin_on_oob_packet_bygo
func toxin_on_oob_packet_bygo(obj voidptr, peerpk voidptr, tcp_connections_number int, packet *C.char, length uint16, userdata voidptr) {
	log.Println("<<", tcp_connections_number, packet, length)
	pkt := C.GoStringN(packet, C.int(length))
	pk := key_bin2hex(peerpk)

	gp.on_oob_packet(obj, pk, tcp_connections_number, pkt)
}
func (p* ConnPool) on_oob_packet(obj voidptr, peerpk string, conn_num int, pkt string) {
	log.Println("<<", pkt, peerpk)
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

//export toxin_on_log_line
func toxin_on_log_line(ctx voidptr, level int, file voidptr, line uint32, funcname voidptr, msg voidptr, userdata voidptr) {
	log.Println(level, line, msg)
}
