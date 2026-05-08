package tcpcli

import (
	"unsafe"
	"encoding/hex"
	"log"
	"strings"
)

/*
   #cgo LDFLAGS: -ltoxcore

   #include <stdlib.h>
   #include "tcpclient.h"
*/
import "C"

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
}

func New(keyfile string) *ConnPool {
	p := new_pool(keyfile)
	return p
}

func new_pool(keyfile string) *ConnPool {

	mem := C.os_memory()
	rng := C.os_random()
	ns := C.os_network()
	mono_time := C.mono_time_new(mem, nil, nil)
	logger := C.logger_new(mem)
	np := C.netprof_new(logger, mem)
	pxy := C.malloc(256)
	defer C.free(pxy)

	_, sk := keyfile_neworload(keyfile, rng)
	skb, err := hex.DecodeString(sk)
	if err != nil { log.Fatalln(err) }
	log.Println(sk)

	o := C.new_tcp_connections(logger, mem, rng, ns,
		mono_time, voidptr(&skb[0]), pxy, np)

	p := &ConnPool{}
	p.Conns = o
	p.Mem = mem
	p.Rng = rng
	p.Logger = logger

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
        // println("已生成新密钥，保存到 %s")
    } else {
        // println("已加载密钥文件 %s");
    }

	r0 := hex.EncodeToString(pk[:])
	r1 := hex.EncodeToString(sk[:])

	return strings.ToUpper(r0), strings.ToUpper(r1)
}
