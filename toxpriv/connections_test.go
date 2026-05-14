package toxpriv

import (
	"testing"
	"unsafe"
)

func TestSystemInit(t *testing.T) {
	mem := OsMemory()
	rng := OsRandom()
	ns := OsNetwork()
	if unsafe.Pointer(mem) == nil {
		t.Error("OsMemory nil")
	}
	if unsafe.Pointer(rng) == nil {
		t.Error("OsRandom nil")
	}
	if unsafe.Pointer(ns) == nil {
		t.Error("OsNetwork nil")
	}

	logger := LoggerNew(mem)
	monoT := MonoTimeNew(mem, nil, nil)
	np := NetprofNew(logger, mem)
	if unsafe.Pointer(logger) == nil {
		t.Error("LoggerNew nil")
	}
	if unsafe.Pointer(monoT) == nil {
		t.Error("MonoTimeNew nil")
	}
	if unsafe.Pointer(np) == nil {
		t.Error("NetprofNew nil")
	}
}

func TestCString(t *testing.T) {
	s := "hello"
	p := CString(s)
	b := unsafe.Slice((*byte)(p), len(s)+1)
	if string(b[:len(s)]) != s {
		t.Error("CString content mismatch")
	}
	if b[len(s)] != 0 {
		t.Error("CString missing NUL")
	}
}

func TestNetworkUtils(t *testing.T) {
	f := NetFamilyIPv4()
	_ = f

	v := NetHtons(3389)
	if v == 0 {
		t.Error("NetHtons zero")
	}
}

func TestCryptoKeypair(t *testing.T) {
	rng := OsRandom()
	pk := make([]byte, 32)
	sk := make([]byte, 32)
	CryptoNewKeypair(rng, unsafe.Pointer(&pk[0]), unsafe.Pointer(&sk[0]))

	zero := true
	for _, b := range pk {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		t.Error("pk all zero")
	}
	zero = true
	for _, b := range sk {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		t.Error("sk all zero")
	}
}

func TestMakeIPPort(t *testing.T) {
	ipp, err := MakeIPPort("127.0.0.1", 3389)
	if err != nil {
		t.Fatal(err)
	}
	if unsafe.Pointer(&ipp) == nil {
		t.Error("ipp nil")
	}
}

func TestTCPConnections(t *testing.T) {
	mem := OsMemory()
	rng := OsRandom()
	ns := OsNetwork()
	logger := LoggerNew(mem)
	monoT := MonoTimeNew(mem, nil, nil)
	np := NetprofNew(logger, mem)

	pk := make([]byte, 32)
	sk := make([]byte, 32)
	CryptoNewKeypair(rng, unsafe.Pointer(&pk[0]), unsafe.Pointer(&sk[0]))

	proxy := make([]byte, 256)
	conns := NewTCPConnections(logger, mem, rng, ns, monoT,
		unsafe.Pointer(&sk[0]), unsafe.Pointer(&proxy[0]), np)
	if unsafe.Pointer(conns) == nil {
		t.Fatal("NewTCPConnections nil")
	}
	KillTCPConnections(conns)
}

func TestTCPRelay(t *testing.T) {
	mem := OsMemory()
	rng := OsRandom()
	ns := OsNetwork()
	logger := LoggerNew(mem)
	monoT := MonoTimeNew(mem, nil, nil)
	np := NetprofNew(logger, mem)

	pk := make([]byte, 32)
	sk := make([]byte, 32)
	CryptoNewKeypair(rng, unsafe.Pointer(&pk[0]), unsafe.Pointer(&sk[0]))

	proxy := make([]byte, 256)
	conns := NewTCPConnections(logger, mem, rng, ns, monoT,
		unsafe.Pointer(&sk[0]), unsafe.Pointer(&proxy[0]), np)
	if unsafe.Pointer(conns) == nil {
		t.Fatal("NewTCPConnections nil")
	}
	defer KillTCPConnections(conns)

	ipp, err := MakeIPPort("43.198.227.166", 3389)
	if err != nil {
		t.Fatal(err)
	}
	relayPK := mustHexDecode("AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E")

	rc := AddTCPRelayGlobal(conns, unsafe.Pointer(&ipp), unsafe.Pointer(&relayPK[0]))
	t.Logf("AddTCPRelayGlobal = %d", rc)
}

func mustHexDecode(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := hexNibble(s[i])
		lo := hexNibble(s[i+1])
		b[i/2] = (hi << 4) | lo
	}
	return b
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return 0
	}
}
