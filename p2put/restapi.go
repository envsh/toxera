package p2put


import (
	"net/http"
	"path/filepath"
)

// mux can nil, then http.DefaultServemux
func InstallRestHandler(path string, mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	myinstall := func(name string, f func(w http.ResponseWriter, r *http.Request)) {
		uri := filepath.Join(path, name)
		mux.HandleFunc(uri, f)
	}
	myinstall("board", onBoard)
	myinstall("relays", onRelays)
	myinstall("dht", onDHT)
	myinstall("conns", onConns)
	myinstall("peers", onPeers)

}

func onBoard(w http.ResponseWriter, r *http.Request) {

}
func onDHT(w http.ResponseWriter, r *http.Request) {

}
func onRelays(w http.ResponseWriter, r *http.Request) {

}

func onPeers(w http.ResponseWriter, r *http.Request) {

}
func onConns(w http.ResponseWriter, r *http.Request) {

}
