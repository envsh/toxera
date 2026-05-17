package p2put

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"path/filepath"
)

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
	myinstall("index", onIndex)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func onBoard(w http.ResponseWriter, r *http.Request) {
	resp, err := CollectBoard()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, resp)
}

func onDHT(w http.ResponseWriter, r *http.Request) {
	resp, err := CollectDHT()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, resp)
}

func onRelays(w http.ResponseWriter, r *http.Request) {
	resp, err := CollectRelays()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, resp)
}

func onPeers(w http.ResponseWriter, r *http.Request) {
	resp, err := CollectConns()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, resp)
}

func onConns(w http.ResponseWriter, r *http.Request) {
	resp, err := CollectConns()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, resp)
}

func onIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

//go:embed index.html
var indexHTML string

