package p2put

import (
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
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
	myinstall("kv", onKV)
	myinstall("index", onIndex)
	myinstall("events", onEvents)
	myinstall("send", onSend)
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

func onKV(w http.ResponseWriter, r *http.Request) {
	op := r.URL.Query().Get("op")
	key := r.URL.Query().Get("key")
	if key == "" {
		writeErr(w, http.StatusBadRequest, "missing key")
		return
	}

	switch r.Method {
	case http.MethodGet:
		switch op {
		case "get":
			val, err := GetKV(r.Context(), key)
			if err != nil {
				writeErr(w, http.StatusNotFound, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(val)
		case "delete":
			if err := DelKV(r.Context(), key); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, map[string]bool{"ok": true})
		default:
			writeErr(w, http.StatusBadRequest, "unknown op: "+op)
		}
	case http.MethodPost:
		if op != "put" {
			writeErr(w, http.StatusBadRequest, "unknown op: "+op)
			return
		}
		val, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := PutKV(r.Context(), key, val); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

//go:embed index.html
var indexHTML string

func onEvents(w http.ResponseWriter, r *http.Request) {
	topicStr := r.URL.Query().Get("topic")
	var topics []string
	if topicStr != "" {
		for _, t := range strings.Split(topicStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				topics = append(topics, t)
				go getOrSubscribeTopic(t)
			}
		}
	}

	ch := make(chan Event, 20)
	clientsMu.Lock()
	clients[ch] = struct{}{}
	if len(topics) > 0 {
		clientTopics[ch] = topics
	}
	clientsMu.Unlock()
	defer func() {
		clientsMu.Lock()
		delete(clients, ch)
		delete(clientTopics, ch)
		clientsMu.Unlock()
		close(ch)
	}()

	var events []Event
	collectDeadline := time.Now().Add(60 * time.Millisecond)

	for len(events) < 20 {
		remaining := collectDeadline.Sub(time.Now())
		if remaining <= 0 {
			break
		}
		select {
		case evt := <-ch:
			events = append(events, evt)
		case <-time.After(remaining):
			goto output
		case <-r.Context().Done():
			return
		}
	}

output:
	if len(events) > 0 {
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, e := range events {
			json.NewEncoder(w).Encode(e)
		}
		return
	}

	select {
	case evt := <-ch:
		w.Header().Set("Content-Type", "application/x-ndjson")
		json.NewEncoder(w).Encode(evt)
	case <-time.After(30 * time.Second):
		w.Header().Set("Content-Type", "application/x-ndjson")
		json.NewEncoder(w).Encode(map[string]string{"event": "timeout"})
	case <-r.Context().Done():
	}
}

func onSend(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Query().Get("topic")
	if topic == "" {
		writeErr(w, http.StatusBadRequest, "missing topic")
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(maxPublishSize)+1))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	if err := PublishTopic(topic, data); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

