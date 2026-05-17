package main

import (

	"net/http"

	"github.com/envsh/toxera/p2put"

)

func main() {
	cfg := p2put.DefaultConfig()
	cfg.Dht = false
	_ = cfg

	go p2put.MainLibp2p()
	p2put.InstallRestHandler("/p2pin", nil)
	http.ListenAndServe(":4004", nil)
}
