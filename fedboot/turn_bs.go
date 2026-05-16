//go:build turn

package fedboot

import (
	// "context"
	// "encoding/hex"
	// "flag"
	// "fmt"
	// "log"
	// "time"

	// "github.com/envsh/toxera/fedkey"
	// "github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/p2p"
	// "github.com/ethereum/go-ethereum/p2p/nat"
	// "github.com/ethereum/go-ethereum/p2p/enode"
)

////////////

type Turn struct {

}

var _ = regme(&Turn{})

func (o *Turn) Start() error {
	return nil
}

func (o *Turn) Stop() error {
	return nil
}

func (o *Turn) Info() string {
	return "{}"
}

func MainTurn() {
	mainTurn()
}

//////


func mainTurn() {
}
