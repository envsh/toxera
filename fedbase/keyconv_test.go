package fedbase

import (
	"testing"
	"log"
)

func Test1(t *testing.T) {
	pk, sk := NewKeypairNostr()
	log.Println("pk", pk)
	log.Println("sk", sk)

	pk2 := SeckeyTopubTox(sk)
	log.Println("pk tox", pk2)
}
