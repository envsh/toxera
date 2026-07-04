package fedkey

import (
	"encoding/hex"
	"strings"
	"log"

	// "fiatjaf.com/nostr"
	"github.com/nbd-wtf/go-nostr"
	"github.com/ebitengine/purego"
)

/*
   #cgo LDFLAGS: -ltoxcore
*/
// import "C"

func SeckeyTopubNostr(hexsk string) string {
	// keyobj := nostr.SecretKeyFromHex(hexsk)
	// pk := keyobj.Public()
	// return pk

	pk, err := nostr.GetPublicKey(hexsk)
	if err != nil { panic(err) }
	return pk
}

func NewKeypairNostr() (string,string) {
	sk := nostr.GeneratePrivateKey()
	return SeckeyTopubNostr(sk), sk
}
func NewKeypairTox() (string,string) {
	// pkb := make([]byte, 32)
	// skb := make([]byte, 32)

	return "", ""
}

func SeckeyTopubTox(hexsk string) string {
	// crypto_scalarmult_base(pk, sk)
	// crypto_derive_public_key(pk, sk)

	skb, err := hex.DecodeString(hexsk)
	if err != nil { panic(err) }
	pkb := make([]byte, len(skb))


	var fnobj func(*byte, *byte)
	fnptr := Dlsym0("crypto_derive_public_key")
	if fnptr != nil {
		purego.RegisterFunc(&fnobj, uintptr(fnptr))
		fnobj(&pkb[0], &skb[0])
	} else {
		fnptr = Dlsym0("crypto_scalarmult_base")
		if fnptr != nil {
			purego.RegisterFunc(&fnobj, uintptr(fnptr))
			fnobj(&pkb[0], &skb[0])
		}
	}
	if fnptr == nil {
		log.Println("maybe toxcore not linked", fnptr)
		return ""
	}

	pk := hex.EncodeToString(pkb)
	return strings.ToUpper(pk)
}
