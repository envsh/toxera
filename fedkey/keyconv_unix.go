//go:build !windows

package fedkey

import (
	"log"
	"unsafe"

	"github.com/ebitengine/purego"
)

func Dlsym0(name string) unsafe.Pointer {
	ptr, err := purego.Dlsym(purego.RTLD_DEFAULT, name)
	if err != nil {
		log.Println(err)
		return nil
	}
	return *(*unsafe.Pointer)(unsafe.Pointer(&ptr))
}
