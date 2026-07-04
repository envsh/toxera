//go:build windows

package fedkey

import (
	"log"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	toxcoreHandle windows.Handle
	loadOnce      sync.Once
	loadErr       error
)

func loadToxcore() error {
	loadOnce.Do(func() {
		toxcoreHandle, loadErr = windows.LoadLibrary("toxcore.dll")
	})
	return loadErr
}

func Dlsym0(name string) unsafe.Pointer {
	if err := loadToxcore(); err != nil {
		log.Println("failed to load toxcore.dll:", err)
		return nil
	}
	addr, err := windows.GetProcAddress(toxcoreHandle, name)
	if err != nil {
		log.Println(err)
		return nil
	}
	return unsafe.Pointer(addr)
}
