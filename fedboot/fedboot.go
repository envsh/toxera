package fedboot

import (
	"reflect"
	"log"
)

func init() {
	flags := log.Flags()
	flags |= log.Lshortfile
	flags ^= log.Ldate
	log.SetFlags(flags)
}

type Instance interface {
	Start() error
	Stop() error
	Info() string // json
}

type Pool struct {
	insts map[string]Instance // protocol =>
}

var gp = &Pool{insts:make(map[string]Instance)}

func regme(inst Instance) int {
	tyobj := reflect.TypeOf(inst)
	tystr := tyobj.String()

	gp.insts[tystr] = inst
	return 0
}

func List() map[string]Instance {
	return gp.insts
}
