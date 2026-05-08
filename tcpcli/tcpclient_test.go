package tcpcli

import "testing"

func Test1(t *testing.T) {
	p := New("dummy.key")
	if p == nil {
		t.Fail()
	}
}
