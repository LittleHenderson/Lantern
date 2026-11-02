package store

import "testing"

func TestSave(t *testing.T) {
	s := Open(":memory:")
	n := s.Save("ann", "hi")
	if n.Text != "hi" {
		t.Fatal("bad text")
	}
}
