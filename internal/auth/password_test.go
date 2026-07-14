package auth

import "testing"

func TestHashPasswordDeterministic(t *testing.T) {
	if HashPassword("x") != HashPassword("x") {
		t.Fatal("not deterministic")
	}
}
