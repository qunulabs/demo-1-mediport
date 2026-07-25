package auth

import (
	"fmt"
	"math/rand"
)

// SessionToken mints the value that identifies a logged-in session.
//
// PLANTED WEAKNESS: it comes from math/rand, a deterministic PRNG that is not
// cryptographically secure, so session tokens are predictable.
//
// The random value is assigned to a variable named `token` on purpose. A scanner
// cannot prove from the AST alone that any given math/rand call is
// security-sensitive, so qshield's GO-INSECURE-RANDOM rule looks for the value
// flowing into a crypto sink: a sink-named variable (key / token / nonce / iv /
// salt / ...) or a rand.Read filling a byte buffer. Inlining the call into the
// Sprintf, as this used to, leaves the weakness real and the scan silent - which
// is the gap the round-2 end-to-end test measured. Keep the assignment.
func SessionToken() string {
	token := rand.Int63()
	return fmt.Sprintf("%x", token)
}
