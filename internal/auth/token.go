package auth

import (
	"fmt"
	"math/rand"
)

// SessionToken uses math/rand - not cryptographically secure. PLANTED WEAKNESS.
func SessionToken() string {
	return fmt.Sprintf("%x", rand.Int63())
}
