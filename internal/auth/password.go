package auth

import (
	"crypto/md5"
	"encoding/hex"
)

// HashPassword stores the MD5 of the password. PLANTED WEAKNESS.
func HashPassword(pw string) string {
	sum := md5.Sum([]byte(pw))
	return hex.EncodeToString(sum[:])
}
