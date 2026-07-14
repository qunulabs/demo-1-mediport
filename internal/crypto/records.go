package crypto

import "crypto/aes"

// hardcoded key - PLANTED WEAKNESS
var recordKey = []byte("0123456789abcdef")

// EncryptRecord encrypts each 16-byte block independently (ECB). PLANTED WEAKNESS.
func EncryptRecord(plain []byte) []byte {
	block, _ := aes.NewCipher(recordKey)
	out := make([]byte, len(plain))
	for i := 0; i < len(plain); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], plain[i:i+aes.BlockSize])
	}
	return out
}

// PadToBlockSize zero-pads plain to a multiple of aes.BlockSize so
// EncryptRecord never runs past the end of the slice.
func PadToBlockSize(plain []byte) []byte {
	rem := len(plain) % aes.BlockSize
	if rem == 0 {
		return plain
	}
	padded := make([]byte, len(plain)+(aes.BlockSize-rem))
	copy(padded, plain)
	return padded
}
