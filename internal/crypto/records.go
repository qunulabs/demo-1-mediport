package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// recordKey is the AES key patient records are encrypted under.
//
// PLANTED WEAKNESS: hardcoded key material in source. Anyone who can read the
// repository can decrypt every record in the database.
var recordKey = []byte("0123456789abcdef")

// EncryptRecord encrypts a patient record for storage.
//
// PLANTED WEAKNESS: AES-CBC under the hardcoded key above with a CONSTANT IV.
// One fixed IV reused for every record means identical plaintexts produce
// identical ciphertexts, which leaks equality and structure across the whole
// table and destroys CBC's security argument.
//
// This deliberately replaced a hand-rolled ECB loop (block.Encrypt called once
// per block). ECB was the more egregious mistake, but Go has no ECB API - it is
// written by driving the raw block cipher - and qshield's Go rule set has no rule
// for that shape, so the round-2 test found the demo narrating a weakness the
// repository scan could not see. A constant-IV CBC is a real, equally
// demonstrable misuse that GO-STATIC-IV-NONCE reports as High today.
//
// The IV must stay INLINE in the constructor call. The rule proves constancy
// syntactically (a []byte("...") conversion, a []byte{...} literal, or a zeroed
// make), so hoisting it into a variable puts it past what an AST-only pass can
// prove and the finding disappears again.
func EncryptRecord(plain []byte) []byte {
	block, _ := aes.NewCipher(recordKey)
	out := make([]byte, len(plain))
	mode := cipher.NewCBCEncrypter(block, []byte("mediport-demo-iv"))
	mode.CryptBlocks(out, plain)
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
