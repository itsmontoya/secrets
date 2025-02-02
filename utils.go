package secrets

import (
	"crypto/aes"
	"crypto/rand"
	"io"
)

var makeIV func() ([]byte, error) = makeIVFromCrypto

func makeIVFromCrypto() (iv []byte, err error) {
	// Generate a random initialization vector (IV)
	iv = make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	return
}

// Function to ensure the key is 16 bytes long for AES-128
func getKeyBytes(key string) []byte {
	keyBytes := []byte(key)
	if len(keyBytes) != 16 {
		// You can truncate or pad the key if necessary, but AES-128 requires 16 bytes
		keyBytes = append(keyBytes, make([]byte, 16-len(keyBytes))...)
	}
	return keyBytes
}
