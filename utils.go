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
