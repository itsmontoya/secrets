package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

// Encrypt function which generates a random IV and prepends it to the ciphertext
func encrypt(in []byte, key string) (out string, err error) {
	if len(in) == 0 {
		return
	}

	// Create AES cipher
	var block cipher.Block
	keyBS := getKeyBytes(key)
	if block, err = aes.NewCipher(keyBS); err != nil {
		return
	}

	var iv []byte
	if iv, err = makeIV(); err != nil {
		return
	}

	// Create a slice for the ciphertext, starting with the IV
	cipherText := make([]byte, aes.BlockSize+len(in))

	// Prepend the IV to the ciphertext
	copy(cipherText[:aes.BlockSize], iv)

	// Encrypt the data using the IV
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], in)

	// Return encrypted text as a hex string, which includes the IV
	out = hex.EncodeToString(cipherText)
	return
}

// Decrypt function which extracts the IV from the ciphertext and decrypts the rest
func decrypt(in string, key string) (out []byte, err error) {
	// Decode the hex string to get the ciphertext
	cipherText, err := hex.DecodeString(in)
	if err != nil {
		return
	}

	// Create AES cipher
	var block cipher.Block
	keyBS := getKeyBytes(key)
	if block, err = aes.NewCipher(keyBS); err != nil {
		return
	}

	// Ensure the ciphertext is long enough to contain the IV
	if len(cipherText) < aes.BlockSize {
		err = fmt.Errorf("ciphertext too short, expected a minimum size of %d and received a size of %d", aes.BlockSize, len(cipherText))
		return
	}

	// Extract the IV from the ciphertext (first BlockSize bytes)
	iv := cipherText[:aes.BlockSize]

	// Decrypt the data
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], cipherText[aes.BlockSize:])

	// Return the decrypted text as a string
	out = cipherText[aes.BlockSize:]
	return
}
