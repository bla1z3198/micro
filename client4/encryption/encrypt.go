package encryption

import (
	"crypto/sha256"

	"golang.org/x/crypto/chacha20"
)

func Secret(password string) [32]byte {
	hash := sha256.Sum256([]byte(password))
	return hash
}

func Encrypt(dst []byte, data []byte, hash [32]byte, nonce []byte) {
	cipherInstance, _ := chacha20.NewUnauthenticatedCipher(hash[:], nonce)
	cipherInstance.XORKeyStream(dst, data)
}
