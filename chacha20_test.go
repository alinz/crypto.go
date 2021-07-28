package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/alinz/crypto.go"
)

func TestChaCha20(t *testing.T) {

	chacha20 := crypto.NewChaCha20()

	plaintext := []byte("this is amazing")
	key := make([]byte, 32)

	var err error
	var ciphertext []byte

	t.Run("should be able to encrypt and decrypt the content", func(t *testing.T) {
		ciphertext, err = chacha20.Encrypt(plaintext, key)
		assert.NoError(t, err)
		assert.NotEqual(t, ciphertext, plaintext, "failed to encrypt plaintext, both values are the same")

		decryptedtext, err := chacha20.Decrypt(ciphertext, key)
		assert.NoError(t, err)
		assert.Equal(t, decryptedtext, plaintext, "decrypted value are not the same as plaintext")
	})

	t.Run("should be able to detect if encrypted content is tampered", func(t *testing.T) {
		ciphertext[2] = 1

		decryptedtext, err := chacha20.Decrypt(ciphertext, key)
		assert.NotNil(t, err)
		assert.NotEqual(t, decryptedtext, plaintext, "decrypted should not be the same as plaintext")
	})
}
