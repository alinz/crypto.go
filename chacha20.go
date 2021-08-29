package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrChiperTextTooShort if content length is too short for decoding
	ErrChiperTextTooShort = errors.New("ciphertext too short")
	// ErrWrongKey is returns when decrypting content is failing
	ErrWrongKey = errors.New("wrong key")
)

// ChaCha20 enecryption type
type ChaCha20 struct{}

func (c ChaCha20) prepareKey(key []byte) (cipher.AEAD, int, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, 0, err
	}
	return aead, aead.NonceSize(), nil
}

func secureRandom(value []byte) error {
	_, err := rand.Read(value)
	if err != nil {
		return err
	}
	return nil
}

// Encrypt encrypts data using given key
func (c ChaCha20) Encrypt(data []byte, key []byte) ([]byte, error) {
	aead, nonceSize, err := c.prepareKey(key)
	if err != nil {
		return nil, err
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, nonceSize, nonceSize+len(data)+aead.Overhead())
	if err = secureRandom(nonce); err != nil {
		return nil, err
	}

	// Encrypt the message and append the ciphertext to the nonce.
	return aead.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts data using given key
func (c ChaCha20) Decrypt(data []byte, key []byte) ([]byte, error) {
	aead, nonceSize, err := c.prepareKey(key)
	if err != nil {
		return nil, err
	}

	if len(data) < nonceSize {
		return nil, ErrChiperTextTooShort
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		if err.Error() == "chacha20poly1305: message authentication failed" {
			return nil, ErrWrongKey
		}
		return nil, err
	}

	return plaintext, nil
}

// NewChaCha20 creates chacha20 encryption
func NewChaCha20() *ChaCha20 {
	return &ChaCha20{}
}
