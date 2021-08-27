package crypto_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/alinz/crypto.go"
	"github.com/stretchr/testify/assert"
)

func TestChaCha20Stream(t *testing.T) {
	content := []byte("hello world")
	size := int64(len(content))
	key := make([]byte, 32)

	r := bytes.NewReader(content)

	encryptor, err := crypto.NewChaCha20Stream(r, key)
	assert.NoError(t, err)

	cipher := &bytes.Buffer{}

	n, err := io.Copy(cipher, encryptor)
	assert.NoError(t, err)
	assert.Equal(t, size, n)

	fmt.Printf("%x\n", cipher.Bytes())

	cipher = bytes.NewBuffer(cipher.Bytes())
	decryptor, err := crypto.NewChaCha20Stream(cipher, key)
	assert.NoError(t, err)

	plain := &bytes.Buffer{}
	n, err = io.Copy(plain, decryptor)
	assert.NoError(t, err)
	assert.Equal(t, size, n)

	assert.Equal(t, content, plain.Bytes())
}
