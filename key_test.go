package crypto_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/alinz/crypto.go"
)

func TestEncodeDecodeKey(t *testing.T) {
	bannerName := "AWESOME"

	public, private, err := crypto.NewKeyPair()
	assert.NoError(t, err)

	t.Run("should encode and decode public key in bytes", func(t *testing.T) {
		encoded, err := public.Encode()
		assert.NoError(t, err)

		result := &crypto.PublicKey{}

		err = result.Decode(encoded)
		assert.NoError(t, err)

		assert.Equal(t, public, result)
	})

	t.Run("should encode and decode public key in PEM format", func(t *testing.T) {
		var buffer bytes.Buffer
		var err error

		err = crypto.EncodePEM(&buffer, public, bannerName, nil)
		assert.NoError(t, err)

		result := &crypto.PublicKey{}

		err = crypto.DecodePEM(&buffer, result, bannerName, nil)
		assert.NoError(t, err)

		assert.EqualValues(t, public, result)
	})

	t.Run("should encode and decode private key in PEM format", func(t *testing.T) {
		var buffer bytes.Buffer

		err := crypto.EncodePEM(&buffer, private, bannerName, nil)
		assert.NoError(t, err)

		result := &crypto.PrivateKey{}

		err = crypto.DecodePEM(&buffer, result, bannerName, nil)
		assert.NoError(t, err)

		assert.Equal(t, private, result)
	})

	t.Run("should encode and decode private key with passphrase in PEM format", func(t *testing.T) {
		var buffer bytes.Buffer

		key := make([]byte, 32)

		err := crypto.EncodePEM(&buffer, private, bannerName, key)
		assert.NoError(t, err)

		result := &crypto.PrivateKey{}

		err = crypto.DecodePEM(&buffer, result, bannerName, key)
		assert.NoError(t, err)

		assert.Equal(t, private, result)
	})

	t.Run("should encode and failed to decode because of wrong passphrase", func(t *testing.T) {
		var buffer bytes.Buffer

		key := make([]byte, 32)

		err := crypto.EncodePEM(&buffer, private, bannerName, key)
		assert.NoError(t, err)

		result := &crypto.PrivateKey{}

		key[0] = 1 // changed the key

		err = crypto.DecodePEM(&buffer, result, bannerName, key)
		assert.Error(t, err)
	})

	t.Run("should encode and decode private key in bytes", func(t *testing.T) {
		encoded, err := private.Encode()
		assert.NoError(t, err)

		result := &crypto.PrivateKey{}

		err = result.Decode(encoded)
		assert.NoError(t, err)

		assert.Equal(t, private, result)
	})

	t.Run("should sign and verify the content", func(t *testing.T) {
		message1 := []byte("hello world")
		message2 := []byte("byte world")

		signature, err := private.Sign(message1)
		assert.NoError(t, err)

		assert.True(t, public.Verify(message1, signature))
		assert.False(t, public.Verify(message2, signature))
	})

	t.Run("should generate the same shared key", func(t *testing.T) {
		pub1, priv1, err := crypto.NewKeyPair()
		assert.NoError(t, err)
		pub2, priv2, err := crypto.NewKeyPair()
		assert.NoError(t, err)

		sharedKey1, err := priv1.SharedKey(pub2)
		assert.NoError(t, err)

		sharedKey2, err := priv2.SharedKey(pub1)
		assert.NoError(t, err)

		assert.Equal(t, sharedKey1, sharedKey2)
	})
}

func TestIsKeysMatched(t *testing.T) {
	public1, private1, err := crypto.NewKeyPair()
	assert.NoError(t, err)

	public2, private2, err := crypto.NewKeyPair()
	assert.NoError(t, err)

	assert.True(t, crypto.IsKeysMatched(public1, private1))
	assert.False(t, crypto.IsKeysMatched(public1, private2))
	assert.False(t, crypto.IsKeysMatched(public2, private1))
	assert.True(t, crypto.IsKeysMatched(public2, private2))
}
