package crypto

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

var ErrWrongFormat = errors.New("wrong format")

type PublicKey struct {
	verifiedKey ed25519.PublicKey
	key         []byte
}

func (p *PublicKey) GobEncode() ([]byte, error) {
	return p.Encode()
}

func (p *PublicKey) GobDecode(b []byte) error {
	return p.Decode(b)
}

func (p *PublicKey) Verify(data []byte, signature []byte) bool {
	return ed25519.Verify(p.verifiedKey, data, signature)
}

func (p *PublicKey) Encode() ([]byte, error) {
	var buffer bytes.Buffer

	buffer.Write(p.key)
	buffer.Write(p.verifiedKey)

	return buffer.Bytes(), nil
}

func (p *PublicKey) Decode(b []byte) error {
	if len(b) != 64 {
		return ErrWrongFormat
	}

	p.key = make([]byte, 32)
	copy(p.key, b[:32])
	p.verifiedKey = make([]byte, 32)
	copy(p.verifiedKey, b[32:])

	return nil
}

type PrivateKey struct {
	signedKey ed25519.PrivateKey
	key       []byte
}

func (p *PrivateKey) SharedKey(public *PublicKey) ([]byte, error) {
	return curve25519.X25519(p.key, public.key)
}

func (p *PrivateKey) Sign(data []byte) ([]byte, error) {
	signature, err := p.signedKey.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (p *PrivateKey) Encode() ([]byte, error) {
	var buffer bytes.Buffer

	buffer.Write(p.key)
	buffer.Write(p.signedKey)

	return buffer.Bytes(), nil
}

func (p *PrivateKey) Decode(b []byte) error {
	if len(b) != 96 {
		return ErrWrongFormat
	}

	p.key = make([]byte, 32)
	copy(p.key, b[:32])
	p.signedKey = make([]byte, 64)
	copy(p.signedKey, b[32:])

	return nil
}

func NewKeyPair() (*PublicKey, *PrivateKey, error) {
	publicKey := &PublicKey{}
	privateKey := &PrivateKey{}

	{
		public, private, err := newX25519Keys()
		if err != nil {
			return nil, nil, err
		}

		publicKey.key = public
		privateKey.key = private
	}

	{
		public, private, err := newEd25519Keys()
		if err != nil {
			return nil, nil, err
		}

		publicKey.verifiedKey = public
		privateKey.signedKey = private
	}

	return publicKey, privateKey, nil
}

func newX25519Keys() ([]byte, []byte, error) {
	var publicKey, privateKey [32]byte
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return nil, nil, err
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey[:], privateKey[:], nil
}

func newEd25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// IsKeysMatched checks whether both public and private key are belong to each other
func IsKeysMatched(public *PublicKey, private *PrivateKey) bool {
	sampleContent := []byte("sample")

	signature, err := private.Sign(sampleContent)
	if err != nil {
		return false
	}

	return public.Verify(sampleContent, signature)
}
