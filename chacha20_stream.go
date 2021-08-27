package crypto

import (
	"crypto/cipher"
	"io"

	"golang.org/x/crypto/chacha20"
)

type ChaCha20Stream struct {
	source io.Reader
	stream cipher.Stream
}

func (cs *ChaCha20Stream) Read(p []byte) (int, error) {
	n, err := cs.source.Read(p)
	if err != nil {
		return n, err
	}

	if n == 0 || err == io.EOF {
		return n, io.EOF
	}

	cs.stream.XORKeyStream(p[:n], p[:n])
	return n, nil
}

func NewChaCha20Stream(r io.Reader, key []byte) (*ChaCha20Stream, error) {
	nonce := make([]byte, 24)

	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}

	return &ChaCha20Stream{
		source: r,
		stream: stream,
	}, nil
}
