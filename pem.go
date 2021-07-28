package crypto

import (
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
)

var (
	ErrPemBannerNotFound  = errors.New("pem banner not found")
	ErrPemIncorrectFormat = errors.New("pem incurrent format")
)

func EncodePEM(w io.Writer, encoder BinaryEncoder, banner string, passphrase []byte) error {
	b, err := encoder.Encode()
	if err != nil {
		return err
	}

	if passphrase != nil {
		b, err = ChaCha20{}.Encrypt(b, passphrase)
		if err != nil {
			return err
		}
	}

	block := &pem.Block{
		Type:  banner,
		Bytes: b,
	}

	return pem.Encode(w, block)
}

func DecodePEM(r io.Reader, decoder BinaryDecoder, banner string, passphrase []byte) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	var block *pem.Block
	var privateKey []byte

	for {
		block, data = pem.Decode(data)
		if block == nil || privateKey != nil {
			break
		}

		switch block.Type {
		case banner:
			privateKey = block.Bytes
		}
	}

	if privateKey == nil {
		return ErrPemBannerNotFound
	}

	if passphrase != nil {
		privateKey, err = ChaCha20{}.Decrypt(privateKey, passphrase)
		if err != nil {
			return err
		}
	}

	return decoder.Decode(privateKey)
}
