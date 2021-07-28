package crypto

import (
	"bytes"
	"encoding/gob"
)

type BinaryEncoder interface {
	Encode() ([]byte, error)
}

type BinaryDecoder interface {
	Decode(b []byte) error
}

func BinaryEncode(value interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(value)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func BinaryDecode(b []byte, ptr interface{}) error {
	return gob.NewDecoder(bytes.NewReader(b)).Decode(ptr)
}
