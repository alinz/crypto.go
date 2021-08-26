package crypto

import (
	"bytes"
	"errors"
	"time"

	"github.com/alinz/hash.go"
)

var (
	ErrKeyMismatched           = errors.New("keys are mismatched")
	ErrNotCA                   = errors.New("given certificate is not a CA")
	ErrNotIssuer               = errors.New("issuer value is not the same")
	ErrFailedVerifyCertificate = errors.New("certificate is not verified by ca")
)

type CertificateDetails struct {
	NotBefore time.Time
	NotAfter  time.Time
	PublicKey PublicKey
	Issuer    []byte
	Extra     []byte
	IsCA      bool
}

type Certificate struct {
	Details   *CertificateDetails
	Signature []byte
}

func (c *Certificate) Verify(ca *Certificate) error {
	if !ca.Details.IsCA {
		return ErrNotCA
	}

	if c.Details.Issuer != nil && !bytes.Equal(c.Details.Issuer, ca.Signature) {
		return ErrNotIssuer
	}

	b, err := BinaryEncode(c.Details)
	if err != nil {
		return err
	}

	if !ca.Details.PublicKey.Verify(hash.Bytes(b), c.Signature) {
		return ErrFailedVerifyCertificate
	}

	return nil
}

func (c *Certificate) Encode() ([]byte, error) {
	var buffer bytes.Buffer

	details, err := BinaryEncode(c.Details)
	if err != nil {
		return nil, err
	}

	// because Singature is always fixed size (64), it has to be written first
	buffer.Write(c.Signature)
	buffer.Write(details)

	return buffer.Bytes(), nil
}

func (c *Certificate) Decode(b []byte) error {
	c.Signature = make([]byte, 64)
	copy(c.Signature, b[:64])

	c.Details = &CertificateDetails{}
	err := BinaryDecode(b[64:], c.Details)
	if err != nil {
		return err
	}

	return nil
}

func (c *Certificate) DecodeExtra(decoder BinaryDecoder) error {
	return decoder.Decode(c.Details.Extra)
}

// creation of certificate

type CertificateDetailsFn func(details *CertificateDetails) error

func CertWithNotBefore(notBefore time.Time) CertificateDetailsFn {
	return func(details *CertificateDetails) error {
		details.NotBefore = time.Unix(notBefore.Unix(), 0)
		return nil
	}
}

func CertWithNotAfter(notAfter time.Time) CertificateDetailsFn {
	return func(details *CertificateDetails) error {
		details.NotAfter = time.Unix(notAfter.Unix(), 0)
		return nil
	}
}

func CertWithAuthority() CertificateDetailsFn {
	return func(details *CertificateDetails) error {
		details.IsCA = true
		return nil
	}
}

func CertWithExtra(extra BinaryEncoder) CertificateDetailsFn {
	return func(details *CertificateDetails) error {
		data, err := extra.Encode()
		if err != nil {
			return err
		}
		details.Extra = data
		return nil
	}
}

func CreateCertificate(parentPrivateKey *PrivateKey, parentCertificate *Certificate, opts ...CertificateDetailsFn) (*Certificate, *PrivateKey, error) {
	parentProvided := false
	if parentPrivateKey != nil && parentCertificate != nil {
		if !IsKeysMatched(&parentCertificate.Details.PublicKey, parentPrivateKey) {
			return nil, nil, ErrKeyMismatched
		}
		parentProvided = true
	}

	details := &CertificateDetails{}

	for _, opt := range opts {
		err := opt(details)
		if err != nil {
			return nil, nil, err
		}
	}

	public, private, err := NewKeyPair()
	if err != nil {
		return nil, nil, err
	}

	details.PublicKey = *public

	if parentProvided {
		details.Issuer = parentCertificate.Signature
	}

	b, err := BinaryEncode(details)
	if err != nil {
		return nil, nil, err
	}

	var signKey *PrivateKey

	if parentProvided {
		signKey = parentPrivateKey
	} else {
		signKey = private
	}

	signature, err := signKey.Sign(hash.Bytes(b))
	if err != nil {
		return nil, nil, err
	}

	return &Certificate{
		Details:   details,
		Signature: signature,
	}, private, nil
}
