package crypto_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/alinz/crypto.go"
)

func TestCertificate(t *testing.T) {
	now := time.Now()
	oneDay := now.Add(24 * time.Hour)
	rootCert, rootPrivate, err := crypto.CreateCertificate(
		nil,
		nil,
		crypto.CertWithAuthority(),
		crypto.CertWithNotBefore(now),
		crypto.CertWithNotAfter(oneDay),
	)
	assert.NoError(t, err)

	t.Run("check serialize and deserialize certificate", func(t *testing.T) {
		b, err := rootCert.Encode()
		assert.NoError(t, err)

		result := &crypto.Certificate{}

		err = result.Decode(b)
		assert.NoError(t, err)

		assert.Equal(t, result, rootCert)
	})

	t.Run("create intermidate certificate", func(t *testing.T) {
		interCert, _, err := crypto.CreateCertificate(
			rootPrivate,
			rootCert,
			crypto.CertWithAuthority(),
			crypto.CertWithNotBefore(now),
			crypto.CertWithNotAfter(oneDay),
		)
		assert.NoError(t, err)

		assert.NoError(t, interCert.Verify(rootCert))
	})

	t.Run("create certificate", func(t *testing.T) {
		interCert, interPrivate, err := crypto.CreateCertificate(
			rootPrivate,
			rootCert,
			crypto.CertWithAuthority(),
			crypto.CertWithNotBefore(now),
			crypto.CertWithNotAfter(oneDay),
		)
		assert.NoError(t, err)

		cert, _, err := crypto.CreateCertificate(
			interPrivate,
			interCert,
			crypto.CertWithNotBefore(now),
			crypto.CertWithNotAfter(oneDay),
		)

		assert.NoError(t, err)

		assert.NoError(t, cert.Verify(interCert))
	})

	t.Run("checking if PEM encoding working", func(t *testing.T) {
		var buffer bytes.Buffer

		err := crypto.EncodePEM(&buffer, rootCert, "TEST", nil)
		assert.NoError(t, err)

		result := &crypto.Certificate{}
		err = crypto.DecodePEM(&buffer, result, "TEST", nil)
		assert.NoError(t, err)

		assert.Equal(t, rootCert, result)
	})
}
