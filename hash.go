package crypto

import "crypto/sha256"

// hashSHA256 calculates hash of given data in sha256
func hashSHA256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}
