package cipher

import "crypto/cipher"

type Cipher interface {
	Name() string
	NewEncryptionContext() (keyMaterial []byte, stream cipher.Stream, err error)
	LoadDecryptionContext(keyMaterial []byte) (stream cipher.Stream, err error)
}