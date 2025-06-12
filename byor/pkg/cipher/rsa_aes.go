package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	aesKeySize = 32
	ivSize     = aes.BlockSize
	rsaKeySize = 2048
)

type RsaAes struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeySize)
}

func NewRsaAesWithPublicKey(pubKeyBytes []byte) (*RsaAes, error) {
	block, _ := pem.Decode(pubKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}
	return &RsaAes{publicKey: rsaPub}, nil
}

func NewRsaAesWithPrivateKey(privKeyBytes []byte) (*RsaAes, error) {
	block, _ := pem.Decode(privKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return &RsaAes{privateKey: priv}, nil
}

func (c *RsaAes) Name() string {
	return "rsa-aes"
}

func (c *RsaAes) NewEncryptionContext() ([]byte, cipher.Stream, error) {
	aesKey := make([]byte, aesKeySize)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	encryptedAesKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.publicKey, aesKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	stream := cipher.NewCTR(block, iv)

	keyMaterial := append(encryptedAesKey, iv...)
	return keyMaterial, stream, nil
}

func (c *RsaAes) LoadDecryptionContext(keyMaterial []byte) (cipher.Stream, error) {
	if c.privateKey == nil {
		return nil, fmt.Errorf("cipher is not configured with a private key for decryption")
	}

	rsaKeyBytes := c.privateKey.PublicKey.Size()
	if len(keyMaterial) != rsaKeyBytes+ivSize {
		return nil, fmt.Errorf("invalid key material size: expected %d, got %d", rsaKeyBytes+ivSize, len(keyMaterial))
	}
	encryptedAesKey := keyMaterial[:rsaKeyBytes]
	iv := keyMaterial[rsaKeyBytes:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privateKey, encryptedAesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher for decryption: %w", err)
	}

	return cipher.NewCTR(block, iv), nil
}