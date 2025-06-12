package cipher

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

const publicKeySize = 32

type EcdhChaCha20 struct {
	serverPublicKey  *ecdh.PublicKey
	serverPrivateKey *ecdh.PrivateKey
}

func NewEcdhChaCha20WithPublicKey(pubKeyBytes []byte) (*EcdhChaCha20, error) {
	curve := ecdh.X25519()
	serverPublicKey, err := curve.NewPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	return &EcdhChaCha20{serverPublicKey: serverPublicKey}, nil
}

func NewEcdhChaCha20WithPrivateKey(privKeyBytes []byte) (*EcdhChaCha20, error) {
	curve := ecdh.X25519()
	serverPrivateKey, err := curve.NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	return &EcdhChaCha20{serverPrivateKey: serverPrivateKey}, nil
}

func GenerateEcdhKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return priv, priv.PublicKey(), nil
}

func (c *EcdhChaCha20) Name() string {
	return "ecdh-chacha20"
}

func (c *EcdhChaCha20) NewEncryptionContext() ([]byte, cipher.Stream, error) {
	ephemeralPriv, ephemeralPub, err := GenerateEcdhKeyPair()
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := ephemeralPriv.ECDH(c.serverPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	keySum := sha256.Sum256(sharedSecret)
	nonceSum := sha256.Sum256(keySum[:])
	key, nonce := keySum[:], nonceSum[:12]

	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create chacha20 cipher: %w", err)
	}

	return ephemeralPub.Bytes(), stream, nil
}

func (c *EcdhChaCha20) LoadDecryptionContext(keyMaterial []byte) (cipher.Stream, error) {
	if c.serverPrivateKey == nil {
		return nil, fmt.Errorf("cipher is not configured with a private key for decryption")
	}

	ephemeralPubKey, err := ecdh.X25519().NewPublicKey(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key from metadata: %w", err)
	}

	sharedSecret, err := c.serverPrivateKey.ECDH(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret for decryption: %w", err)
	}

	keySum := sha256.Sum256(sharedSecret)
	nonceSum := sha256.Sum256(keySum[:])
	key, nonce := keySum[:], nonceSum[:12]

	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create chacha20 cipher for decryption: %w", err)
	}

	return stream, nil
}