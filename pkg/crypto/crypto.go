package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// ValidateEd25519Pub validates that a byte slice is a valid Ed25519 public key (32 bytes)
func ValidateEd25519Pub(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key size")
	}
	return nil
}

// ValidateX25519Pub validates that a byte slice is a valid X25519 public key (32 bytes)
func ValidateX25519Pub(pub []byte) error {
	if len(pub) != 32 {
		return errors.New("invalid X25519 public key size")
	}
	return nil
}

// DecodeBase64Key decodes a base64-encoded key
func DecodeBase64Key(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodeBase64Key encodes a key to base64
func EncodeBase64Key(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// GenerateX25519KeyPair generates a new X25519 key pair for prekeys
func GenerateX25519KeyPair() (publicKey, privateKey []byte, err error) {
	privateKeyBytes := make([]byte, 32)
	if _, err := rand.Read(privateKeyBytes); err != nil {
		return nil, nil, err
	}
	var privateKeyArr [32]byte
	copy(privateKeyArr[:], privateKeyBytes)
	
	var publicKeyArr [32]byte
	curve25519.ScalarBaseMult(&publicKeyArr, &privateKeyArr)
	
	return publicKeyArr[:], privateKeyArr[:], nil
}

