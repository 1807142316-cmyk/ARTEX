package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// secretBox seals short secrets (proxy URLs, shell credentials) with AES-256-GCM.
//
// It exists because the proxy pool and the C2/WebShell adapters used to carry
// their own copy of the same cipher code, both keyed straight off the JWT
// signing key. Reusing a signing key as an encryption key is a bad habit: one
// leak then compromises both. The new derivation keeps them separate via a
// domain-separation prefix, and open() still falls back to the old derivation so
// rows sealed before this change keep opening.
type secretBox struct {
	key       []byte // current, domain-separated
	legacyKey []byte // pre-change derivation, kept only to open old rows
}

// secretKeyPrefix is hashed together with jwtKey to derive the box key. Change it
// only with a new fallback chain; existing seals depend on the current value.
const secretKeyPrefix = "artex-secretbox-v1\x00"

// derivedSecretKey returns the 32-byte AES key. legacy selects the pre-existing
// derivation (plain sha256 of the JWT key) which must stay stable forever.
func derivedSecretKey(jwtKey []byte, legacy bool) []byte {
	if legacy {
		sum := sha256.Sum256(jwtKey)
		return sum[:]
	}
	hasher := sha256.New()
	hasher.Write([]byte(secretKeyPrefix))
	hasher.Write(jwtKey)
	return hasher.Sum(nil)
}

func newSecretBox(jwtKey []byte) *secretBox {
	return &secretBox{key: derivedSecretKey(jwtKey, false), legacyKey: derivedSecretKey(jwtKey, true)}
}

func secretAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts raw with the current derivation.
func (b *secretBox) seal(raw string) (string, error) {
	a, err := secretAEAD(b.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(a.Seal(nonce, nonce, []byte(raw), nil)), nil
}

// open decrypts with the current derivation and falls back to the legacy one, so
// values written before the derivation changed stay readable.
func (b *secretBox) open(sealed string) (string, error) {
	data, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil {
		return "", err
	}
	current, currentErr := secretOpen(data, b.key)
	if currentErr == nil {
		return current, nil
	}
	if legacy, legacyErr := secretOpen(data, b.legacyKey); legacyErr == nil {
		return legacy, nil
	}
	return "", currentErr
}

func secretOpen(data, key []byte) (string, error) {
	a, err := secretAEAD(key)
	if err != nil {
		return "", err
	}
	if len(data) < a.NonceSize() {
		return "", errors.New("invalid sealed secret")
	}
	plain, err := a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
