package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// legacySeal reproduces the derivation that shipped before the shared helper:
// sha256(jwtKey) with no domain separation. Existing rows in proxy_endpoints and
// connection_adapters were written with it, so opening must keep working.
func legacySeal(t *testing.T, jwtKey []byte, raw string) string {
	t.Helper()
	key := sha256.Sum256(jwtKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return base64.RawStdEncoding.EncodeToString(a.Seal(nonce, nonce, []byte(raw), nil))
}

// TestSecretBoxOpensLegacySealedValuesAndRoundTripsNewOnes pins the migration:
// data sealed with the old derivation still opens, and new seals use the
// domain-separated one so a leaked box key can never double as a JWT signer.
func TestSecretBoxOpensLegacySealedValuesAndRoundTripsNewOnes(t *testing.T) {
	jwtKey := []byte("0123456789abcdef0123456789abcdef")
	box := newSecretBox(jwtKey)

	const plaintext = "http://user:pass@proxy.internal:8080 and a c2 credential"
	old := legacySeal(t, jwtKey, plaintext)
	if got, err := box.open(old); err != nil || got != plaintext {
		t.Fatalf("legacy open=%q err=%v", got, err)
	}

	sealed, err := box.seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if sealed == old {
		t.Fatal("new seal reused the legacy encoding")
	}
	if got, err := box.open(sealed); err != nil || got != plaintext {
		t.Fatalf("new open=%q err=%v", got, err)
	}

	// The new derivation must differ from the legacy one, or the fallback would
	// never be exercised and domain separation would be a no-op.
	if bytes.Equal(derivedSecretKey(jwtKey, true), derivedSecretKey(jwtKey, false)) {
		t.Fatal("domain separation did not change the derived key")
	}

	// A different instance key cannot open the box, and garbage is rejected
	// rather than silently decoding to bytes.
	other := newSecretBox([]byte("ffffffffffffffffffffffffffffffff"))
	if _, err := other.open(sealed); err == nil {
		t.Fatal("wrong key opened a seal")
	}
	if _, err := box.open("not-base64!!"); err == nil {
		t.Fatal("invalid base64 accepted")
	}
}
