// Package crypto provides AES-256-GCM encryption for owner credentials
// (session_cookies.value_encrypted, session_tokens.value_encrypted).
//
// Ciphertext layout stored in the database: base64( nonce(12B) || ciphertext || tag ).
// The column is `text`, not `bytea`, so the binary AEAD output is base64-encoded
// before it is written.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Cipher encrypts/decrypts credential values with a single AES-256-GCM key.
// It is safe for concurrent use.
type Cipher struct {
	aead cipher.AEAD
}

// New builds a Cipher from a 32-byte AES-256 key. The key must already be
// raw bytes (decoded from base64 by the config package), not the encoded string.
func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt returns a base64 string suitable for storing directly in a
// value_encrypted text column. Called from the service layer, which is the
// only place that ever sees credential plaintext coming from an owner.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt. It is called from exactly one place in the
// application: the proxy injector, immediately before the credential is
// placed on the outgoing request to the target site. GCM authentication
// means a tampered value_encrypted column fails decryption instead of
// silently returning garbage.
func (c *Cipher) Decrypt(stored string) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return "", fmt.Errorf("crypto: not valid base64: %w", err)
	}
	nonceSize := c.aead.NonceSize()
	if len(sealed) < nonceSize {
		return "", fmt.Errorf("crypto: ciphertext too short")
	}
	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt failed: %w", err)
	}
	return string(plaintext), nil
}
