package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c, err := New(testKey(t))
	require.NoError(t, err)

	plaintext := "session_id=abc123; Domain=github.com"
	stored, err := c.Encrypt(plaintext)
	require.NoError(t, err)
	require.NotContains(t, stored, plaintext, "stored value must not leak plaintext")

	got, err := c.Decrypt(stored)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestEncryptProducesDistinctCiphertextsForSamePlaintext(t *testing.T) {
	c, err := New(testKey(t))
	require.NoError(t, err)

	a, err := c.Encrypt("same-value")
	require.NoError(t, err)
	b, err := c.Encrypt("same-value")
	require.NoError(t, err)
	require.NotEqual(t, a, b, "random nonce must make ciphertexts differ")
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	c, err := New(testKey(t))
	require.NoError(t, err)

	stored, err := c.Encrypt("secret-cookie-value")
	require.NoError(t, err)

	tampered := []byte(stored)
	// flip a bit well inside the base64 body, not just padding
	tampered[len(tampered)/2] ^= 0x01

	_, err = c.Decrypt(string(tampered))
	require.Error(t, err, "GCM must reject tampered ciphertext instead of returning garbage")
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	c1, err := New(testKey(t))
	require.NoError(t, err)
	c2, err := New(testKey(t))
	require.NoError(t, err)

	stored, err := c1.Encrypt("owner-token")
	require.NoError(t, err)

	_, err = c2.Decrypt(stored)
	require.Error(t, err)
}

func TestNewRejectsWrongKeyLength(t *testing.T) {
	_, err := New(make([]byte, 16))
	require.Error(t, err)
}
