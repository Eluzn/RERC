package crypto

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPair1)

	keyPair2, err := GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPair2)

	// Keys should be different
	assert.NotEqual(t, keyPair1.Private, keyPair2.Private)
	assert.NotEqual(t, keyPair1.Public, keyPair2.Public)
}

func TestGenerateSigningKeyPair(t *testing.T) {
	signingPair1, err := GenerateSigningKeyPair()
	require.NoError(t, err)
	require.NotNil(t, signingPair1)

	signingPair2, err := GenerateSigningKeyPair()
	require.NoError(t, err)
	require.NotNil(t, signingPair2)

	// Keys should be different
	assert.NotEqual(t, signingPair1.Private, signingPair2.Private)
	assert.NotEqual(t, signingPair1.Public, signingPair2.Public)
}

func TestComputeSharedKey(t *testing.T) {
	// Generate two key pairs
	keyPair1, err := GenerateKeyPair()
	require.NoError(t, err)

	keyPair2, err := GenerateKeyPair()
	require.NoError(t, err)

	// Compute shared keys
	sharedKey1, err := ComputeSharedKey(keyPair1.Private, keyPair2.Public)
	require.NoError(t, err)

	sharedKey2, err := ComputeSharedKey(keyPair2.Private, keyPair1.Public)
	require.NoError(t, err)

	// Shared keys should be identical
	assert.Equal(t, sharedKey1, sharedKey2)
}

func TestEncryptDecryptMessage(t *testing.T) {
	// Generate key pairs
	keyPair1, err := GenerateKeyPair()
	require.NoError(t, err)

	keyPair2, err := GenerateKeyPair()
	require.NoError(t, err)

	signingPair, err := GenerateSigningKeyPair()
	require.NoError(t, err)

	// Compute shared key
	sharedKey, err := ComputeSharedKey(keyPair1.Private, keyPair2.Public)
	require.NoError(t, err)

	// Test message
	plaintext := []byte("Hello, secure world!")
	sequence := uint64(1)

	// Encrypt message
	encryptedMsg, err := EncryptMessage(plaintext, sharedKey, signingPair.Private, sequence)
	require.NoError(t, err)
	require.NotNil(t, encryptedMsg)

	// Decrypt message
	messageContext, err := DecryptMessage(encryptedMsg, sharedKey, signingPair.Public, 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, messageContext)

	// Verify decrypted content
	assert.Equal(t, plaintext, messageContext.Plaintext)
	assert.Equal(t, sequence, messageContext.Sequence)
	assert.True(t, messageContext.Verified)
}

func TestDecryptMessageInvalidSignature(t *testing.T) {
	// Generate key pairs
	keyPair1, err := GenerateKeyPair()
	require.NoError(t, err)

	keyPair2, err := GenerateKeyPair()
	require.NoError(t, err)

	signingPair1, err := GenerateSigningKeyPair()
	require.NoError(t, err)

	signingPair2, err := GenerateSigningKeyPair()
	require.NoError(t, err)

	// Compute shared key
	sharedKey, err := ComputeSharedKey(keyPair1.Private, keyPair2.Public)
	require.NoError(t, err)

	// Encrypt with one signing key
	plaintext := []byte("Hello, secure world!")
	encryptedMsg, err := EncryptMessage(plaintext, sharedKey, signingPair1.Private, 1)
	require.NoError(t, err)

	// Try to decrypt with different signing key (should fail)
	_, err = DecryptMessage(encryptedMsg, sharedKey, signingPair2.Public, 5*time.Minute)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestDecryptMessageExpired(t *testing.T) {
	// Generate key pairs
	keyPair1, err := GenerateKeyPair()
	require.NoError(t, err)

	keyPair2, err := GenerateKeyPair()
	require.NoError(t, err)

	signingPair, err := GenerateSigningKeyPair()
	require.NoError(t, err)

	// Compute shared key
	sharedKey, err := ComputeSharedKey(keyPair1.Private, keyPair2.Public)
	require.NoError(t, err)

	// Encrypt message
	plaintext := []byte("Hello, secure world!")
	encryptedMsg, err := EncryptMessage(plaintext, sharedKey, signingPair.Private, 1)
	require.NoError(t, err)

	// Manually set old timestamp
	encryptedMsg.Timestamp = uint64(time.Now().Add(-1*time.Hour).Unix())

	// Try to decrypt with short max age (should fail)
	_, err = DecryptMessage(encryptedMsg, sharedKey, signingPair.Public, 5*time.Minute)
	assert.ErrorIs(t, err, ErrMessageExpired)
}

func TestDecryptMessageWrongKey(t *testing.T) {
	// Generate key pairs
	keyPair1, err := GenerateKeyPair()
	require.NoError(t, err)

	keyPair2, err := GenerateKeyPair()
	require.NoError(t, err)

	keyPair3, err := GenerateKeyPair()
	require.NoError(t, err)

	signingPair, err := GenerateSigningKeyPair()
	require.NoError(t, err)

	// Compute shared keys
	sharedKey1, err := ComputeSharedKey(keyPair1.Private, keyPair2.Public)
	require.NoError(t, err)

	sharedKey2, err := ComputeSharedKey(keyPair1.Private, keyPair3.Public)
	require.NoError(t, err)

	// Encrypt with first shared key
	plaintext := []byte("Hello, secure world!")
	encryptedMsg, err := EncryptMessage(plaintext, sharedKey1, signingPair.Private, 1)
	require.NoError(t, err)

	// Try to decrypt with different shared key (should fail)
	_, err = DecryptMessage(encryptedMsg, sharedKey2, signingPair.Public, 5*time.Minute)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestSecureRandom(t *testing.T) {
	// Test different sizes
	sizes := []int{16, 32, 64, 128}
	
	for _, size := range sizes {
		random1, err := SecureRandom(size)
		require.NoError(t, err)
		require.Len(t, random1, size)

		random2, err := SecureRandom(size)
		require.NoError(t, err)
		require.Len(t, random2, size)

		// Should be different
		assert.NotEqual(t, random1, random2)
	}
}

func TestHash(t *testing.T) {
	data1 := []byte("Hello, world!")
	data2 := []byte("Hello, world!")
	data3 := []byte("Hello, World!")

	hash1 := Hash(data1)
	hash2 := Hash(data2)
	hash3 := Hash(data3)

	// Same data should produce same hash
	assert.Equal(t, hash1, hash2)

	// Different data should produce different hash
	assert.NotEqual(t, hash1, hash3)
}

// Benchmark tests
func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptMessage(b *testing.B) {
	keyPair1, _ := GenerateKeyPair()
	keyPair2, _ := GenerateKeyPair()
	signingPair, _ := GenerateSigningKeyPair()
	sharedKey, _ := ComputeSharedKey(keyPair1.Private, keyPair2.Public)
	
	plaintext := []byte("This is a test message for benchmarking encryption performance.")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptMessage(plaintext, sharedKey, signingPair.Private, uint64(i))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptMessage(b *testing.B) {
	keyPair1, _ := GenerateKeyPair()
	keyPair2, _ := GenerateKeyPair()
	signingPair, _ := GenerateSigningKeyPair()
	sharedKey, _ := ComputeSharedKey(keyPair1.Private, keyPair2.Public)
	
	plaintext := []byte("This is a test message for benchmarking decryption performance.")
	encryptedMsg, _ := EncryptMessage(plaintext, sharedKey, signingPair.Private, 1)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptMessage(encryptedMsg, sharedKey, signingPair.Public, 5*time.Minute)
		if err != nil {
			b.Fatal(err)
		}
	}
}
