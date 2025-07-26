package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// Key sizes
	PrivateKeySize = 32
	PublicKeySize  = 32
	SharedKeySize  = 32
	NonceSize      = 12
	TagSize        = 16
	
	// Message components
	TimestampSize = 8
	SequenceSize  = 8
	SignatureSize = ed25519.SignatureSize
)

var (
	ErrInvalidKeySize     = errors.New("invalid key size")
	ErrInvalidNonce       = errors.New("invalid nonce size")
	ErrDecryptionFailed   = errors.New("decryption failed")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrReplayAttack       = errors.New("potential replay attack detected")
	ErrMessageExpired     = errors.New("message has expired")
)

// KeyPair represents a Curve25519 key pair for ECDH
type KeyPair struct {
	Private [PrivateKeySize]byte
	Public  [PublicKeySize]byte
}

// SigningKeyPair represents an Ed25519 key pair for signatures
type SigningKeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// EncryptedMessage represents an encrypted message with metadata
type EncryptedMessage struct {
	Nonce     [NonceSize]byte
	Timestamp uint64
	Sequence  uint64
	Signature [SignatureSize]byte
	Data      []byte
}

// MessageContext contains the decrypted message and metadata
type MessageContext struct {
	Plaintext []byte
	Timestamp time.Time
	Sequence  uint64
	Verified  bool
}

// GenerateKeyPair generates a new Curve25519 key pair for ECDH
func GenerateKeyPair() (*KeyPair, error) {
	var private, public [32]byte
	
	if _, err := rand.Read(private[:]); err != nil {
		return nil, err
	}
	
	curve25519.ScalarBaseMult(&public, &private)
	
	return &KeyPair{
		Private: private,
		Public:  public,
	}, nil
}

// GenerateSigningKeyPair generates a new Ed25519 key pair for signatures
func GenerateSigningKeyPair() (*SigningKeyPair, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	
	return &SigningKeyPair{
		Private: private,
		Public:  public,
	}, nil
}

// ComputeSharedKey computes the shared secret using ECDH
func ComputeSharedKey(privateKey, publicKey [32]byte) ([32]byte, error) {
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, &privateKey, &publicKey)
	
	// Derive key using HKDF for additional security
	hkdf := hkdf.New(sha256.New, sharedKey[:], nil, []byte("RERC-v1"))
	var derivedKey [32]byte
	if _, err := hkdf.Read(derivedKey[:]); err != nil {
		return [32]byte{}, err
	}
	
	return derivedKey, nil
}

// EncryptMessage encrypts a message with AES-256-GCM using the shared key
func EncryptMessage(plaintext []byte, sharedKey [32]byte, signingKey ed25519.PrivateKey, sequence uint64) (*EncryptedMessage, error) {
	// Generate random nonce
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	
	// Create AES cipher
	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Add timestamp
	timestamp := uint64(time.Now().Unix())
	
	// Prepare additional data (authenticated but not encrypted)
	additionalData := make([]byte, TimestampSize+SequenceSize)
	binary.BigEndian.PutUint64(additionalData[:TimestampSize], timestamp)
	binary.BigEndian.PutUint64(additionalData[TimestampSize:], sequence)
	
	// Encrypt the message
	ciphertext := gcm.Seal(nil, nonce[:], plaintext, additionalData)
	
	// Sign the entire message (nonce + timestamp + sequence + ciphertext)
	messageToSign := make([]byte, 0, NonceSize+TimestampSize+SequenceSize+len(ciphertext))
	messageToSign = append(messageToSign, nonce[:]...)
	messageToSign = append(messageToSign, additionalData...)
	messageToSign = append(messageToSign, ciphertext...)
	
	signature := ed25519.Sign(signingKey, messageToSign)
	
	var sigArray [SignatureSize]byte
	copy(sigArray[:], signature)
	
	return &EncryptedMessage{
		Nonce:     nonce,
		Timestamp: timestamp,
		Sequence:  sequence,
		Signature: sigArray,
		Data:      ciphertext,
	}, nil
}

// DecryptMessage decrypts and verifies a message
func DecryptMessage(msg *EncryptedMessage, sharedKey [32]byte, signingPublicKey ed25519.PublicKey, maxAge time.Duration) (*MessageContext, error) {
	// Verify timestamp (prevent replay attacks)
	msgTime := time.Unix(int64(msg.Timestamp), 0)
	if time.Since(msgTime) > maxAge {
		return nil, ErrMessageExpired
	}
	
	// Prepare additional data for verification
	additionalData := make([]byte, TimestampSize+SequenceSize)
	binary.BigEndian.PutUint64(additionalData[:TimestampSize], msg.Timestamp)
	binary.BigEndian.PutUint64(additionalData[TimestampSize:], msg.Sequence)
	
	// Verify signature
	messageToVerify := make([]byte, 0, NonceSize+TimestampSize+SequenceSize+len(msg.Data))
	messageToVerify = append(messageToVerify, msg.Nonce[:]...)
	messageToVerify = append(messageToVerify, additionalData...)
	messageToVerify = append(messageToVerify, msg.Data...)
	
	if !ed25519.Verify(signingPublicKey, messageToVerify, msg.Signature[:]) {
		return nil, ErrInvalidSignature
	}
	
	// Create AES cipher
	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Decrypt the message
	plaintext, err := gcm.Open(nil, msg.Nonce[:], msg.Data, additionalData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	
	return &MessageContext{
		Plaintext: plaintext,
		Timestamp: msgTime,
		Sequence:  msg.Sequence,
		Verified:  true,
	}, nil
}

// SecureRandom generates cryptographically secure random bytes
func SecureRandom(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// Hash computes SHA-256 hash of data
func Hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}
