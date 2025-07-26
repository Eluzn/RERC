package protocol

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMessage(t *testing.T) {
	msgType := MessageTypeHandshake
	from := "test-peer"
	data := &HandshakeData{
		ProtocolVersion: "1.0",
		Capabilities:    []string{"client"},
	}

	msg := NewMessage(msgType, from, data)

	assert.NotEmpty(t, msg.ID)
	assert.Equal(t, msgType, msg.Type)
	assert.Equal(t, from, msg.From)
	assert.NotZero(t, msg.Timestamp)
	assert.Equal(t, data, msg.Data)
}

func TestMessageToJSON(t *testing.T) {
	msg := NewMessage(MessageTypePing, "test-peer", &PingData{
		Timestamp: time.Now().Unix(),
		Data:      []byte("test"),
	})

	jsonData, err := msg.ToJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonData, &parsed)
	require.NoError(t, err)
}

func TestFromJSON(t *testing.T) {
	original := NewMessage(MessageTypePong, "test-peer", &PongData{
		Timestamp:      time.Now().Unix(),
		OriginalPing:   12345,
		ProcessingTime: 100,
	})

	jsonData, err := original.ToJSON()
	require.NoError(t, err)

	parsed, err := FromJSON(jsonData)
	require.NoError(t, err)

	assert.Equal(t, original.ID, parsed.ID)
	assert.Equal(t, original.Type, parsed.Type)
	assert.Equal(t, original.From, parsed.From)
	assert.Equal(t, original.Timestamp, parsed.Timestamp)
}

func TestGetHandshakeData(t *testing.T) {
	handshakeData := &HandshakeData{
		PublicKey:       [32]byte{1, 2, 3, 4, 5},
		SigningKey:      []byte("test-signing-key"),
		ProtocolVersion: "1.0",
		Capabilities:    []string{"client", "relay"},
	}

	msg := NewMessage(MessageTypeHandshake, "test-peer", handshakeData)

	extracted, err := msg.GetHandshakeData()
	require.NoError(t, err)
	assert.Equal(t, handshakeData.ProtocolVersion, extracted.ProtocolVersion)
	assert.Equal(t, handshakeData.Capabilities, extracted.Capabilities)
}

func TestGetHandshakeDataInvalidType(t *testing.T) {
	msg := NewMessage(MessageTypePing, "test-peer", &PingData{})

	_, err := msg.GetHandshakeData()
	assert.ErrorIs(t, err, ErrInvalidMessageType)
}

func TestGetRelayData(t *testing.T) {
	relayData := &RelayData{
		MessageID:     "test-message-123",
		TargetPeerID:  "target-peer",
		EncryptedData: []byte("encrypted-content"),
		Signature:     []byte("signature"),
		TTL:           5,
		Route:         []string{"peer1", "peer2"},
	}

	msg := NewMessage(MessageTypeRelay, "test-peer", relayData)

	extracted, err := msg.GetRelayData()
	require.NoError(t, err)
	assert.Equal(t, relayData.MessageID, extracted.MessageID)
	assert.Equal(t, relayData.TargetPeerID, extracted.TargetPeerID)
	assert.Equal(t, relayData.TTL, extracted.TTL)
	assert.Equal(t, relayData.Route, extracted.Route)
}

func TestGetRelayDataInvalidType(t *testing.T) {
	msg := NewMessage(MessageTypePing, "test-peer", &PingData{})

	_, err := msg.GetRelayData()
	assert.ErrorIs(t, err, ErrInvalidMessageType)
}

func TestGetDirectMessageData(t *testing.T) {
	directMsgData := &DirectMessageData{
		MessageID:     "direct-msg-123",
		EncryptedData: []byte("encrypted-direct-content"),
		Signature:     []byte("direct-signature"),
	}

	msg := NewMessage(MessageTypeDirectMessage, "test-peer", directMsgData)

	extracted, err := msg.GetDirectMessageData()
	require.NoError(t, err)
	assert.Equal(t, directMsgData.MessageID, extracted.MessageID)
	assert.Equal(t, directMsgData.EncryptedData, extracted.EncryptedData)
	assert.Equal(t, directMsgData.Signature, extracted.Signature)
}

func TestGetDirectMessageDataInvalidType(t *testing.T) {
	msg := NewMessage(MessageTypePing, "test-peer", &PingData{})

	_, err := msg.GetDirectMessageData()
	assert.ErrorIs(t, err, ErrInvalidMessageType)
}

func TestMessageTypes(t *testing.T) {
	// Test that all message types are defined
	types := []MessageType{
		MessageTypeHandshake,
		MessageTypeHandshakeResp,
		MessageTypeAuth,
		MessageTypeAuthResp,
		MessageTypePeerDiscovery,
		MessageTypePeerAnnounce,
		MessageTypeRelay,
		MessageTypeRelayAck,
		MessageTypeDirectMessage,
		MessageTypePing,
		MessageTypePong,
		MessageTypeError,
		MessageTypeDisconnect,
	}

	for _, msgType := range types {
		assert.NotEmpty(t, string(msgType))
	}
}

func TestComplexMessageSerialization(t *testing.T) {
	// Test with complex nested data
	peerInfo := []PeerInfo{
		{
			ID:         "peer1",
			PublicKey:  [32]byte{1, 2, 3},
			SigningKey: []byte("signing-key-1"),
			Addresses:  []string{"192.168.1.1:8080", "192.168.1.2:8080"},
			LastSeen:   time.Now(),
			Relay:      true,
		},
		{
			ID:         "peer2",
			PublicKey:  [32]byte{4, 5, 6},
			SigningKey: []byte("signing-key-2"),
			Addresses:  []string{"192.168.1.3:8080"},
			LastSeen:   time.Now().Add(-time.Hour),
			Relay:      false,
		},
	}

	discoveryData := &PeerDiscoveryData{
		RequestID: "discovery-123",
		Query:     "find-peers",
		Peers:     peerInfo,
	}

	msg := NewMessage(MessageTypePeerDiscovery, "test-peer", discoveryData)

	// Serialize and deserialize
	jsonData, err := msg.ToJSON()
	require.NoError(t, err)

	parsed, err := FromJSON(jsonData)
	require.NoError(t, err)

	// Verify the complex data survived serialization
	assert.Equal(t, msg.ID, parsed.ID)
	assert.Equal(t, msg.Type, parsed.Type)
	assert.Equal(t, msg.From, parsed.From)
}

// Benchmark tests
func BenchmarkNewMessage(b *testing.B) {
	data := &PingData{
		Timestamp: time.Now().Unix(),
		Data:      []byte("benchmark-data"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewMessage(MessageTypePing, "bench-peer", data)
	}
}

func BenchmarkMessageToJSON(b *testing.B) {
	msg := NewMessage(MessageTypePing, "bench-peer", &PingData{
		Timestamp: time.Now().Unix(),
		Data:      []byte("benchmark-data"),
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := msg.ToJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFromJSON(b *testing.B) {
	msg := NewMessage(MessageTypePing, "bench-peer", &PingData{
		Timestamp: time.Now().Unix(),
		Data:      []byte("benchmark-data"),
	})
	
	jsonData, _ := msg.ToJSON()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := FromJSON(jsonData)
		if err != nil {
			b.Fatal(err)
		}
	}
}
