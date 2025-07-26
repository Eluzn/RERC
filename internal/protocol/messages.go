package protocol

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// MessageType defines the type of protocol message
type MessageType string

const (
	// Connection and handshake
	MessageTypeHandshake     MessageType = "handshake"
	MessageTypeHandshakeResp MessageType = "handshake_response"
	MessageTypeAuth          MessageType = "auth"
	MessageTypeAuthResp      MessageType = "auth_response"

	// Peer discovery
	MessageTypePeerDiscovery MessageType = "peer_discovery"
	MessageTypePeerAnnounce  MessageType = "peer_announce"

	// Message relay
	MessageTypeRelay         MessageType = "relay"
	MessageTypeRelayAck      MessageType = "relay_ack"
	MessageTypeDirectMessage MessageType = "direct_message"

	// Network management
	MessageTypePing       MessageType = "ping"
	MessageTypePong       MessageType = "pong"
	MessageTypeError      MessageType = "error"
	MessageTypeDisconnect MessageType = "disconnect"
)

// Message represents the base protocol message structure
type Message struct {
	ID        string      `json:"id"`
	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp"`
	From      string      `json:"from"`
	To        string      `json:"to,omitempty"`
	Data      interface{} `json:"data,omitempty"`
}

// HandshakeData contains key exchange information
type HandshakeData struct {
	PublicKey       [32]byte `json:"public_key"`
	SigningKey      []byte   `json:"signing_key"`
	ProtocolVersion string   `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"`
}

// HandshakeResponse contains the response to a handshake
type HandshakeResponse struct {
	PublicKey       [32]byte `json:"public_key"`
	SigningKey      []byte   `json:"signing_key"`
	ProtocolVersion string   `json:"protocol_version"`
	Accepted        bool     `json:"accepted"`
	SessionID       string   `json:"session_id"`
}

// AuthData contains authentication information
type AuthData struct {
	PeerID    string `json:"peer_id"`
	Challenge []byte `json:"challenge"`
	Signature []byte `json:"signature"`
}

// AuthResponse contains authentication response
type AuthResponse struct {
	Success   bool   `json:"success"`
	SessionID string `json:"session_id"`
	Error     string `json:"error,omitempty"`
}

// PeerInfo represents information about a peer
type PeerInfo struct {
	ID         string    `json:"id"`
	PublicKey  [32]byte  `json:"public_key"`
	SigningKey []byte    `json:"signing_key"`
	Addresses  []string  `json:"addresses"`
	LastSeen   time.Time `json:"last_seen"`
	Relay      bool      `json:"relay"`
}

// PeerDiscoveryData contains peer discovery information
type PeerDiscoveryData struct {
	RequestID string     `json:"request_id"`
	Query     string     `json:"query,omitempty"`
	Peers     []PeerInfo `json:"peers,omitempty"`
}

// RelayData contains encrypted message relay information
type RelayData struct {
	MessageID     string   `json:"message_id"`
	TargetPeerID  string   `json:"target_peer_id"`
	EncryptedData []byte   `json:"encrypted_data"`
	Signature     []byte   `json:"signature"`
	TTL           int      `json:"ttl"`
	Route         []string `json:"route"`
}

// RelayAckData contains relay acknowledgment
type RelayAckData struct {
	MessageID string `json:"message_id"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// DirectMessageData contains direct message information
type DirectMessageData struct {
	MessageID     string `json:"message_id"`
	EncryptedData []byte `json:"encrypted_data"`
	Signature     []byte `json:"signature"`
}

// ErrorData contains error information
type ErrorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// PingData contains ping information
type PingData struct {
	Timestamp int64  `json:"timestamp"`
	Data      []byte `json:"data,omitempty"`
}

// PongData contains pong response
type PongData struct {
	Timestamp      int64 `json:"timestamp"`
	OriginalPing   int64 `json:"original_ping"`
	ProcessingTime int64 `json:"processing_time"`
}

// NewMessage creates a new protocol message
func NewMessage(msgType MessageType, from string, data interface{}) *Message {
	return &Message{
		ID:        uuid.New().String(),
		Type:      msgType,
		Timestamp: time.Now().Unix(),
		From:      from,
		Data:      data,
	}
}

// ToJSON serializes the message to JSON
func (m *Message) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// FromJSON deserializes a message from JSON
func FromJSON(data []byte) (*Message, error) {
	var msg Message
	err := json.Unmarshal(data, &msg)
	return &msg, err
}

// GetHandshakeData extracts handshake data from message
func (m *Message) GetHandshakeData() (*HandshakeData, error) {
	if m.Type != MessageTypeHandshake {
		return nil, ErrInvalidMessageType
	}

	data, err := json.Marshal(m.Data)
	if err != nil {
		return nil, err
	}

	var handshake HandshakeData
	err = json.Unmarshal(data, &handshake)
	return &handshake, err
}

// GetRelayData extracts relay data from message
func (m *Message) GetRelayData() (*RelayData, error) {
	if m.Type != MessageTypeRelay {
		return nil, ErrInvalidMessageType
	}

	data, err := json.Marshal(m.Data)
	if err != nil {
		return nil, err
	}

	var relay RelayData
	err = json.Unmarshal(data, &relay)
	return &relay, err
}

// GetDirectMessageData extracts direct message data
func (m *Message) GetDirectMessageData() (*DirectMessageData, error) {
	if m.Type != MessageTypeDirectMessage {
		return nil, ErrInvalidMessageType
	}

	data, err := json.Marshal(m.Data)
	if err != nil {
		return nil, err
	}

	var directMsg DirectMessageData
	err = json.Unmarshal(data, &directMsg)
	return &directMsg, err
}

// GetPeerDiscoveryData extracts peer discovery data from message
func (m *Message) GetPeerDiscoveryData() (*PeerDiscoveryData, error) {
	if m.Type != MessageTypePeerDiscovery {
		return nil, ErrInvalidMessageType
	}

	data, err := json.Marshal(m.Data)
	if err != nil {
		return nil, err
	}

	var discovery PeerDiscoveryData
	err = json.Unmarshal(data, &discovery)
	return &discovery, err
}

// Common errors
var (
	ErrInvalidMessageType = errors.New("invalid message type")
	ErrInvalidData        = errors.New("invalid message data")
)
