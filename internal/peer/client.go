package peer

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/google/uuid"

	"github.com/rerc/distributed-relay-chat/internal/crypto"
	"github.com/rerc/distributed-relay-chat/internal/protocol"
)

const (
	MaxMessageAge = 5 * time.Minute
	ReconnectDelay = 5 * time.Second
	HandshakeTimeout = 10 * time.Second
)

// Client represents a peer client
type Client struct {
	id          string
	keyPair     *crypto.KeyPair
	signingPair *crypto.SigningKeyPair
	conn        *websocket.Conn
	peers       map[string]*PeerInfo
	sessions    map[string]*crypto.KeyPair
	sequence    uint64
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	
	// Event handlers
	onMessage    func(from string, message []byte)
	onPeerUpdate func(peers []PeerInfo)
	onError      func(err error)
}

// PeerInfo contains information about a discovered peer
type PeerInfo struct {
	ID         string                `json:"id"`
	PublicKey  [32]byte             `json:"public_key"`
	SigningKey ed25519.PublicKey    `json:"signing_key"`
	SharedKey  [32]byte             `json:"shared_key"`
	LastSeen   time.Time            `json:"last_seen"`
	IsRelay    bool                 `json:"is_relay"`
}

// Config holds the peer client configuration
type Config struct {
	RelayNodes []string
	OnMessage  func(from string, message []byte)
	OnPeerUpdate func(peers []PeerInfo)
	OnError    func(err error)
}

// NewClient creates a new peer client
func NewClient(config *Config) (*Client, error) {
	// Generate cryptographic keys
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	signingPair, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key pair: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		id:          fmt.Sprintf("peer-%x", crypto.Hash(keyPair.Public[:])[:8]),
		keyPair:     keyPair,
		signingPair: signingPair,
		peers:       make(map[string]*PeerInfo),
		sessions:    make(map[string]*crypto.KeyPair),
		sequence:    0,
		ctx:         ctx,
		cancel:      cancel,
		onMessage:   config.OnMessage,
		onPeerUpdate: config.OnPeerUpdate,
		onError:     config.OnError,
	}

	return client, nil
}

// Connect connects to a relay node
func (c *Client) Connect(relayURL string) error {
	log.Printf("Connecting to relay node: %s", relayURL)

	u, err := url.Parse(relayURL)
	if err != nil {
		return fmt.Errorf("invalid relay URL: %w", err)
	}

	// Establish WebSocket connection
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to relay: %w", err)
	}

	c.conn = conn

	// Start message handling
	go c.readPump()

	// Perform handshake
	if err := c.performHandshake(); err != nil {
		c.conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	log.Printf("Successfully connected to relay node")
	return nil
}

// Disconnect disconnects from the relay node
func (c *Client) Disconnect() error {
	if c.conn != nil {
		c.cancel()
		return c.conn.Close()
	}
	return nil
}

// SendMessage sends an encrypted message to a peer
func (c *Client) SendMessage(targetPeerID string, message []byte) error {
	c.mu.RLock()
	peer, exists := c.peers[targetPeerID]
	c.mu.RUnlock()

	if !exists {
		return fmt.Errorf("peer not found: %s", targetPeerID)
	}

	// Encrypt the message
	c.mu.Lock()
	c.sequence++
	sequence := c.sequence
	c.mu.Unlock()

	encryptedMsg, err := crypto.EncryptMessage(message, peer.SharedKey, c.signingPair.Private, sequence)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Serialize encrypted message
	encryptedData, err := c.serializeEncryptedMessage(encryptedMsg)
	if err != nil {
		return fmt.Errorf("serialization failed: %w", err)
	}

	// Create relay message
	relayData := &protocol.RelayData{
		MessageID:     uuid.New().String(),
		TargetPeerID:  targetPeerID,
		EncryptedData: encryptedData,
		TTL:           5, // Maximum 5 hops
		Route:         []string{c.id},
	}

	// Sign the relay data
	signature := ed25519.Sign(c.signingPair.Private, encryptedData)
	relayData.Signature = signature

	// Send relay message
	msg := protocol.NewMessage(protocol.MessageTypeRelay, c.id, relayData)
	return c.sendMessage(msg)
}

// DiscoverPeers requests peer discovery from the relay node
func (c *Client) DiscoverPeers() error {
	msg := protocol.NewMessage(
		protocol.MessageTypePeerDiscovery,
		c.id,
		&protocol.PeerDiscoveryData{
			RequestID: uuid.New().String(),
		},
	)

	return c.sendMessage(msg)
}

// GetPeers returns the list of discovered peers
func (c *Client) GetPeers() []PeerInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	peers := make([]PeerInfo, 0, len(c.peers))
	for _, peer := range c.peers {
		peers = append(peers, *peer)
	}
	return peers
}

// GetID returns the client's peer ID
func (c *Client) GetID() string {
	return c.id
}

// performHandshake performs the initial handshake with the relay node
func (c *Client) performHandshake() error {
	// Send handshake
	handshakeData := &protocol.HandshakeData{
		PublicKey:       c.keyPair.Public,
		SigningKey:      c.signingPair.Public,
		ProtocolVersion: "1.0",
		Capabilities:    []string{"client"},
	}

	msg := protocol.NewMessage(protocol.MessageTypeHandshake, c.id, handshakeData)
	if err := c.sendMessage(msg); err != nil {
		return err
	}

	// Wait for handshake response (simplified - in production use proper timeout)
	time.Sleep(1 * time.Second)
	return nil
}

// readPump handles incoming messages from the relay node
func (c *Client) readPump() {
	defer func() {
		if c.conn != nil {
			c.conn.Close()
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			_, messageData, err := c.conn.ReadMessage()
			if err != nil {
				if c.onError != nil {
					c.onError(fmt.Errorf("read error: %w", err))
				}
				return
			}

			// Parse message
			msg, err := protocol.FromJSON(messageData)
			if err != nil {
				log.Printf("Invalid message format: %v", err)
				continue
			}

			// Handle message
			if err := c.handleMessage(msg); err != nil {
				log.Printf("Message handling error: %v", err)
			}
		}
	}
}

// handleMessage processes incoming messages
func (c *Client) handleMessage(msg *protocol.Message) error {
	switch msg.Type {
	case protocol.MessageTypeHandshakeResp:
		return c.handleHandshakeResponse(msg)
		
	case protocol.MessageTypeDirectMessage:
		return c.handleDirectMessage(msg)
		
	case protocol.MessageTypePeerDiscovery:
		return c.handlePeerDiscovery(msg)
		
	case protocol.MessageTypePong:
		return c.handlePong(msg)
		
	case protocol.MessageTypeError:
		return c.handleError(msg)
		
	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}
	
	return nil
}

// handleHandshakeResponse processes handshake responses
func (c *Client) handleHandshakeResponse(msg *protocol.Message) error {
	log.Printf("Received handshake response from %s", msg.From)
	return nil
}

// handleDirectMessage processes direct encrypted messages
func (c *Client) handleDirectMessage(msg *protocol.Message) error {
	directMsg, err := msg.GetDirectMessageData()
	if err != nil {
		return fmt.Errorf("invalid direct message: %w", err)
	}

	// Find the sender's peer info
	c.mu.RLock()
	peer, exists := c.peers[msg.From]
	c.mu.RUnlock()

	if !exists {
		return fmt.Errorf("unknown sender: %s", msg.From)
	}

	// Verify signature
	if !ed25519.Verify(peer.SigningKey, directMsg.EncryptedData, directMsg.Signature) {
		return fmt.Errorf("invalid message signature")
	}

	// Deserialize encrypted message
	encryptedMsg, err := c.deserializeEncryptedMessage(directMsg.EncryptedData)
	if err != nil {
		return fmt.Errorf("deserialization failed: %w", err)
	}

	// Decrypt message
	messageContext, err := crypto.DecryptMessage(encryptedMsg, peer.SharedKey, peer.SigningKey, MaxMessageAge)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Call message handler
	if c.onMessage != nil {
		c.onMessage(msg.From, messageContext.Plaintext)
	}

	return nil
}

// handlePeerDiscovery processes peer discovery responses
func (c *Client) handlePeerDiscovery(msg *protocol.Message) error {
	discoveryData, err := msg.GetPeerDiscoveryData()
	if err != nil {
		return fmt.Errorf("invalid peer discovery data: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Update peer information
	for _, peerInfo := range discoveryData.Peers {
		if peerInfo.ID == c.id {
			continue // Skip ourselves
		}

		// Compute shared key
		sharedKey, err := crypto.ComputeSharedKey(c.keyPair.Private, peerInfo.PublicKey)
		if err != nil {
			log.Printf("Failed to compute shared key for peer %s: %v", peerInfo.ID, err)
			continue
		}

		c.peers[peerInfo.ID] = &PeerInfo{
			ID:         peerInfo.ID,
			PublicKey:  peerInfo.PublicKey,
			SigningKey: peerInfo.SigningKey,
			SharedKey:  sharedKey,
			LastSeen:   peerInfo.LastSeen,
			IsRelay:    peerInfo.Relay,
		}
	}

	// Notify about peer updates
	if c.onPeerUpdate != nil {
		peers := make([]PeerInfo, 0, len(c.peers))
		for _, peer := range c.peers {
			peers = append(peers, *peer)
		}
		go c.onPeerUpdate(peers)
	}

	return nil
}

// handlePong processes pong messages
func (c *Client) handlePong(msg *protocol.Message) error {
	log.Printf("Received pong from %s", msg.From)
	return nil
}

// handleError processes error messages
func (c *Client) handleError(msg *protocol.Message) error {
	log.Printf("Received error from %s: %v", msg.From, msg.Data)
	if c.onError != nil {
		c.onError(fmt.Errorf("relay error: %v", msg.Data))
	}
	return nil
}

// sendMessage sends a message to the relay node
func (c *Client) sendMessage(msg *protocol.Message) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to relay")
	}

	data, err := msg.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}

	return c.conn.WriteMessage(websocket.TextMessage, data)
}

// serializeEncryptedMessage serializes an encrypted message to bytes
func (c *Client) serializeEncryptedMessage(msg *crypto.EncryptedMessage) ([]byte, error) {
	// Simple binary serialization
	// In production, use a proper serialization format like protobuf
	data := make([]byte, 0, len(msg.Nonce)+8+8+len(msg.Signature)+len(msg.Data))
	data = append(data, msg.Nonce[:]...)
	
	// Add timestamp (8 bytes)
	timestampBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		timestampBytes[i] = byte(msg.Timestamp >> (8 * (7 - i)))
	}
	data = append(data, timestampBytes...)
	
	// Add sequence (8 bytes)
	sequenceBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		sequenceBytes[i] = byte(msg.Sequence >> (8 * (7 - i)))
	}
	data = append(data, sequenceBytes...)
	
	data = append(data, msg.Signature[:]...)
	data = append(data, msg.Data...)
	
	return data, nil
}

// deserializeEncryptedMessage deserializes an encrypted message from bytes
func (c *Client) deserializeEncryptedMessage(data []byte) (*crypto.EncryptedMessage, error) {
	if len(data) < crypto.NonceSize+8+8+crypto.SignatureSize {
		return nil, fmt.Errorf("invalid encrypted message size")
	}

	msg := &crypto.EncryptedMessage{}
	offset := 0

	// Read nonce
	copy(msg.Nonce[:], data[offset:offset+crypto.NonceSize])
	offset += crypto.NonceSize

	// Read timestamp
	msg.Timestamp = 0
	for i := 0; i < 8; i++ {
		msg.Timestamp = (msg.Timestamp << 8) | uint64(data[offset+i])
	}
	offset += 8

	// Read sequence
	msg.Sequence = 0
	for i := 0; i < 8; i++ {
		msg.Sequence = (msg.Sequence << 8) | uint64(data[offset+i])
	}
	offset += 8

	// Read signature
	copy(msg.Signature[:], data[offset:offset+crypto.SignatureSize])
	offset += crypto.SignatureSize

	// Read encrypted data
	msg.Data = make([]byte, len(data)-offset)
	copy(msg.Data, data[offset:])

	return msg, nil
}
