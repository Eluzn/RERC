package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"go.etcd.io/bbolt"

	"github.com/eluzn/RERC/internal/crypto"
	"github.com/eluzn/RERC/internal/network"
	"github.com/eluzn/RERC/internal/protocol"
)

const (
	DatabaseName   = "relay.db"
	PeersBucket    = "peers"
	SessionsBucket = "sessions"
	MessageTTL     = 24 * time.Hour
	SessionTimeout = 30 * time.Minute
	MaxRelayHops   = 5
)

// Node represents a relay node in the distributed network
type Node struct {
	id          string
	keyPair     *crypto.KeyPair
	signingPair *crypto.SigningKeyPair
	hub         *network.Hub
	db          *bbolt.DB
	peers       map[string]*PeerSession
	sessions    map[string]*Session
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// PeerSession represents a connected peer session
type PeerSession struct {
	ID         string              `json:"id"`
	PublicKey  [32]byte            `json:"public_key"`
	SigningKey ed25519.PublicKey   `json:"signing_key"`
	SharedKey  [32]byte            `json:"shared_key"`
	Connection *network.Connection `json:"-"`
	LastSeen   time.Time           `json:"last_seen"`
	IsRelay    bool                `json:"is_relay"`
	Sequence   uint64              `json:"sequence"`
}

// Session represents an authenticated session
type Session struct {
	ID        string    `json:"id"`
	PeerID    string    `json:"peer_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Config holds the relay node configuration
type Config struct {
	ListenAddr   string
	DatabasePath string
	MaxPeers     int
	IsBootstrap  bool
}

// NewNode creates a new relay node
func NewNode(config *Config) (*Node, error) {
	// Generate cryptographic keys
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	signingPair, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key pair: %w", err)
	}

	// Open database
	db, err := bbolt.Open(config.DatabasePath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Initialize database buckets
	err = db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(PeersBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(SessionsBucket)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	node := &Node{
		id: func() string {
			hash := crypto.Hash(keyPair.Public[:])
			return fmt.Sprintf("relay-%x", hash[:8])
		}(),
		keyPair:     keyPair,
		signingPair: signingPair,
		hub:         network.NewHub(),
		db:          db,
		peers:       make(map[string]*PeerSession),
		sessions:    make(map[string]*Session),
		ctx:         ctx,
		cancel:      cancel,
	}

	return node, nil
}

// Start starts the relay node
func (n *Node) Start(listenAddr string) error {
	log.Printf("Starting relay node %s on %s", n.id, listenAddr)

	// Start the network hub
	go n.hub.Run()

	// Start cleanup routines
	go n.cleanupRoutine()

	// Setup HTTP handlers
	http.HandleFunc("/ws", network.HandleWebSocket(n.hub, n))
	http.HandleFunc("/health", n.healthHandler)
	http.HandleFunc("/peers", n.peersHandler)

	// Start HTTP server
	return http.ListenAndServe(listenAddr, nil)
}

// Stop gracefully stops the relay node
func (n *Node) Stop() error {
	log.Printf("Stopping relay node %s", n.id)

	n.cancel()
	n.hub.Stop()

	if n.db != nil {
		return n.db.Close()
	}

	return nil
}

// HandleMessage implements the MessageHandler interface
func (n *Node) HandleMessage(conn *network.Connection, msg *protocol.Message) error {
	switch msg.Type {
	case protocol.MessageTypeHandshake:
		return n.handleHandshake(conn, msg)

	case protocol.MessageTypeAuth:
		return n.handleAuth(conn, msg)

	case protocol.MessageTypeRelay:
		return n.handleRelay(conn, msg)

	case protocol.MessageTypeDirectMessage:
		return n.handleDirectMessage(conn, msg)

	case protocol.MessageTypePeerDiscovery:
		return n.handlePeerDiscovery(conn, msg)

	case protocol.MessageTypePing:
		return n.handlePing(conn, msg)

	default:
		log.Printf("Unknown message type: %s", msg.Type)
		return n.sendError(conn, "unknown_message_type", "Unknown message type")
	}
}

// handleHandshake processes handshake messages
func (n *Node) handleHandshake(conn *network.Connection, msg *protocol.Message) error {
	handshakeData, err := msg.GetHandshakeData()
	if err != nil {
		return n.sendError(conn, "invalid_handshake", "Invalid handshake data")
	}

	// Generate shared key
	sharedKey, err := crypto.ComputeSharedKey(n.keyPair.Private, handshakeData.PublicKey)
	if err != nil {
		return n.sendError(conn, "key_exchange_failed", "Key exchange failed")
	}

	// Create peer session
	peerSession := &PeerSession{
		ID:         msg.From,
		PublicKey:  handshakeData.PublicKey,
		SigningKey: handshakeData.SigningKey,
		SharedKey:  sharedKey,
		Connection: conn,
		LastSeen:   time.Now(),
		IsRelay:    contains(handshakeData.Capabilities, "relay"),
		Sequence:   0,
	}

	// Store peer session
	n.mu.Lock()
	n.peers[msg.From] = peerSession
	n.mu.Unlock()

	// Send handshake response
	response := protocol.NewMessage(
		protocol.MessageTypeHandshakeResp,
		n.id,
		&protocol.HandshakeResponse{
			PublicKey:       n.keyPair.Public,
			SigningKey:      n.signingPair.Public,
			ProtocolVersion: "1.0",
			Accepted:        true,
			SessionID:       fmt.Sprintf("session-%d", time.Now().UnixNano()),
		},
	)
	response.To = msg.From

	return conn.SendMessage(response)
}

// handleAuth processes authentication messages
func (n *Node) handleAuth(conn *network.Connection, msg *protocol.Message) error {
	// In a production system, implement proper authentication
	// For now, we'll accept all authenticated handshakes as valid

	session := &Session{
		ID:        fmt.Sprintf("session-%d", time.Now().UnixNano()),
		PeerID:    msg.From,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(SessionTimeout),
	}

	n.mu.Lock()
	n.sessions[session.ID] = session
	n.mu.Unlock()

	response := protocol.NewMessage(
		protocol.MessageTypeAuthResp,
		n.id,
		&protocol.AuthResponse{
			Success:   true,
			SessionID: session.ID,
		},
	)
	response.To = msg.From

	return conn.SendMessage(response)
}

// handleRelay processes relay messages
func (n *Node) handleRelay(conn *network.Connection, msg *protocol.Message) error {
	relayData, err := msg.GetRelayData()
	if err != nil {
		return n.sendError(conn, "invalid_relay", "Invalid relay data")
	}

	// Check TTL
	if relayData.TTL <= 0 {
		log.Printf("Message TTL expired: %s", relayData.MessageID)
		return nil
	}

	// Check if we've seen this message before (prevent loops)
	if contains(relayData.Route, n.id) {
		log.Printf("Message loop detected: %s", relayData.MessageID)
		return nil
	}

	// Add ourselves to the route
	relayData.Route = append(relayData.Route, n.id)
	relayData.TTL--

	// Try to deliver directly to target
	n.mu.RLock()
	targetPeer, exists := n.peers[relayData.TargetPeerID]
	n.mu.RUnlock()

	if exists && targetPeer.Connection != nil {
		// Direct delivery
		directMsg := protocol.NewMessage(
			protocol.MessageTypeDirectMessage,
			msg.From,
			&protocol.DirectMessageData{
				MessageID:     relayData.MessageID,
				EncryptedData: relayData.EncryptedData,
				Signature:     relayData.Signature,
			},
		)
		directMsg.To = relayData.TargetPeerID

		err := targetPeer.Connection.SendMessage(directMsg)
		if err == nil {
			// Send acknowledgment
			ack := protocol.NewMessage(
				protocol.MessageTypeRelayAck,
				n.id,
				&protocol.RelayAckData{
					MessageID: relayData.MessageID,
					Success:   true,
				},
			)
			ack.To = msg.From
			return conn.SendMessage(ack)
		}
	}

	// Relay to other nodes
	relayMsg := protocol.NewMessage(protocol.MessageTypeRelay, msg.From, relayData)

	n.mu.RLock()
	for peerID, peer := range n.peers {
		if peer.IsRelay && peerID != msg.From && !contains(relayData.Route, peerID) {
			go peer.Connection.SendMessage(relayMsg)
		}
	}
	n.mu.RUnlock()

	return nil
}

// handleDirectMessage processes direct messages
func (n *Node) handleDirectMessage(conn *network.Connection, msg *protocol.Message) error {
	// Direct messages are end-to-end encrypted and just passed through
	log.Printf("Received direct message from %s", msg.From)
	return nil
}

// handlePeerDiscovery processes peer discovery messages
func (n *Node) handlePeerDiscovery(conn *network.Connection, msg *protocol.Message) error {
	n.mu.RLock()
	peers := make([]protocol.PeerInfo, 0, len(n.peers))
	for _, peer := range n.peers {
		peers = append(peers, protocol.PeerInfo{
			ID:         peer.ID,
			PublicKey:  peer.PublicKey,
			SigningKey: peer.SigningKey,
			LastSeen:   peer.LastSeen,
			Relay:      peer.IsRelay,
		})
	}
	n.mu.RUnlock()

	response := protocol.NewMessage(
		protocol.MessageTypePeerDiscovery,
		n.id,
		&protocol.PeerDiscoveryData{
			Peers: peers,
		},
	)
	response.To = msg.From

	return conn.SendMessage(response)
}

// handlePing processes ping messages
func (n *Node) handlePing(conn *network.Connection, msg *protocol.Message) error {
	response := protocol.NewMessage(
		protocol.MessageTypePong,
		n.id,
		&protocol.PongData{
			Timestamp:      time.Now().Unix(),
			OriginalPing:   msg.Timestamp,
			ProcessingTime: time.Now().Unix() - msg.Timestamp,
		},
	)
	response.To = msg.From

	return conn.SendMessage(response)
}

// sendError sends an error message to a connection
func (n *Node) sendError(conn *network.Connection, code, message string) error {
	errorMsg := protocol.NewMessage(
		protocol.MessageTypeError,
		n.id,
		&protocol.ErrorData{
			Code:    code,
			Message: message,
		},
	)

	return conn.SendMessage(errorMsg)
}

// healthHandler provides health check endpoint
func (n *Node) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	health := map[string]interface{}{
		"status":    "healthy",
		"node_id":   n.id,
		"peers":     len(n.peers),
		"sessions":  len(n.sessions),
		"timestamp": time.Now().Unix(),
	}

	json.NewEncoder(w).Encode(health)
}

// peersHandler provides peer information endpoint
func (n *Node) peersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	n.mu.RLock()
	peers := make([]protocol.PeerInfo, 0, len(n.peers))
	for _, peer := range n.peers {
		peers = append(peers, protocol.PeerInfo{
			ID:        peer.ID,
			PublicKey: peer.PublicKey,
			LastSeen:  peer.LastSeen,
			Relay:     peer.IsRelay,
		})
	}
	n.mu.RUnlock()

	json.NewEncoder(w).Encode(peers)
}

// cleanupRoutine performs periodic cleanup of expired sessions and peers
func (n *Node) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.cleanup()
		}
	}
}

// cleanup removes expired sessions and inactive peers
func (n *Node) cleanup() {
	now := time.Now()

	n.mu.Lock()
	defer n.mu.Unlock()

	// Clean up expired sessions
	for sessionID, session := range n.sessions {
		if now.After(session.ExpiresAt) {
			delete(n.sessions, sessionID)
			log.Printf("Cleaned up expired session: %s", sessionID)
		}
	}

	// Clean up inactive peers
	for peerID, peer := range n.peers {
		if now.Sub(peer.LastSeen) > 30*time.Minute {
			delete(n.peers, peerID)
			log.Printf("Cleaned up inactive peer: %s", peerID)
		}
	}
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
