package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/eluzn/RERC/internal/protocol"
)

const (
	// WebSocket configuration
	WriteWait      = 10 * time.Second
	PongWait       = 60 * time.Second
	PingPeriod     = (PongWait * 9) / 10
	MaxMessageSize = 4096
	
	// Connection limits
	MaxConnections = 1000
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
}

// Connection represents a WebSocket connection
type Connection struct {
	conn       *websocket.Conn
	send       chan []byte
	hub        *Hub
	peerID     string
	lastPing   time.Time
	isRelay    bool
	mu         sync.RWMutex
}

// Hub manages all active connections
type Hub struct {
	connections map[string]*Connection
	register    chan *Connection
	unregister  chan *Connection
	broadcast   chan []byte
	relay       chan *RelayMessage
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// RelayMessage represents a message to be relayed
type RelayMessage struct {
	Target  string
	Message []byte
	Route   []string
}

// MessageHandler defines the interface for handling messages
type MessageHandler interface {
	HandleMessage(conn *Connection, msg *protocol.Message) error
}

// NewHub creates a new connection hub
func NewHub() *Hub {
	ctx, cancel := context.WithCancel(context.Background())
	return &Hub{
		connections: make(map[string]*Connection),
		register:    make(chan *Connection, 256),
		unregister:  make(chan *Connection, 256),
		broadcast:   make(chan []byte, 256),
		relay:       make(chan *RelayMessage, 256),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Run starts the hub's main event loop
func (h *Hub) Run() {
	ticker := time.NewTicker(PingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
			
		case conn := <-h.register:
			h.registerConnection(conn)
			
		case conn := <-h.unregister:
			h.unregisterConnection(conn)
			
		case message := <-h.broadcast:
			h.broadcastMessage(message)
			
		case relay := <-h.relay:
			h.relayMessage(relay)
			
		case <-ticker.C:
			h.pingConnections()
		}
	}
}

// Stop gracefully shuts down the hub
func (h *Hub) Stop() {
	h.cancel()
	
	h.mu.Lock()
	for _, conn := range h.connections {
		conn.Close()
	}
	h.mu.Unlock()
}

// registerConnection adds a new connection to the hub
func (h *Hub) registerConnection(conn *Connection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	if len(h.connections) >= MaxConnections {
		conn.Close()
		return
	}
	
	h.connections[conn.peerID] = conn
	log.Printf("Connection registered: %s (total: %d)", conn.peerID, len(h.connections))
}

// unregisterConnection removes a connection from the hub
func (h *Hub) unregisterConnection(conn *Connection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	if _, exists := h.connections[conn.peerID]; exists {
		delete(h.connections, conn.peerID)
		close(conn.send)
		log.Printf("Connection unregistered: %s (total: %d)", conn.peerID, len(h.connections))
	}
}

// broadcastMessage sends a message to all connections
func (h *Hub) broadcastMessage(message []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	for _, conn := range h.connections {
		select {
		case conn.send <- message:
		default:
			// Connection is blocked, close it
			h.unregister <- conn
		}
	}
}

// relayMessage sends a message to a specific target
func (h *Hub) relayMessage(relay *RelayMessage) {
	h.mu.RLock()
	conn, exists := h.connections[relay.Target]
	h.mu.RUnlock()
	
	if !exists {
		log.Printf("Target peer not found: %s", relay.Target)
		return
	}
	
	select {
	case conn.send <- relay.Message:
	default:
		// Connection is blocked, close it
		h.unregister <- conn
	}
}

// GetConnection returns a connection by peer ID
func (h *Hub) GetConnection(peerID string) (*Connection, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	conn, exists := h.connections[peerID]
	return conn, exists
}

// GetConnectedPeers returns a list of connected peer IDs
func (h *Hub) GetConnectedPeers() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	peers := make([]string, 0, len(h.connections))
	for peerID := range h.connections {
		peers = append(peers, peerID)
	}
	return peers
}

// pingConnections sends ping messages to all connections
func (h *Hub) pingConnections() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	now := time.Now()
	for _, conn := range h.connections {
		if now.Sub(conn.lastPing) > PongWait {
			h.unregister <- conn
			continue
		}
		
		if err := conn.Ping(); err != nil {
			h.unregister <- conn
		}
	}
}

// NewConnection creates a new WebSocket connection
func NewConnection(conn *websocket.Conn, hub *Hub, peerID string) *Connection {
	return &Connection{
		conn:     conn,
		send:     make(chan []byte, 256),
		hub:      hub,
		peerID:   peerID,
		lastPing: time.Now(),
	}
}

// ReadPump handles reading messages from the WebSocket connection
func (c *Connection) ReadPump(handler MessageHandler) {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(MaxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(PongWait))
	c.conn.SetPongHandler(func(string) error {
		c.lastPing = time.Now()
		c.conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	for {
		_, messageData, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Parse protocol message
		msg, err := protocol.FromJSON(messageData)
		if err != nil {
			log.Printf("Invalid message format: %v", err)
			continue
		}

		// Handle the message
		if err := handler.HandleMessage(c, msg); err != nil {
			log.Printf("Message handling error: %v", err)
		}
	}
}

// WritePump handles writing messages to the WebSocket connection
func (c *Connection) WritePump() {
	ticker := time.NewTicker(PingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// SendMessage sends a message through the connection
func (c *Connection) SendMessage(msg *protocol.Message) error {
	data, err := msg.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}

	select {
	case c.send <- data:
		return nil
	default:
		return fmt.Errorf("connection send channel is full")
	}
}

// Ping sends a ping message
func (c *Connection) Ping() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.conn.SetWriteDeadline(time.Now().Add(WriteWait))
	return c.conn.WriteMessage(websocket.PingMessage, nil)
}

// Close closes the connection
func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.conn.Close()
}

// GetPeerID returns the peer ID for this connection
func (c *Connection) GetPeerID() string {
	return c.peerID
}

// SetRelay marks this connection as a relay node
func (c *Connection) SetRelay(isRelay bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isRelay = isRelay
}

// IsRelay returns whether this connection is a relay node
func (c *Connection) IsRelay() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isRelay
}

// HandleWebSocket upgrades an HTTP connection to WebSocket
func HandleWebSocket(hub *Hub, handler MessageHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket upgrade error: %v", err)
			return
		}

		// Generate temporary peer ID until authentication
		peerID := fmt.Sprintf("temp-%d", time.Now().UnixNano())
		
		connection := NewConnection(conn, hub, peerID)
		hub.register <- connection

		// Start connection goroutines
		go connection.WritePump()
		go connection.ReadPump(handler)
	}
}
