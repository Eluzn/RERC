# Distributed Encrypted Relay Chat (RERC)

A lightweight, secure, distributed end-to-end encrypted relay chat system built in Go.

## Features

- 🔐 End-to-end encryption using Curve25519 + AES-256-GCM
- 🌐 Distributed peer-to-peer architecture with relay nodes
- 🚀 High performance with <50MB memory footprint
- 🔑 Forward secrecy with X3DH key exchange
- 📡 WebSocket-based real-time communication
- 🛡️ Zero-knowledge relay nodes (cannot decrypt messages)
- 🔍 Dynamic peer discovery
- ⚡ Message replay protection

## Architecture

```
Peer A ←→ Relay Node 1 ←→ Relay Node 2 ←→ Peer B
           ↕                    ↕
      Relay Node 3 ←→ Relay Node 4
```

- Messages are encrypted end-to-end between peers
- Relay nodes forward encrypted messages without decryption capability
- Multiple relay paths for redundancy and fault tolerance

## Security Model

- **End-to-End Encryption**: All messages encrypted with ephemeral keys
- **Forward Secrecy**: Key rotation prevents retroactive decryption
- **Authentication**: Ed25519 signatures for message authenticity
- **Replay Protection**: Timestamps and sequence numbers prevent replay attacks
- **Zero-Knowledge Relays**: Relay nodes cannot decrypt message content

## Quick Start

```bash
# Build the relay node
go build -o rerc-node ./cmd/node

# Build the client
go build -o rerc-client ./cmd/client

# Start a relay node
./rerc-node -port 8080

# Connect with a client
./rerc-client -node ws://localhost:8080
```

## Project Structure

```
├── cmd/                    # Application entry points
│   ├── node/              # Relay node binary
│   └── client/            # Client binary
├── internal/              # Private application code
│   ├── crypto/            # Cryptographic primitives
│   ├── network/           # Network and transport layer
│   ├── relay/             # Relay node implementation
│   ├── peer/              # Peer client implementation
│   └── protocol/          # Message protocol definitions
├── pkg/                   # Public library code
└── tests/                 # Integration tests
```

## License

MIT License
