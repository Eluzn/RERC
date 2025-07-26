package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/eluzn/RERC/internal/peer"
)

func main() {
	var (
		relayNode = flag.String("node", "ws://localhost:8080/ws", "Relay node WebSocket URL")
	)
	flag.Parse()

	log.Printf("Starting RERC Peer Client")
	log.Printf("Relay Node: %s", *relayNode)

	// Create client configuration
	config := &peer.Config{
		RelayNodes: []string{*relayNode},
		OnMessage: func(from string, message []byte) {
			fmt.Printf("\n[%s]: %s\n> ", from, string(message))
		},
		OnPeerUpdate: func(peers []peer.PeerInfo) {
			fmt.Printf("\nPeers updated: %d connected\n> ", len(peers))
		},
		OnError: func(err error) {
			fmt.Printf("\nError: %v\n> ", err)
		},
	}

	// Create and connect the client
	client, err := peer.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	if err := client.Connect(*relayNode); err != nil {
		log.Fatalf("Failed to connect to relay: %v", err)
	}

	fmt.Printf("Connected as peer: %s\n", client.GetID())
	fmt.Println("Commands:")
	fmt.Println("  /peers - List connected peers")
	fmt.Println("  /discover - Discover new peers")
	fmt.Println("  /msg <peer_id> <message> - Send message to peer")
	fmt.Println("  /quit - Exit the client")
	fmt.Print("> ")

	// Start interactive shell
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Print("> ")
			continue
		}

		if strings.HasPrefix(line, "/") {
			handleCommand(client, line)
		} else {
			fmt.Println("Unknown command. Type /help for available commands.")
		}

		fmt.Print("> ")
	}

	// Cleanup
	if err := client.Disconnect(); err != nil {
		log.Printf("Error disconnecting: %v", err)
	}
}

func handleCommand(client *peer.Client, command string) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "/peers":
		peers := client.GetPeers()
		if len(peers) == 0 {
			fmt.Println("No peers connected")
		} else {
			fmt.Printf("Connected peers (%d):\n", len(peers))
			for _, peer := range peers {
				relayStatus := ""
				if peer.IsRelay {
					relayStatus = " (relay)"
				}
				fmt.Printf("  - %s%s\n", peer.ID, relayStatus)
			}
		}

	case "/discover":
		if err := client.DiscoverPeers(); err != nil {
			fmt.Printf("Error discovering peers: %v\n", err)
		} else {
			fmt.Println("Peer discovery request sent")
		}

	case "/msg":
		if len(parts) < 3 {
			fmt.Println("Usage: /msg <peer_id> <message>")
			return
		}

		peerID := parts[1]
		message := strings.Join(parts[2:], " ")

		if err := client.SendMessage(peerID, []byte(message)); err != nil {
			fmt.Printf("Error sending message: %v\n", err)
		} else {
			fmt.Printf("Message sent to %s\n", peerID)
		}

	case "/quit":
		fmt.Println("Goodbye!")
		os.Exit(0)

	case "/help":
		fmt.Println("Available commands:")
		fmt.Println("  /peers - List connected peers")
		fmt.Println("  /discover - Discover new peers")
		fmt.Println("  /msg <peer_id> <message> - Send message to peer")
		fmt.Println("  /quit - Exit the client")

	default:
		fmt.Printf("Unknown command: %s\n", parts[0])
		fmt.Println("Type /help for available commands")
	}
}
