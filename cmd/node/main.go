package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/rerc/distributed-relay-chat/internal/relay"
)

func main() {
	var (
		listenAddr   = flag.String("addr", ":8080", "Listen address for the relay node")
		dbPath       = flag.String("db", "relay.db", "Database file path")
		maxPeers     = flag.Int("peers", 1000, "Maximum number of connected peers")
		isBootstrap  = flag.Bool("bootstrap", false, "Run as bootstrap node")
	)
	flag.Parse()

	log.Printf("Starting RERC Relay Node")
	log.Printf("Listen Address: %s", *listenAddr)
	log.Printf("Database Path: %s", *dbPath)
	log.Printf("Max Peers: %d", *maxPeers)
	log.Printf("Bootstrap Node: %v", *isBootstrap)

	// Create relay node configuration
	config := &relay.Config{
		ListenAddr:   *listenAddr,
		DatabasePath: *dbPath,
		MaxPeers:     *maxPeers,
		IsBootstrap:  *isBootstrap,
	}

	// Create and start the relay node
	node, err := relay.NewNode(config)
	if err != nil {
		log.Fatalf("Failed to create relay node: %v", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down relay node...")
		if err := node.Stop(); err != nil {
			log.Printf("Error stopping node: %v", err)
		}
		os.Exit(0)
	}()

	// Start the relay node
	if err := node.Start(*listenAddr); err != nil {
		log.Fatalf("Failed to start relay node: %v", err)
	}
}
