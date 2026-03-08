// Revelion Daemon - bridges cloud brain to local Docker containers.
//
// Architecture (from build plan Section 4):
// - WebSocket client with auto-reconnect (exponential backoff)
// - Docker manager for container lifecycle
// - Tool server proxy (forwards exec messages to container port 48081)
// - Health reporter (system stats in pong messages)
// - Backlog processor (catches up on missed commands after reconnect)
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/revelion/daemon/internal/config"
	dockermgr "github.com/revelion/daemon/internal/docker"
	"github.com/revelion/daemon/internal/health"
	"github.com/revelion/daemon/internal/ws"
)

// Version is set at build time via -ldflags
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "auth":
		runAuth()
	case "start":
		runDaemon()
	case "status":
		runStatus()
	case "version":
		fmt.Printf("revelion-daemon %s\n", Version)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`Revelion Daemon %s - Local execution layer for Revelion pentesting platform

Usage:
  revelion auth <token>  Authenticate with your API token
  revelion start         Start the daemon
  revelion status        Check daemon configuration
  revelion version       Print version
`, Version)
}

func runAuth() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: revelion auth <api-token>")
		fmt.Println("")
		fmt.Println("Find your API token at: https://revelion-ten.vercel.app/agents")
		os.Exit(1)
	}
	token := os.Args[2]

	// Load existing config or use defaults
	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}
	cfg.APIToken = token

	if err := config.Save(cfg); err != nil {
		log.Fatalf("Failed to save config: %v", err)
	}
	fmt.Println("Authenticated successfully. Run 'revelion start' to connect.")
}

func runStatus() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Println("Status: NOT CONFIGURED")
		fmt.Println("")
		fmt.Println("Run 'revelion auth <token>' to authenticate.")
		os.Exit(1)
	}

	masked := cfg.APIToken
	if len(masked) > 8 {
		masked = masked[:4] + "..." + masked[len(masked)-4:]
	}

	fmt.Println("Status: CONFIGURED")
	fmt.Printf("  Token:    %s\n", masked)
	fmt.Printf("  Brain:    %s\n", cfg.BrainURL)
	fmt.Printf("  Sandbox:  %s\n", cfg.SandboxImage)
	fmt.Printf("  Config:   ~/.revelion/config.json\n")
}

func runDaemon() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Config not found. Run 'revelion auth <token>' first: %v", err)
	}

	docker := dockermgr.NewManager()
	reporter := health.NewReporter(docker)
	client := ws.NewClient(cfg, docker, reporter)

	// Handle shutdown gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down daemon...")
		client.Close()
		reporter.Stop()
		docker.CleanupAll()
		os.Exit(0)
	}()

	log.Printf("Starting Revelion daemon %s...", Version)
	client.ConnectAndServe()
}
