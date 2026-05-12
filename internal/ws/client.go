// Package ws implements the WebSocket client for brain communication.
//
// Protocol from build plan Section 2.3:
// - Receives: exec, kill, create_container, destroy_container, register_agent, ping
// - Sends: container_ready, started, output, completed, error, pong
//
// Connection lifecycle from Section 2.4:
// 1. Exchange API token for short-lived ticket via POST /api/daemons/auth
// 2. Connect to wss://brain/ws/daemon?ticket=<jwt>
// 3. Auto-reconnect with exponential backoff (100ms -> 30s max)
//
// Reliability features:
// - Dedicated read/write pump goroutines (no mutex contention)
// - Priority pong channel (heartbeats never blocked by tool results)
// - Daemon-side keepalive ping every 15s (prevents Fly.io proxy idle drops)
// - SetWriteDeadline on every write (prevents indefinite blocking)
// - Background health stats cache (no 1s blocking CPU sample in pong path)
// - In-flight command cancellation on disconnect (prevents goroutine leaks)
// - TCP keepalive on underlying connection
package ws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/revelion/daemon/internal/burp"
	"github.com/revelion/daemon/internal/config"
	dockermgr "github.com/revelion/daemon/internal/docker"
	"github.com/revelion/daemon/internal/health"
)

const (
	// Write deadline for WebSocket writes. If a write takes longer than this,
	// the connection is considered dead and will be closed.
	writeDeadline = 10 * time.Second

	// Read deadline — extended on every received message. If no message
	// (including pong frames) arrives within this window, we reconnect.
	readDeadline = 180 * time.Second

	// Daemon-side keepalive interval. Sends a ping frame every 15s to keep
	// Fly.io proxy (and any other intermediate proxies) from dropping the
	// connection due to idle timeout.
	keepaliveInterval = 15 * time.Second

	// Size of the normal send channel. Large enough to buffer output chunks
	// and tool results without blocking producers.
	sendChanSize = 256

	// Maximum reconnect backoff.
	maxBackoff = 30 * time.Second
)

// Client manages the persistent WebSocket connection to the brain.
type Client struct {
	cfg       *config.Config
	docker    *dockermgr.Manager
	reporter  *health.Reporter
	burp      *burp.Manager
	extension *burp.ExtensionServer

	// Connection state — only accessed by connect/reconnect goroutine
	conn   *websocket.Conn
	connMu sync.Mutex // only protects conn pointer swap during connect/close

	// Channel-based write pump (replaces mutex-guarded writeJSON)
	pongCh chan []byte // cap 1, priority — pong messages jump the queue
	sendCh chan []byte // cap 256, normal — tool results, output, etc.

	// Lifecycle
	done     chan struct{}
	doneOnce sync.Once

	// Track running executions for kill support + cleanup on disconnect
	runningMu sync.Mutex
	running   map[string]chan struct{} // cmd_id -> cancel channel
}

// Message is a generic WebSocket message envelope.
type Message struct {
	Type            string          `json:"type"`
	ID              string          `json:"id,omitempty"`
	RequestID       string          `json:"request_id,omitempty"`
	ScanID          string          `json:"scan_id,omitempty"`
	AgentID         string          `json:"agent_id,omitempty"`
	ToolName        string          `json:"tool_name,omitempty"`
	Parameters      json.RawMessage `json:"parameters,omitempty"`
	Timeout         int             `json:"timeout,omitempty"`
	Image           string          `json:"image,omitempty"`
	Capabilities    []string        `json:"capabilities,omitempty"`
	ProxyProvider   string          `json:"proxy_provider,omitempty"`
	SandboxProxyURL string          `json:"sandbox_proxy_url,omitempty"`
	MissionID       string          `json:"mission_id,omitempty"`
	BurpToolName    string          `json:"burp_tool_name,omitempty"`
	BurpRESTAction  string          `json:"burp_rest_action,omitempty"`
	SnapshotID      string          `json:"snapshot_id,omitempty"`
	IncludeRules    []string        `json:"include_rules,omitempty"`
	ExcludeRules    []string        `json:"exclude_rules,omitempty"`
	Autonomous      bool            `json:"autonomous,omitempty"`
	// VPN config (passed in create_container)
	VPNConfig *VPNConfig `json:"vpn_config,omitempty"`
	// Response fields
	Result         string `json:"result,omitempty"`
	Error          string `json:"error,omitempty"`
	ExitCode       *int   `json:"exit_code,omitempty"`
	Data           string `json:"data,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	ToolServerPort int    `json:"tool_server_port,omitempty"`
	DurationMs     int    `json:"duration_ms,omitempty"`
	StatusCode     int    `json:"status_code,omitempty"`
}

// VPNConfig holds VPN tunnel configuration for sandbox containers.
type VPNConfig struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`    // "openvpn" or "wireguard"
	Config   string `json:"config_data"` // base64-encoded .ovpn or .conf
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// ticketResponse is the response from POST /api/daemons/auth
type ticketResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresIn int    `json:"expires_in"`
}

func NewClient(cfg *config.Config, docker *dockermgr.Manager, reporter *health.Reporter) *Client {
	return &Client{
		cfg:      cfg,
		docker:   docker,
		reporter: reporter,
		burp: burp.NewManager(burp.Config{
			ProxyURL:          cfg.BurpProxyURL,
			MCPURL:            cfg.BurpMCPURL,
			RESTURL:           cfg.BurpRESTURL,
			CAPath:            cfg.BurpCAPath,
			AutonomousMode:    cfg.BurpAutonomousMode,
			RESTKeyConfigured: strings.TrimSpace(cfg.BurpRESTAPIKey) != "",
		}),
		pongCh:  make(chan []byte, 1),
		sendCh:  make(chan []byte, sendChanSize),
		done:    make(chan struct{}),
		running: make(map[string]chan struct{}),
	}
}

func (c *Client) SetExtensionServer(extension *burp.ExtensionServer) {
	c.extension = extension
	if extension != nil {
		extension.SetScanIssueHandler(c.handleExtensionScanIssue)
	}
}

// sendMsg serialises a message and queues it for sending via the write pump.
// Non-blocking: if the send channel is full, the message is dropped with a warning.
// Pong messages use the priority channel and are never dropped.
func (c *Client) sendMsg(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("Failed to marshal message: %v", err)
		return
	}

	// Check if this is a pong — route to priority channel
	if msg, ok := v.(health.PongMessage); ok && msg.Type == "pong" {
		select {
		case c.pongCh <- data:
		default:
			// Pong channel full (cap 1) — replace stale pong with fresh one
			select {
			case <-c.pongCh:
			default:
			}
			c.pongCh <- data
		}
		return
	}

	// Also check raw Message type
	if msg, ok := v.(Message); ok && msg.Type == "pong" {
		select {
		case c.pongCh <- data:
		default:
			select {
			case <-c.pongCh:
			default:
			}
			c.pongCh <- data
		}
		return
	}

	// Normal message — non-blocking send
	select {
	case c.sendCh <- data:
	default:
		log.Printf("WARNING: send channel full, dropping message")
	}
}

// sendMsgSync is like sendMsg but blocks until the message is queued.
// Used for critical messages (started, completed, error) that must not be dropped.
func (c *Client) sendMsgSync(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("Failed to marshal message: %v", err)
		return
	}
	select {
	case c.sendCh <- data:
	case <-c.done:
	}
}

// writePump is the sole goroutine that writes to the WebSocket.
// It drains the priority pong channel first, then the normal send channel.
// Sends a keepalive ping every 15s regardless of data traffic.
// Exits when done is closed or a write fails (triggering reconnect).
func (c *Client) writePump(conn *websocket.Conn, stopped chan struct{}) {
	ticker := time.NewTicker(keepaliveInterval)
	defer func() {
		ticker.Stop()
		close(stopped)
	}()

	// sendPing sends a WebSocket ping frame. Returns error if connection is dead.
	sendPing := func() error {
		conn.SetWriteDeadline(time.Now().Add(writeDeadline))
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			log.Printf("Write pump: keepalive ping failed: %v", err)
			return err
		}
		return nil
	}

	for {
		// Priority 1: always drain pong channel first (non-blocking)
		select {
		case data := <-c.pongCh:
			if err := c.writeRaw(conn, data); err != nil {
				log.Printf("Write pump: pong write failed: %v", err)
				return
			}
		default:
		}

		// Priority 2: check if ping is due (non-blocking)
		select {
		case <-ticker.C:
			if err := sendPing(); err != nil {
				return
			}
		default:
		}

		// Now wait for data, pong, ping, or shutdown
		select {
		case data := <-c.pongCh:
			if err := c.writeRaw(conn, data); err != nil {
				log.Printf("Write pump: pong write failed: %v", err)
				return
			}
		case data := <-c.sendCh:
			if err := c.writeRaw(conn, data); err != nil {
				log.Printf("Write pump: write failed: %v", err)
				return
			}
			// After writing data, drain up to 16 more queued messages
			// but check for pending pings between each batch
		drain:
			for i := 0; i < 16; i++ {
				// Check ping between batch writes
				select {
				case <-ticker.C:
					if err := sendPing(); err != nil {
						return
					}
				default:
				}
				// Try to drain another message (non-blocking)
				select {
				case data := <-c.sendCh:
					if err := c.writeRaw(conn, data); err != nil {
						log.Printf("Write pump: write failed: %v", err)
						return
					}
				default:
					break drain
				}
			}
		case <-ticker.C:
			if err := sendPing(); err != nil {
				return
			}
		case <-c.done:
			// Graceful shutdown: send close frame
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "daemon shutdown"))
			return
		}
	}
}

// writeRaw writes pre-serialised JSON bytes to the WebSocket with a deadline.
func (c *Client) writeRaw(conn *websocket.Conn, data []byte) error {
	conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	return conn.WriteMessage(websocket.TextMessage, data)
}

// readPump is the sole goroutine that reads from the WebSocket.
// Extends read deadline on every message. Exits on any read error.
func (c *Client) readPump(conn *websocket.Conn) {
	conn.SetReadDeadline(time.Now().Add(readDeadline))

	// Extend read deadline whenever we receive a WebSocket pong frame
	// (response to our keepalive pings)
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(readDeadline))
		return nil
	})

	// Also extend read deadline on ping frames from the brain
	// (gorilla default PingHandler sends pong via WriteControl which is goroutine-safe)
	conn.SetPingHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(readDeadline))
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(writeDeadline))
	})

	for {
		_, rawMsg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Read error: %v", err)
			}
			return
		}

		// Any message extends the read deadline
		conn.SetReadDeadline(time.Now().Add(readDeadline))

		var msg Message
		if err := json.Unmarshal(rawMsg, &msg); err != nil {
			log.Printf("Failed to unmarshal message: %v", err)
			continue
		}

		c.handleMessage(msg)
	}
}

// ConnectAndServe connects to the brain and processes messages forever.
// Reconnects with exponential backoff on disconnect.
func (c *Client) ConnectAndServe() {
	backoff := 100 * time.Millisecond
	prePullDone := false

	for {
		conn, err := c.connect()
		if err != nil {
			log.Printf("Connection failed: %v, retrying in %v", err, backoff)
			select {
			case <-c.done:
				return
			case <-time.After(backoff):
			}
			backoff = time.Duration(math.Min(float64(backoff)*2, float64(maxBackoff)))
			continue
		}

		// Connected — reset backoff
		backoff = 100 * time.Millisecond
		log.Println("Connected to brain")

		// Drain any stale messages from previous connection
		c.drainChannels()

		// Pre-pull sandbox image on first connection + register retry callback
		if !prePullDone {
			prePullDone = true
			c.reporter.SetOnNeedsPull(func() { c.prePullSandboxImage() })
			go c.prePullSandboxImage()
		}

		// Start read and write pumps
		writeStopped := make(chan struct{})
		go c.writePump(conn, writeStopped)
		c.readPump(conn) // blocks until read error

		// Read pump exited — connection is dead
		// Close the connection to unblock write pump
		conn.Close()
		<-writeStopped // wait for write pump to exit

		// Cancel all in-flight commands
		c.cancelAllRunning()

		select {
		case <-c.done:
			return
		default:
			log.Println("Disconnected from brain, reconnecting...")
		}
	}
}

// drainChannels clears stale messages from send channels after reconnect.
func (c *Client) drainChannels() {
	for {
		select {
		case <-c.pongCh:
		case <-c.sendCh:
		default:
			return
		}
	}
}

// cancelAllRunning closes all in-flight command cancel channels.
// Called on disconnect to prevent goroutine leaks.
func (c *Client) cancelAllRunning() {
	c.runningMu.Lock()
	defer c.runningMu.Unlock()

	count := len(c.running)
	for id, ch := range c.running {
		select {
		case <-ch:
			// Already closed
		default:
			close(ch)
		}
		delete(c.running, id)
	}
	if count > 0 {
		log.Printf("Cancelled %d in-flight commands on disconnect", count)
	}
}

// exchangeTicket calls POST /api/daemons/auth to get a short-lived WebSocket ticket.
func (c *Client) exchangeTicket() (string, error) {
	httpURL := c.cfg.BrainURL
	httpURL = strings.Replace(httpURL, "wss://", "https://", 1)
	httpURL = strings.Replace(httpURL, "ws://", "http://", 1)
	authURL := httpURL + "/api/daemons/auth"

	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("create auth request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed (%d): %s", resp.StatusCode, string(body))
	}

	var ticketResp ticketResponse
	if err := json.NewDecoder(resp.Body).Decode(&ticketResp); err != nil {
		return "", fmt.Errorf("decode ticket: %w", err)
	}
	return ticketResp.Ticket, nil
}

func (c *Client) connect() (*websocket.Conn, error) {
	// Step 1: Exchange API token for short-lived WebSocket ticket
	ticket, err := c.exchangeTicket()
	if err != nil {
		return nil, fmt.Errorf("ticket exchange: %w", err)
	}

	// Step 2: Connect WebSocket with ticket in Authorization header
	wsURL := c.cfg.BrainURL + "/ws/daemon"

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+ticket)

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		NetDialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second, // TCP keepalive
		}).DialContext,
	}

	conn, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	// Enable compression if supported
	conn.EnableWriteCompression(true)

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	return conn, nil
}

func (c *Client) handleMessage(msg Message) {
	switch msg.Type {
	case "ping":
		pong := c.reporter.GetPongCached()
		c.sendMsg(pong)

	case "exec":
		go c.handleExec(msg)

	case "kill":
		c.handleKill(msg)

	case "create_container":
		go c.handleCreateContainer(msg)

	case "destroy_container":
		go c.handleDestroyContainer(msg)

	case "register_agent":
		go c.handleRegisterAgent(msg)

	case "burp_health":
		go c.handleBurpHealth(msg)

	case "burp_acquire_mission":
		go c.handleBurpAcquireMission(msg)

	case "burp_release_mission":
		go c.handleBurpReleaseMission(msg)

	case "burp_disconnect":
		go c.handleBurpDisconnect(msg)

	case "burp_store_rest_key":
		go c.handleBurpStoreRESTKey(msg)

	case "burp_install_ca":
		go c.handleBurpInstallCA(msg)

	case "burp_configure_approval_mode":
		go c.handleBurpConfigureApprovalMode(msg)

	case "burp_mcp_call":
		go c.handleBurpMCPCall(msg)

	case "burp_rest_call":
		go c.handleBurpRESTCall(msg)

	case "burp_scope_set":
		go c.handleBurpScopeSet(msg)

	case "burp_scope_restore":
		go c.handleBurpScopeRestore(msg)

	case "burp_approval_gates_set":
		go c.handleBurpApprovalGatesSet(msg)

	case "burp_approval_gates_restore":
		go c.handleBurpApprovalGatesRestore(msg)

	case "burp_scan_start":
		go c.handleBurpScanStart(msg)

	case "burp_scan_cancel":
		go c.handleBurpScanCancel(msg)

	case "burp_pair_initiate_request",
		"burp_pair_status_request",
		"burp_pair_cancel_request",
		"burp_pair_disconnect_request",
		"burp_state_request",
		"burp_scope_active_request",
		"burp_scope_clear_request",
		"burp_approval_gates_active_request":
		go c.handleBurpExtensionProxyRequest(msg)

	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}
}

func (c *Client) handleExec(msg Message) {
	// Register cancellation channel
	cancelCh := make(chan struct{})
	c.runningMu.Lock()
	c.running[msg.ID] = cancelCh
	c.runningMu.Unlock()

	defer func() {
		c.runningMu.Lock()
		delete(c.running, msg.ID)
		c.runningMu.Unlock()
	}()

	// Send "started" acknowledgement (critical — use sync send)
	c.sendMsgSync(Message{Type: "started", ID: msg.ID, AgentID: msg.AgentID})

	start := time.Now()

	// Execute in container via tool_server proxy with output streaming
	resultCh := make(chan struct {
		result   string
		exitCode int
		err      error
	}, 1)

	// Output callback: streams chunks to brain, keeping WebSocket alive
	onOutput := func(chunk string) {
		c.sendMsg(Message{Type: "output", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Data: chunk})
	}

	go func() {
		result, exitCode, err := c.docker.ExecuteInContainer(msg.ScanID, msg.AgentID, msg.ToolName, msg.Parameters, onOutput)
		resultCh <- struct {
			result   string
			exitCode int
			err      error
		}{result, exitCode, err}
	}()

	// Wait for result or kill
	select {
	case res := <-resultCh:
		durationMs := int(time.Since(start).Milliseconds())
		if res.err != nil {
			c.sendMsgSync(Message{
				Type:       "error",
				ID:         msg.ID,
				AgentID:    msg.AgentID,
				Error:      res.err.Error(),
				DurationMs: durationMs,
			})
			return
		}
		code := res.exitCode
		c.sendMsgSync(Message{
			Type:       "completed",
			ID:         msg.ID,
			AgentID:    msg.AgentID,
			Result:     res.result,
			ExitCode:   &code,
			DurationMs: durationMs,
		})

	case <-cancelCh:
		durationMs := int(time.Since(start).Milliseconds())
		c.sendMsgSync(Message{
			Type:       "error",
			ID:         msg.ID,
			AgentID:    msg.AgentID,
			Error:      "killed by user",
			DurationMs: durationMs,
		})
	}
}

func (c *Client) handleKill(msg Message) {
	c.runningMu.Lock()
	ch, ok := c.running[msg.ID]
	if ok {
		close(ch)
		delete(c.running, msg.ID)
	}
	c.runningMu.Unlock()

	if ok {
		log.Printf("Killed command %s", msg.ID)
	} else {
		log.Printf("Kill: command %s not found (may have already completed)", msg.ID)
	}
}

func (c *Client) handleCreateContainer(msg Message) {
	imgName := msg.Image
	if imgName == "" {
		imgName = c.cfg.SandboxImage
	}

	// Convert WS VPNConfig to Docker VPNConfig
	var vpn *dockermgr.VPNConfig
	if msg.VPNConfig != nil && msg.VPNConfig.Enabled {
		vpn = &dockermgr.VPNConfig{
			Provider: msg.VPNConfig.Provider,
			Config:   msg.VPNConfig.Config,
			Username: msg.VPNConfig.Username,
			Password: msg.VPNConfig.Password,
		}
	}

	containerID, port, err := c.docker.CreateContainer(msg.ScanID, imgName, msg.Capabilities, vpn, msg.ProxyProvider, msg.SandboxProxyURL, c.cfg.BurpCAPath)
	if err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: err.Error()})
		return
	}

	c.sendMsgSync(Message{
		Type:           "container_ready",
		ScanID:         msg.ScanID,
		ContainerID:    containerID,
		ToolServerPort: port,
	})
}

func (c *Client) handleDestroyContainer(msg Message) {
	if err := c.docker.DestroyContainer(msg.ScanID); err != nil {
		log.Printf("Failed to destroy container for scan %s: %v", msg.ScanID, err)
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: err.Error()})
	}
}

func (c *Client) handleRegisterAgent(msg Message) {
	if err := c.docker.RegisterAgent(msg.ScanID, msg.AgentID); err != nil {
		log.Printf("Failed to register agent %s for scan %s: %v", msg.AgentID, msg.ScanID, err)
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, Error: err.Error()})
		return
	}
	log.Printf("Registered agent %s for scan %s", msg.AgentID, msg.ScanID)
}

func (c *Client) handleBurpHealth(msg Message) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	health := c.burp.Health(ctx)
	payload, _ := json.Marshal(health)
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: string(payload)})
}

func (c *Client) handleBurpAcquireMission(msg Message) {
	missionID := msg.MissionID
	if missionID == "" {
		missionID = msg.ScanID
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	health, err := c.burp.AcquireMission(ctx, missionID)
	payload, _ := json.Marshal(health)
	if err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: err.Error(), Result: string(payload)})
		return
	}
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: string(payload)})
}

func (c *Client) handleBurpReleaseMission(msg Message) {
	missionID := msg.MissionID
	if missionID == "" {
		missionID = msg.ScanID
	}
	if c.extension != nil {
		c.extension.ClearScanForMission(missionID)
	}
	c.burp.ReleaseMission(missionID)
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: `{"released":true}`})
}

func (c *Client) handleBurpDisconnect(msg Message) {
	c.burp.Disconnect()
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: `{"disconnected":true}`})
}

func (c *Client) handleBurpStoreRESTKey(msg Message) {
	var params struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(msg.Parameters, &params); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "invalid_burp_rest_key_payload"})
		return
	}
	key := strings.TrimSpace(params.Key)
	if key == "" {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "missing_burp_rest_key"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.burp.VerifyRESTKey(ctx, key); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "burp_rest_key_verification_failed: " + err.Error()})
		return
	}

	c.cfg.BurpRESTAPIKey = key
	if err := config.Save(c.cfg); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "burp_rest_key_save_failed"})
		return
	}
	c.burp.SetRESTKeyConfigured(true)

	log.Printf("AUDIT burp_rest_key_stored via brain at=%s", time.Now().UTC().Format(time.RFC3339))
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: `{"stored":true}`})
}

func (c *Client) handleBurpInstallCA(msg Message) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	path := strings.TrimSpace(c.cfg.BurpCAPath)
	if path == "" {
		path = config.DefaultBurpCAPath()
	}

	result, err := c.burp.InstallCA(ctx, path)
	if err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "burp_ca_install_failed: " + err.Error()})
		return
	}

	c.cfg.BurpCAPath = result.Path
	if err := config.Save(c.cfg); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "burp_ca_save_failed"})
		return
	}

	payload, _ := json.Marshal(result)
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: string(payload)})
}

func (c *Client) handleBurpConfigureApprovalMode(msg Message) {
	var params struct {
		Autonomous bool `json:"autonomous"`
	}
	if len(msg.Parameters) > 0 {
		if err := json.Unmarshal(msg.Parameters, &params); err != nil {
			c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "invalid_burp_approval_mode_payload"})
			return
		}
	} else {
		params.Autonomous = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	state, err := c.burp.ConfigureApprovalMode(ctx, params.Autonomous)
	if err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "burp_approval_mode_failed: " + err.Error()})
		return
	}

	c.cfg.BurpAutonomousMode = params.Autonomous
	if err := config.Save(c.cfg); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "burp_approval_mode_save_failed"})
		return
	}

	payload, _ := json.Marshal(state)
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: string(payload)})
}

func (c *Client) handleBurpMCPCall(msg Message) {
	missionID := msg.MissionID
	if missionID == "" {
		missionID = msg.ScanID
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	start := time.Now()
	result, err := c.burp.CallTool(ctx, missionID, msg.BurpToolName, msg.Parameters)
	durationMs := int(time.Since(start).Milliseconds())
	if err != nil {
		code := err.Error()
		if errors.Is(err, burp.ErrApprovalPending) {
			var params map[string]any
			if len(msg.Parameters) > 0 {
				_ = json.Unmarshal(msg.Parameters, &params)
			}
			if params == nil {
				params = map[string]any{}
			}
			payload, _ := json.Marshal(burp.BuildApprovalPending(msg.BurpToolName, params))
			c.sendMsgSync(Message{
				Type:       "completed",
				ID:         msg.ID,
				ScanID:     msg.ScanID,
				AgentID:    msg.AgentID,
				Result:     string(payload),
				DurationMs: durationMs,
			})
			return
		}
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: code, DurationMs: durationMs})
		return
	}
	payload, _ := json.Marshal(result)
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Result: string(payload), DurationMs: durationMs})
}

func (c *Client) handleBurpRESTCall(msg Message) {
	action := strings.TrimSpace(msg.BurpRESTAction)
	if action == "" {
		action = strings.TrimSpace(msg.BurpToolName)
	}
	if action == "" {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: "missing_burp_rest_action"})
		return
	}
	key := strings.TrimSpace(c.cfg.BurpRESTAPIKey)
	if key == "" {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: "burp_rest_key_missing"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	start := time.Now()
	var (
		payload any
		err     error
	)

	switch action {
	case "list_scan_configurations":
		payload, err = c.burp.ListScanConfigurations(ctx, key)
	case "create_scan":
		if !c.cfg.BurpRESTFallback {
			err = fmt.Errorf("burp_rest_fallback_disabled")
			break
		}
		payload, err = c.burp.CreateRESTScan(ctx, key, msg.Parameters)
	case "poll_scan":
		if !c.cfg.BurpRESTFallback {
			err = fmt.Errorf("burp_rest_fallback_disabled")
			break
		}
		var params struct {
			TaskID      string `json:"task_id"`
			After       string `json:"after"`
			IssueEvents int    `json:"issue_events"`
		}
		if err = json.Unmarshal(msg.Parameters, &params); err == nil {
			payload, err = c.burp.PollRESTScan(ctx, key, params.TaskID, params.After, params.IssueEvents)
		}
	case "cancel_scan":
		if !c.cfg.BurpRESTFallback {
			err = fmt.Errorf("burp_rest_fallback_disabled")
			break
		}
		var params struct {
			TaskID string `json:"task_id"`
		}
		if err = json.Unmarshal(msg.Parameters, &params); err == nil {
			payload, err = c.burp.CancelRESTScan(ctx, key, params.TaskID)
		}
	case "issue_definitions":
		payload, err = c.burp.GetIssueDefinitions(ctx, key)
	default:
		err = fmt.Errorf("unknown_burp_rest_action: %s", action)
	}

	durationMs := int(time.Since(start).Milliseconds())
	if err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: err.Error(), DurationMs: durationMs})
		return
	}

	switch typed := payload.(type) {
	case json.RawMessage:
		c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Result: string(typed), DurationMs: durationMs})
	case []byte:
		c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Result: string(typed), DurationMs: durationMs})
	default:
		data, marshalErr := json.Marshal(typed)
		if marshalErr != nil {
			c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: "burp_rest_result_marshal_failed", DurationMs: durationMs})
			return
		}
		c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Result: string(data), DurationMs: durationMs})
	}
}

func (c *Client) handleBurpScopeSet(msg Message) {
	if c.extension == nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "extension_not_paired"})
		c.sendMsg(Message{Type: "burp_scope_set_failed", ScanID: msg.ScanID, MissionID: msg.MissionID, Error: "extension_not_paired"})
		return
	}
	missionID := msg.MissionID
	if missionID == "" {
		missionID = msg.ScanID
	}
	if err := c.extension.SendScopeSet(missionID, msg.SnapshotID, msg.IncludeRules, msg.ExcludeRules); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: err.Error()})
		c.sendMsg(Message{Type: "burp_scope_set_failed", ScanID: msg.ScanID, MissionID: missionID, Error: err.Error()})
		return
	}
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: `{"sent":true}`})
}

func (c *Client) handleBurpScopeRestore(msg Message) {
	if c.extension == nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "extension_not_paired"})
		return
	}
	if err := c.extension.SendScopeRestore(msg.SnapshotID); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: err.Error()})
		return
	}
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: `{"sent":true}`})
}

func (c *Client) handleBurpApprovalGatesSet(msg Message) {
	if c.extension == nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "extension_not_paired"})
		return
	}
	if err := c.extension.SendApprovalGatesSet(msg.SnapshotID, msg.Autonomous); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: err.Error()})
		return
	}
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: `{"sent":true}`})
}

func (c *Client) handleBurpApprovalGatesRestore(msg Message) {
	if c.extension == nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: "extension_not_paired"})
		return
	}
	if err := c.extension.SendApprovalGatesRestore(msg.SnapshotID); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, Error: err.Error()})
		return
	}
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, Result: `{"sent":true}`})
}

func (c *Client) handleBurpScanStart(msg Message) {
	if c.extension == nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: "extension_not_paired"})
		return
	}
	var params struct {
		ScanID            string `json:"scan_id"`
		ScanTaskID        string `json:"scan_task_id"`
		MissionID         string `json:"mission_id"`
		TargetURL         string `json:"target_url"`
		ConfigurationName string `json:"configuration_name"`
		AuditConfigLabel  string `json:"audit_config_label"`
	}
	if len(msg.Parameters) > 0 {
		if err := json.Unmarshal(msg.Parameters, &params); err != nil {
			c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: "invalid_burp_scan_start_payload"})
			return
		}
	}
	missionID := strings.TrimSpace(params.MissionID)
	if missionID == "" {
		missionID = strings.TrimSpace(msg.MissionID)
	}
	if missionID == "" {
		missionID = strings.TrimSpace(msg.ScanID)
	}
	scanTaskID := strings.TrimSpace(params.ScanTaskID)
	if scanTaskID == "" {
		scanTaskID = strings.TrimSpace(params.ScanID)
	}
	if scanTaskID == "" {
		scanTaskID = missionID
	}
	label := strings.TrimSpace(params.AuditConfigLabel)
	if label == "" {
		label = strings.TrimSpace(params.ConfigurationName)
	}
	if strings.TrimSpace(params.TargetURL) == "" {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: "missing_burp_scan_target_url"})
		return
	}
	if err := c.extension.SendScanStart(missionID, scanTaskID, params.TargetURL, label); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: err.Error()})
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"sent":               true,
		"scan_id":            scanTaskID,
		"mission_id":         missionID,
		"target_url":         params.TargetURL,
		"audit_config_label": label,
		"control_surface":    "montoya_extension",
	})
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Result: string(payload)})
}

func (c *Client) handleBurpScanCancel(msg Message) {
	if c.extension == nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: "extension_not_paired"})
		return
	}
	var params struct {
		ScanID     string `json:"scan_id"`
		ScanTaskID string `json:"scan_task_id"`
	}
	if len(msg.Parameters) > 0 {
		if err := json.Unmarshal(msg.Parameters, &params); err != nil {
			c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: "invalid_burp_scan_cancel_payload"})
			return
		}
	}
	scanTaskID := strings.TrimSpace(params.ScanTaskID)
	if scanTaskID == "" {
		scanTaskID = strings.TrimSpace(params.ScanID)
	}
	if err := c.extension.SendScanCancel(scanTaskID); err != nil {
		c.sendMsgSync(Message{Type: "error", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Error: err.Error()})
		return
	}
	payload, _ := json.Marshal(map[string]any{"sent": true, "scan_id": scanTaskID})
	c.sendMsgSync(Message{Type: "completed", ID: msg.ID, ScanID: msg.ScanID, AgentID: msg.AgentID, Result: string(payload)})
}

func (c *Client) handleExtensionScanIssue(missionID, scanID string, issue json.RawMessage) {
	if strings.TrimSpace(missionID) == "" {
		log.Printf("Dropping Burp scanner issue without mission correlation")
		return
	}
	envelope := map[string]any{
		"mission_id": missionID,
		"scan_id":    scanID,
		"issue":      json.RawMessage(issue),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		log.Printf("Failed to marshal Burp scanner issue for brain: %v", err)
		return
	}
	log.Printf("Forwarding Burp scanner issue to brain mission=%s scan=%s", missionID, scanID)
	c.sendMsg(Message{
		Type:       "burp_scan_issue",
		ScanID:     missionID,
		MissionID:  missionID,
		Parameters: json.RawMessage(body),
	})
}

func (c *Client) handleBurpExtensionProxyRequest(msg Message) {
	responseType := strings.TrimSuffix(msg.Type, "_request") + "_response"
	requestID := msg.RequestID
	if requestID == "" {
		requestID = msg.ID
	}
	if c.extension == nil {
		c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusServiceUnavailable, map[string]any{
			"error": "extension_server_unavailable",
		})
		return
	}

	switch msg.Type {
	case "burp_pair_initiate_request":
		resp, err := c.extension.InitiatePair()
		if err != nil {
			c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusInternalServerError, map[string]any{
				"error":   "pair_initiate_failed",
				"message": err.Error(),
			})
			return
		}
		c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusOK, resp)

	case "burp_pair_status_request":
		c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusOK, c.extension.PairStatus())

	case "burp_pair_cancel_request":
		if err := c.extension.CancelPair(); err != nil {
			c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusInternalServerError, map[string]any{
				"error":   "pair_cancel_failed",
				"message": err.Error(),
			})
			return
		}
		c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusOK, map[string]any{"cancelled": true})

	case "burp_pair_disconnect_request":
		if err := c.extension.DisconnectExtension(); err != nil {
			c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusInternalServerError, map[string]any{
				"error":   "pair_disconnect_failed",
				"message": err.Error(),
			})
			return
		}
		c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusOK, map[string]any{"disconnected": true})

	case "burp_state_request":
		state, err := c.extension.BurpState()
		if errors.Is(err, burp.ErrExtensionStateNotReceived) {
			c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusNotFound, map[string]any{
				"error": "state_not_received",
			})
			return
		}
		if err != nil {
			c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusInternalServerError, map[string]any{
				"error":   "state_unavailable",
				"message": err.Error(),
			})
			return
		}
		c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusOK, state)

	case "burp_scope_active_request":
		scope := c.extension.ActiveScope()
		if scope == nil {
			c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusNoContent, map[string]any{})
			return
		}
		c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusOK, scope)

	case "burp_scope_clear_request":
		if err := c.extension.ClearScope(); err != nil {
			c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusServiceUnavailable, map[string]any{
				"error":   "scope_clear_failed",
				"message": err.Error(),
			})
			return
		}
		c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusOK, map[string]any{"cleared": true})

	case "burp_approval_gates_active_request":
		gates := c.extension.ActiveApprovalGates()
		if gates == nil {
			c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusNoContent, map[string]any{})
			return
		}
		c.sendBurpExtensionProxyResponse(msg, responseType, http.StatusOK, gates)
	}
}

func (c *Client) sendBurpExtensionProxyResponse(request Message, responseType string, statusCode int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		statusCode = http.StatusInternalServerError
		body = []byte(`{"error":"response_marshal_failed"}`)
	}
	requestID := request.RequestID
	if requestID == "" {
		requestID = request.ID
	}
	c.sendMsgSync(Message{
		Type:       responseType,
		ID:         request.ID,
		RequestID:  requestID,
		StatusCode: statusCode,
		Result:     string(body),
	})
}

// prePullSandboxImage checks Docker availability and pre-pulls the sandbox image if missing.
func (c *Client) prePullSandboxImage() {
	if !c.docker.IsAvailable() {
		log.Println("Docker not available — skipping sandbox image pre-pull")
		return
	}

	imgName := c.cfg.SandboxImage

	// Skip if already pulling or ready
	pong := c.reporter.GetPongCached()
	if pong.ImageStatus == "pulling" || pong.ImageStatus == "ready" {
		return
	}

	if c.docker.IsImagePresent(imgName) {
		log.Printf("Sandbox image %s already present", imgName)
		c.reporter.SetImageStatus("ready", 100)
		return
	}

	log.Printf("Pre-pulling sandbox image %s...", imgName)
	c.reporter.SetImageStatus("pulling", 0)

	err := c.docker.PullImage(imgName, func(pct int) {
		c.reporter.SetImageStatus("pulling", pct)
	})
	if err != nil {
		log.Printf("Failed to pre-pull sandbox image: %v", err)
		c.reporter.SetImageStatus("missing", 0)
		return
	}

	log.Printf("Sandbox image %s pre-pulled successfully", imgName)
	c.reporter.SetImageStatus("ready", 100)
}

// Close shuts down the WebSocket client.
func (c *Client) Close() {
	c.doneOnce.Do(func() {
		close(c.done)
	})

	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMu.Unlock()

	c.cancelAllRunning()
}

// --- Utility: derive HTTP base URL from config ---

func httpBaseURL(cfg *config.Config) string {
	url := cfg.BrainURL
	url = strings.Replace(url, "wss://", "https://", 1)
	url = strings.Replace(url, "ws://", "http://", 1)
	return url
}

// FetchPendingCommands calls the brain's REST API to get pending commands.
func (c *Client) FetchPendingCommands() ([]Message, error) {
	url := httpBaseURL(c.cfg) + "/api/commands/pending"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fetch pending commands (%d): %s", resp.StatusCode, body)
	}

	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)

	var commands []Message
	if err := json.Unmarshal(buf.Bytes(), &commands); err != nil {
		return nil, err
	}
	return commands, nil
}
