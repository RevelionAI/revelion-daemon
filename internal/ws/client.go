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
	"encoding/json"
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
	readDeadline = 90 * time.Second

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
	cfg      *config.Config
	docker   *dockermgr.Manager
	reporter *health.Reporter

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
	Type         string          `json:"type"`
	ID           string          `json:"id,omitempty"`
	ScanID       string          `json:"scan_id,omitempty"`
	AgentID      string          `json:"agent_id,omitempty"`
	ToolName     string          `json:"tool_name,omitempty"`
	Parameters   json.RawMessage `json:"parameters,omitempty"`
	Timeout      int             `json:"timeout,omitempty"`
	Image        string          `json:"image,omitempty"`
	Capabilities []string        `json:"capabilities,omitempty"`
	// Response fields
	Result         string `json:"result,omitempty"`
	Error          string `json:"error,omitempty"`
	ExitCode       *int   `json:"exit_code,omitempty"`
	Data           string `json:"data,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	ToolServerPort int    `json:"tool_server_port,omitempty"`
	DurationMs     int    `json:"duration_ms,omitempty"`
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
		pongCh:   make(chan []byte, 1),
		sendCh:   make(chan []byte, sendChanSize),
		done:     make(chan struct{}),
		running:  make(map[string]chan struct{}),
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
// Exits when done is closed or a write fails (triggering reconnect).
func (c *Client) writePump(conn *websocket.Conn, stopped chan struct{}) {
	ticker := time.NewTicker(keepaliveInterval)
	defer func() {
		ticker.Stop()
		close(stopped)
	}()

	for {
		// Priority: always check pong first
		select {
		case data := <-c.pongCh:
			if err := c.writeRaw(conn, data); err != nil {
				log.Printf("Write pump: pong write failed: %v", err)
				return
			}
		default:
		}

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
		case <-ticker.C:
			// Daemon-side keepalive: send WebSocket ping frame
			conn.SetWriteDeadline(time.Now().Add(writeDeadline))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("Write pump: keepalive ping failed: %v", err)
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
		c.sendMsg(Message{Type: "output", ID: msg.ID, AgentID: msg.AgentID, Data: chunk})
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

	containerID, port, err := c.docker.CreateContainer(msg.ScanID, imgName, msg.Capabilities)
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
