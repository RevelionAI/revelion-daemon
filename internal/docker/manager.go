// Package docker manages sandbox containers for scan execution.
//
// One container per scan, with tool_server.py listening on port 48081 inside.
package docker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

const (
	ContainerToolServerPort = "48081"
	ContainerCaidoPort      = "48080"
	HealthCheckTimeout      = 90 * time.Second
	HealthCheckInterval     = 2 * time.Second
	ExecHTTPTimeout         = 150 * time.Second // 120s tool timeout + 30s buffer
	ExecConnectTimeout      = 10 * time.Second
)

// OutputCallback is called with streaming output chunks during tool execution.
type OutputCallback func(chunk string)

// ContainerInfo tracks a running sandbox container.
type ContainerInfo struct {
	ContainerID    string `json:"container_id"`
	ScanID         string `json:"scan_id"`
	ToolServerPort int    `json:"tool_server_port"` // mapped host port
	AuthToken      string `json:"auth_token"`       // tool server bearer token
}

// ToolResult is the response from tool_server.py /execute endpoint.
type ToolResult struct {
	Result interface{} `json:"result"`
	Error  *string     `json:"error"`
}

// Manager handles Docker container lifecycle.
type Manager struct {
	mu         sync.RWMutex
	containers map[string]*ContainerInfo // scan_id -> container
	cli        *client.Client
}

func NewManager() *Manager {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("WARNING: Docker not available: %v", err)
		return &Manager{containers: make(map[string]*ContainerInfo)}
	}
	// Verify Docker connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.Ping(ctx)
	if err != nil {
		log.Printf("WARNING: Docker daemon not reachable: %v", err)
	} else {
		log.Println("Docker connected")
	}
	return &Manager{
		containers: make(map[string]*ContainerInfo),
		cli:        cli,
	}
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateContainer creates a sandbox container for scan execution.
func (m *Manager) CreateContainer(scanID, imgName string, capabilities []string) (string, int, error) {
	if m.cli == nil {
		return "", 0, fmt.Errorf("docker not available")
	}

	// Check if container already exists for this scan
	m.mu.RLock()
	existing, ok := m.containers[scanID]
	m.mu.RUnlock()
	if ok {
		return existing.ContainerID, existing.ToolServerPort, nil
	}

	token := generateToken()
	containerName := fmt.Sprintf("revelion-scan-%s", scanID[:8])

	// Pull image if not present
	ctx := context.Background()
	_, _, err := m.cli.ImageInspectWithRaw(ctx, imgName)
	if err != nil {
		log.Printf("Pulling image %s (this may take a few minutes)...", imgName)
		reader, pullErr := m.cli.ImagePull(ctx, imgName, image.PullOptions{})
		if pullErr != nil {
			return "", 0, fmt.Errorf("pull image: %w", pullErr)
		}
		// Stream pull progress to logs
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		lastStatus := ""
		for scanner.Scan() {
			var event struct {
				Status   string `json:"status"`
				Progress string `json:"progress"`
				ID       string `json:"id"`
			}
			if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Status != "" {
				msg := event.Status
				if event.ID != "" {
					msg = event.ID + ": " + msg
				}
				if event.Progress != "" {
					msg += " " + event.Progress
				}
				if msg != lastStatus {
					log.Printf("  %s", msg)
					lastStatus = msg
				}
			}
		}
		reader.Close()
		log.Printf("Image %s pulled successfully", imgName)
	}

	// Resolve capabilities
	caps := []string{"NET_ADMIN", "NET_RAW"}
	if len(capabilities) > 0 {
		caps = capabilities
	}

	// Container config
	exposedPorts := nat.PortSet{
		nat.Port(ContainerToolServerPort + "/tcp"): struct{}{},
		nat.Port(ContainerCaidoPort + "/tcp"):      struct{}{},
	}

	containerConfig := &container.Config{
		Image:    imgName,
		Hostname: containerName,
		Env: []string{
			"PYTHONUNBUFFERED=1",
			"TOOL_SERVER_PORT=" + ContainerToolServerPort,
			"TOOL_SERVER_TOKEN=" + token,
			"REVELION_SANDBOX_EXECUTION_TIMEOUT=120",
			"HOST_GATEWAY=host.docker.internal",
		},
		ExposedPorts: exposedPorts,
		Cmd:          []string{"sleep", "infinity"},
		Labels: map[string]string{
			"revelion-scan-id": scanID,
		},
		Tty: true,
	}

	hostConfig := &container.HostConfig{
		PortBindings: nat.PortMap{
			nat.Port(ContainerToolServerPort + "/tcp"): []nat.PortBinding{
				{HostIP: "127.0.0.1", HostPort: ""},
			},
			nat.Port(ContainerCaidoPort + "/tcp"): []nat.PortBinding{
				{HostIP: "127.0.0.1", HostPort: ""},
			},
		},
		CapAdd:     caps,
		ExtraHosts: []string{"host.docker.internal:host-gateway"},
	}

	// Create container
	resp, err := m.cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, containerName)
	if err != nil {
		// If name conflict, try to reuse existing
		if strings.Contains(err.Error(), "already in use") {
			return m.recoverContainer(ctx, containerName, scanID, token)
		}
		return "", 0, fmt.Errorf("create container: %w", err)
	}

	// Start container
	if err := m.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", 0, fmt.Errorf("start container: %w", err)
	}

	// Get mapped port
	hostPort, err := m.getMappedPort(ctx, resp.ID, ContainerToolServerPort+"/tcp")
	if err != nil {
		return "", 0, fmt.Errorf("get mapped port: %w", err)
	}

	log.Printf("Container %s created for scan %s (port %d)", resp.ID[:12], scanID, hostPort)

	// Wait for tool_server to be healthy
	if err := m.waitForToolServer(hostPort, token); err != nil {
		log.Printf("WARNING: tool_server health check failed: %v", err)
	}

	info := &ContainerInfo{
		ContainerID:    resp.ID,
		ScanID:         scanID,
		ToolServerPort: hostPort,
		AuthToken:      token,
	}

	m.mu.Lock()
	m.containers[scanID] = info
	m.mu.Unlock()

	return resp.ID, hostPort, nil
}

// recoverContainer handles the case where a container with the name already exists.
func (m *Manager) recoverContainer(ctx context.Context, name, scanID, token string) (string, int, error) {
	inspect, err := m.cli.ContainerInspect(ctx, name)
	if err != nil {
		return "", 0, fmt.Errorf("inspect existing container: %w", err)
	}

	if !inspect.State.Running {
		if err := m.cli.ContainerStart(ctx, inspect.ID, container.StartOptions{}); err != nil {
			return "", 0, fmt.Errorf("start existing container: %w", err)
		}
		inspect, err = m.cli.ContainerInspect(ctx, inspect.ID)
		if err != nil {
			return "", 0, fmt.Errorf("re-inspect container: %w", err)
		}
	}

	// Extract token from env vars
	recoveredToken := token
	for _, env := range inspect.Config.Env {
		if strings.HasPrefix(env, "TOOL_SERVER_TOKEN=") {
			recoveredToken = strings.TrimPrefix(env, "TOOL_SERVER_TOKEN=")
			break
		}
	}

	// Extract port mapping
	portBindings := inspect.NetworkSettings.Ports[nat.Port(ContainerToolServerPort+"/tcp")]
	if len(portBindings) == 0 {
		return "", 0, fmt.Errorf("no port mapping found for recovered container")
	}
	hostPort := 0
	fmt.Sscanf(portBindings[0].HostPort, "%d", &hostPort)

	info := &ContainerInfo{
		ContainerID:    inspect.ID,
		ScanID:         scanID,
		ToolServerPort: hostPort,
		AuthToken:      recoveredToken,
	}

	m.mu.Lock()
	m.containers[scanID] = info
	m.mu.Unlock()

	log.Printf("Recovered container %s for scan %s (port %d)", inspect.ID[:12], scanID, hostPort)
	return inspect.ID, hostPort, nil
}

// getMappedPort returns the host port for a container's exposed port.
func (m *Manager) getMappedPort(ctx context.Context, containerID, containerPort string) (int, error) {
	inspect, err := m.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return 0, err
	}

	bindings := inspect.NetworkSettings.Ports[nat.Port(containerPort)]
	if len(bindings) == 0 {
		return 0, fmt.Errorf("no port binding for %s", containerPort)
	}

	port := 0
	fmt.Sscanf(bindings[0].HostPort, "%d", &port)
	return port, nil
}

// waitForToolServer polls the tool_server health endpoint until it's ready.
func (m *Manager) waitForToolServer(port int, token string) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	deadline := time.Now().Add(HealthCheckTimeout)
	httpClient := &http.Client{Timeout: 5 * time.Second}

	time.Sleep(3 * time.Second)

	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				log.Printf("tool_server healthy on port %d", port)
				return nil
			}
		}
		time.Sleep(HealthCheckInterval)
	}
	return fmt.Errorf("tool_server not ready after %v on port %d", HealthCheckTimeout, port)
}

// ExecuteInContainer forwards a tool execution to the container's tool_server.py.
// The onOutput callback streams stdout/stderr chunks back to the caller,
// which forwards them over the WebSocket to keep the connection alive.
func (m *Manager) ExecuteInContainer(scanID, agentID, toolName string, params json.RawMessage, onOutput OutputCallback) (string, int, error) {
	m.mu.RLock()
	info, ok := m.containers[scanID]
	m.mu.RUnlock()

	if !ok {
		return "", 1, fmt.Errorf("no container for scan %s", scanID)
	}

	// Try streaming endpoint first, fall back to blocking endpoint
	result, exitCode, err := m.executeStreaming(info, agentID, toolName, params, onOutput)
	if err != nil && strings.Contains(err.Error(), "404") {
		// tool_server doesn't support streaming — fall back to blocking
		return m.executeBlocking(info, agentID, toolName, params)
	}
	return result, exitCode, err
}

// executeStreaming calls the /execute_stream endpoint which sends SSE-style chunks.
func (m *Manager) executeStreaming(info *ContainerInfo, agentID, toolName string, params json.RawMessage, onOutput OutputCallback) (string, int, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/execute_stream", info.ToolServerPort)

	body := map[string]interface{}{
		"agent_id":  agentID,
		"tool_name": toolName,
		"kwargs":    json.RawMessage(params),
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", 1, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", 1, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+info.AuthToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	httpClient := &http.Client{Timeout: ExecHTTPTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 1, fmt.Errorf("tool_server request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", 1, fmt.Errorf("404: streaming not supported")
	}

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", 1, fmt.Errorf("tool_server returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Read SSE-style response: lines starting with "data: " are output chunks,
	// final line is JSON result
	var finalResult string
	var finalExitCode int
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			// Try to parse as JSON event
			var event struct {
				Type     string `json:"type"`
				Data     string `json:"data"`
				Result   string `json:"result"`
				ExitCode int    `json:"exit_code"`
				Error    string `json:"error"`
			}
			if json.Unmarshal([]byte(data), &event) == nil {
				switch event.Type {
				case "output":
					if onOutput != nil {
						onOutput(event.Data)
					}
				case "result":
					finalResult = event.Result
					finalExitCode = event.ExitCode
				case "error":
					return "", 1, fmt.Errorf("%s", event.Error)
				}
			} else if onOutput != nil {
				// Raw text chunk
				onOutput(data)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", 1, fmt.Errorf("read stream: %w", err)
	}

	return finalResult, finalExitCode, nil
}

// executeBlocking calls the original /execute endpoint (no streaming).
func (m *Manager) executeBlocking(info *ContainerInfo, agentID, toolName string, params json.RawMessage) (string, int, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/execute", info.ToolServerPort)

	body := map[string]interface{}{
		"agent_id":  agentID,
		"tool_name": toolName,
		"kwargs":    json.RawMessage(params),
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", 1, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", 1, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+info.AuthToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: ExecHTTPTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 1, fmt.Errorf("tool_server request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 1, fmt.Errorf("read response: %w", err)
	}

	var result ToolResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return string(respBody), 0, nil
	}

	if result.Error != nil {
		return "", 1, fmt.Errorf("%s", *result.Error)
	}

	resultStr, err := json.Marshal(result.Result)
	if err != nil {
		return fmt.Sprintf("%v", result.Result), 0, nil
	}
	return string(resultStr), 0, nil
}

// RegisterAgent registers an agent with the container's tool_server.
func (m *Manager) RegisterAgent(scanID, agentID string) error {
	m.mu.RLock()
	info, ok := m.containers[scanID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no container for scan %s", scanID)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/register_agent?agent_id=%s", info.ToolServerPort, agentID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+info.AuthToken)

	httpClient := &http.Client{Timeout: ExecConnectTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("register_agent request: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("register_agent returned %d", resp.StatusCode)
	}
	return nil
}

// DestroyContainer stops and removes a sandbox container.
func (m *Manager) DestroyContainer(scanID string) error {
	m.mu.Lock()
	info, ok := m.containers[scanID]
	delete(m.containers, scanID)
	m.mu.Unlock()

	if !ok || m.cli == nil {
		return nil
	}

	ctx := context.Background()
	timeout := 10

	log.Printf("Destroying container %s for scan %s", info.ContainerID[:12], scanID)

	m.cli.ContainerStop(ctx, info.ContainerID, container.StopOptions{Timeout: &timeout})
	return m.cli.ContainerRemove(ctx, info.ContainerID, container.RemoveOptions{Force: true})
}

// CleanupAll destroys all containers (called on daemon shutdown).
func (m *Manager) CleanupAll() {
	m.mu.RLock()
	scanIDs := make([]string, 0, len(m.containers))
	for id := range m.containers {
		scanIDs = append(scanIDs, id)
	}
	m.mu.RUnlock()

	for _, id := range scanIDs {
		if err := m.DestroyContainer(id); err != nil {
			log.Printf("Failed to destroy container for scan %s: %v", id, err)
		}
	}
}

// ActiveContainers returns the number of running containers.
func (m *Manager) ActiveContainers() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.containers)
}

// GetContainer returns container info for a scan, or nil if not found.
func (m *Manager) GetContainer(scanID string) *ContainerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.containers[scanID]
}
