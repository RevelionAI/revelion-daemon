// Package burp manages the local Burp Suite bridge used by web missions.
package burp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	DefaultProxyURL = "http://127.0.0.1:8080"
	DefaultMCPURL   = "http://127.0.0.1:9876"
	DefaultRESTURL  = "http://127.0.0.1:1337"

	ApprovalTimeout = 30 * time.Second
)

var ErrApprovalPending = errors.New("burp_mcp_approval_pending")

// Config holds local Burp connection settings.
type Config struct {
	ProxyURL       string
	MCPURL         string
	RESTURL        string
	CAPath         string
	AutonomousMode bool
	RESTKeyConfigured bool
}

func DefaultConfig() Config {
	return Config{
		ProxyURL:       DefaultProxyURL,
		MCPURL:         DefaultMCPURL,
		RESTURL:        DefaultRESTURL,
		AutonomousMode: true,
	}
}

// Health describes daemon-observed Burp capability state.
type Health struct {
	ProxyReachable                bool     `json:"proxy_reachable"`
	MCPReachable                  bool     `json:"mcp_reachable"`
	RESTReachable                 bool     `json:"rest_reachable"`
	RESTKeyConfigured             bool     `json:"rest_key_configured"`
	Edition                       string   `json:"edition"`
	ProLicense                    bool     `json:"pro_license"`
	BridgeEnabled                 bool     `json:"burp_bridge_enabled"`
	BlockedReason                 string   `json:"blocked_reason,omitempty"`
	MCPServerName                 string   `json:"mcp_server_name,omitempty"`
	MCPServerVersion              string   `json:"mcp_server_version,omitempty"`
	MCPToolCount                  int      `json:"mcp_tool_count"`
	MCPTools                      []string `json:"mcp_tools,omitempty"`
	CAConfigured                  bool     `json:"ca_configured"`
	CAFingerprint                 string   `json:"ca_fingerprint,omitempty"`
	CAPath                        string   `json:"ca_path,omitempty"`
	ActiveMissionID               string   `json:"active_mission_id,omitempty"`
	SandboxProxyURL               string   `json:"sandbox_proxy_url,omitempty"`
	ForwarderLocalPort            int      `json:"forwarder_local_port,omitempty"`
	AutonomousMode                bool     `json:"autonomous_mode"`
	ApprovalGateConfigSupported   bool     `json:"approval_gate_config_supported"`
	ApprovalGatesAutonomousReady  bool     `json:"approval_gates_autonomous_ready"`
	HTTPRequestApprovalRequired   bool     `json:"require_http_request_approval"`
	HistoryAccessApprovalRequired bool     `json:"require_history_access_approval"`
	ApprovalGateDetail            string   `json:"approval_gate_detail,omitempty"`
}

type CAInstallResult struct {
	Installed   bool   `json:"installed"`
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
	SourceURL   string `json:"source_url"`
}

// ToolResult is a raw MCP tool result.
type ToolResult struct {
	ToolName string          `json:"tool_name"`
	Result   json.RawMessage `json:"result"`
}

type ApprovalPending struct {
	Status       string         `json:"status"`
	Host         string         `json:"host"`
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	OriginalCall map[string]any `json:"original_call"`
}

type ApprovalGateState struct {
	Supported                     bool     `json:"approval_gate_config_supported"`
	HTTPRequestApprovalRequired   bool     `json:"require_http_request_approval"`
	HistoryAccessApprovalRequired bool     `json:"require_history_access_approval"`
	AutonomousReady               bool     `json:"autonomous_ready"`
	ManualRequired                bool     `json:"manual_required"`
	Mode                          string   `json:"mode"`
	Source                        string   `json:"source,omitempty"`
	KeysFound                     []string `json:"keys_found,omitempty"`
	Detail                        string   `json:"detail,omitempty"`
	httpPath                      []string
	historyPath                   []string
}

type Manager struct {
	cfg Config

	httpClient *http.Client

	mu              sync.Mutex
	activeMissionID string
	tools           []string
	serverName      string
	serverVersion   string

	forwarder *Forwarder
}

func NewManager(cfg Config) *Manager {
	if cfg.ProxyURL == "" {
		cfg.ProxyURL = DefaultProxyURL
	}
	if cfg.MCPURL == "" {
		cfg.MCPURL = DefaultMCPURL
	}
	if cfg.RESTURL == "" {
		cfg.RESTURL = DefaultRESTURL
	}
	// The product default is autonomous mode. Supervised mode is explicit opt-in.
	return &Manager{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (m *Manager) Health(ctx context.Context) Health {
	health := Health{
		ProxyReachable:    m.tcpReachable(m.cfg.ProxyURL),
		RESTReachable:     m.tcpReachable(m.cfg.RESTURL),
		RESTKeyConfigured: m.cfg.RESTKeyConfigured,
		AutonomousMode:    m.cfg.AutonomousMode,
	}

	tools, name, version, err := m.discoverTools(ctx)
	if err == nil {
		health.MCPReachable = true
		health.MCPTools = tools
		health.MCPToolCount = len(tools)
		health.MCPServerName = name
		health.MCPServerVersion = version
	}
	if fingerprint, err := caFingerprint(m.cfg.CAPath); err == nil && fingerprint != "" {
		health.CAConfigured = true
		health.CAFingerprint = fingerprint
		health.CAPath = m.cfg.CAPath
	}
	if health.MCPReachable {
		if state, err := m.ApprovalGateState(ctx); err == nil {
			health.ApprovalGateConfigSupported = state.Supported
			health.ApprovalGatesAutonomousReady = state.AutonomousReady
			health.HTTPRequestApprovalRequired = state.HTTPRequestApprovalRequired
			health.HistoryAccessApprovalRequired = state.HistoryAccessApprovalRequired
			health.ApprovalGateDetail = state.Detail
		}
	}

	pro := hasTool(tools, "get_scanner_issues") &&
		hasTool(tools, "generate_collaborator_payload") &&
		hasTool(tools, "get_collaborator_interactions")

	if pro {
		health.Edition = "professional"
		health.ProLicense = true
		health.BridgeEnabled = true
	} else if health.MCPReachable {
		health.Edition = "community"
		health.ProLicense = false
		health.BridgeEnabled = false
		health.BlockedReason = "burp_pro_required"
	} else {
		health.Edition = "unknown"
		health.ProLicense = false
		health.BridgeEnabled = false
		health.BlockedReason = "burp_mcp_unreachable"
	}

	m.mu.Lock()
	health.ActiveMissionID = m.activeMissionID
	if m.forwarder != nil {
		health.ForwarderLocalPort = m.forwarder.Port()
		health.SandboxProxyURL = fmt.Sprintf("http://host.docker.internal:%d", m.forwarder.Port())
	}
	m.mu.Unlock()

	return health
}

func (m *Manager) VerifyRESTKey(ctx context.Context, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("missing REST API key")
	}
	parsed, err := url.Parse(m.cfg.RESTURL)
	if err != nil {
		return fmt.Errorf("invalid REST URL")
	}
	parsed.Path = "/" + strings.Trim(key, "/") + "/v0.1/openapi.json"
	parsed.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return fmt.Errorf("build REST verification request")
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("REST listener unreachable")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("REST API returned %d", resp.StatusCode)
	}
	return nil
}

func (m *Manager) SetCAPath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.CAPath = path
}

func (m *Manager) SetRESTKeyConfigured(configured bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.RESTKeyConfigured = configured
}

func (m *Manager) InstallCA(ctx context.Context, destinationPath string) (CAInstallResult, error) {
	destinationPath = strings.TrimSpace(destinationPath)
	if destinationPath == "" {
		return CAInstallResult{}, fmt.Errorf("missing CA destination path")
	}
	proxyURL, err := url.Parse(m.cfg.ProxyURL)
	if err != nil {
		return CAInstallResult{}, fmt.Errorf("invalid Burp proxy URL")
	}

	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	var lastErr error
	for _, sourceURL := range []string{"http://burpsuite/cert", "http://burp/cert"} {
		certPEM, fingerprint, err := fetchBurpCA(ctx, client, sourceURL)
		if err != nil {
			lastErr = err
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destinationPath), 0700); err != nil {
			return CAInstallResult{}, fmt.Errorf("create CA directory: %w", err)
		}
		if err := os.WriteFile(destinationPath, certPEM, 0600); err != nil {
			return CAInstallResult{}, fmt.Errorf("write Burp CA: %w", err)
		}
		m.SetCAPath(destinationPath)
		return CAInstallResult{
			Installed:   true,
			Path:        destinationPath,
			Fingerprint: fingerprint,
			SourceURL:   sourceURL,
		}, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("Burp CA endpoint unavailable")
	}
	return CAInstallResult{}, lastErr
}

func (m *Manager) AcquireMission(ctx context.Context, missionID string) (Health, error) {
	if missionID == "" {
		return Health{}, fmt.Errorf("missing mission_id")
	}

	health := m.Health(ctx)
	if !health.ProLicense || !health.BridgeEnabled {
		if health.BlockedReason == "burp_pro_required" {
			return health, fmt.Errorf("burp_pro_required")
		}
		return health, fmt.Errorf("burp_unavailable")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeMissionID != "" && m.activeMissionID != missionID {
		health.ActiveMissionID = m.activeMissionID
		return health, fmt.Errorf("burp_mission_conflict")
	}

	if m.forwarder == nil {
		target, err := proxyHostPort(m.cfg.ProxyURL)
		if err != nil {
			return health, err
		}
		fwd, err := StartForwarder(target)
		if err != nil {
			return health, fmt.Errorf("start Burp proxy forwarder: %w", err)
		}
		m.forwarder = fwd
	}

	m.activeMissionID = missionID
	health.ActiveMissionID = missionID
	health.ForwarderLocalPort = m.forwarder.Port()
	health.SandboxProxyURL = fmt.Sprintf("http://host.docker.internal:%d", m.forwarder.Port())
	return health, nil
}

func (m *Manager) ReleaseMission(missionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if missionID != "" && m.activeMissionID == missionID {
		m.activeMissionID = ""
	}
}

func (m *Manager) Disconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeMissionID = ""
}

func (m *Manager) SetAutonomousMode(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.AutonomousMode = enabled
}

func (m *Manager) ApprovalGateState(ctx context.Context) (ApprovalGateState, error) {
	state := ApprovalGateState{
		Mode:           "manual_verification_required",
		ManualRequired: true,
		Detail:         "Burp MCP approval flags were not exposed through output_user_options or output_project_options.",
	}

	userRaw, userErr := m.callMCPTool(ctx, "output_user_options", map[string]any{})
	if userErr == nil {
		text := toolResultText(userRaw)
		if gates, ok := parseApprovalGates(text, "user_options"); ok {
			return gates, nil
		}
	}

	projectRaw, projectErr := m.callMCPTool(ctx, "output_project_options", map[string]any{})
	if projectErr == nil {
		text := toolResultText(projectRaw)
		if gates, ok := parseApprovalGates(text, "project_options"); ok {
			return gates, nil
		}
	}

	if userErr != nil && projectErr != nil {
		return state, fmt.Errorf("read Burp MCP config options: user=%v project=%v", userErr, projectErr)
	}
	return state, nil
}

func (m *Manager) ConfigureApprovalMode(ctx context.Context, autonomous bool) (ApprovalGateState, error) {
	m.SetAutonomousMode(autonomous)

	state, err := m.ApprovalGateState(ctx)
	if err != nil {
		state.Mode = modeName(autonomous, false)
		state.ManualRequired = autonomous
		return state, err
	}
	if !state.Supported {
		state.Mode = modeName(autonomous, false)
		state.ManualRequired = autonomous
		if autonomous {
			state.Detail = "Programmatic approval-gate configuration is not exposed by this MCP server. Complete the manual Burp MCP checkbox step once in the saved project."
		} else {
			state.Detail = "Supervised mode selected. Burp approval gates remain under user control."
		}
		return state, nil
	}

	desired := !autonomous
	payload, err := buildApprovalGatePatch(state, desired)
	if err != nil {
		state.Mode = modeName(autonomous, false)
		state.ManualRequired = autonomous
		state.Detail = err.Error()
		return state, nil
	}

	toolName := "set_user_options"
	if state.Source == "project_options" {
		toolName = "set_project_options"
	}
	if _, err := m.callMCPTool(ctx, toolName, map[string]any{"json": payload}); err != nil {
		state.Mode = modeName(autonomous, false)
		state.ManualRequired = autonomous
		state.Detail = fmt.Sprintf("Programmatic approval-gate write failed: %v", err)
		return state, nil
	}

	verified, err := m.ApprovalGateState(ctx)
	if err != nil {
		return verified, err
	}
	verified.Mode = modeName(autonomous, verified.AutonomousReady)
	verified.ManualRequired = autonomous && !verified.AutonomousReady
	if autonomous && !verified.AutonomousReady {
		verified.Detail = "Burp accepted the config write but approval gates still appear enabled."
	}
	return verified, nil
}

func (m *Manager) CallTool(ctx context.Context, missionID string, toolName string, args json.RawMessage) (ToolResult, error) {
	if missionID == "" {
		return ToolResult{}, fmt.Errorf("missing mission_id")
	}
	if toolName == "" {
		return ToolResult{}, fmt.Errorf("missing burp tool name")
	}

	m.mu.Lock()
	active := m.activeMissionID
	m.mu.Unlock()
	if active == "" {
		return ToolResult{}, fmt.Errorf("burp_mission_not_active")
	}
	if active != missionID {
		return ToolResult{}, fmt.Errorf("burp_mission_conflict")
	}

	var params map[string]any
	if len(args) > 0 {
		if err := json.Unmarshal(args, &params); err != nil {
			return ToolResult{}, fmt.Errorf("decode tool parameters: %w", err)
		}
	}
	if params == nil {
		params = map[string]any{}
	}
	result, err := m.callMCPTool(ctx, toolName, params)
	if err != nil {
		return ToolResult{}, err
	}
	return ToolResult{ToolName: toolName, Result: result}, nil
}

func BuildApprovalPending(toolName string, params map[string]any) ApprovalPending {
	host := stringValue(params["targetHostname"])
	content := stringValue(params["content"])
	if host == "" {
		host = extractRawHost(content)
	}
	method, path := extractRawRequestLine(content)
	if method == "" {
		method = toolName
	}
	if path == "" {
		path = stringValue(params["regex"])
	}
	if path == "" {
		path = "/"
	}
	original := map[string]any{
		"tool_name": toolName,
		"arguments": params,
	}
	return ApprovalPending{
		Status:       "approval_pending",
		Host:         host,
		Method:       method,
		Path:         path,
		OriginalCall: original,
	}
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func modeName(autonomous bool, ready bool) string {
	if autonomous {
		if ready {
			return "autonomous"
		}
		return "autonomous_manual"
	}
	return "supervised"
}

func toolResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var parsed struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(raw, &parsed) == nil && len(parsed.Content) > 0 {
		parts := make([]string, 0, len(parsed.Content))
		for _, item := range parsed.Content {
			if item.Text != "" {
				parts = append(parts, item.Text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return string(raw)
}

func parseApprovalGates(text string, source string) (ApprovalGateState, bool) {
	state := ApprovalGateState{
		Source: source,
		Mode:   "unknown",
		Detail: "Burp MCP approval gate booleans are exposed by the MCP option output.",
	}
	var doc any
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		start := strings.Index(text, "{")
		end := strings.LastIndex(text, "}")
		if start < 0 || end <= start {
			return state, false
		}
		if err := json.Unmarshal([]byte(text[start:end+1]), &doc); err != nil {
			return state, false
		}
	}

	httpValue, httpPath, httpOK := findBoolByKey(doc, "requireHttpRequestApproval", nil)
	historyValue, historyPath, historyOK := findBoolByKey(doc, "requireHistoryAccessApproval", nil)
	if !httpOK || !historyOK {
		return state, false
	}
	state.Supported = true
	state.HTTPRequestApprovalRequired = httpValue
	state.HistoryAccessApprovalRequired = historyValue
	state.AutonomousReady = !httpValue && !historyValue
	state.ManualRequired = !state.AutonomousReady
	state.KeysFound = []string{"requireHttpRequestApproval", "requireHistoryAccessApproval"}
	state.httpPath = httpPath
	state.historyPath = historyPath
	state.Mode = modeName(true, state.AutonomousReady)
	return state, true
}

func findBoolByKey(value any, key string, path []string) (bool, []string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for k, v := range typed {
			nextPath := append(append([]string{}, path...), k)
			if strings.EqualFold(k, key) {
				if boolValue, ok := v.(bool); ok {
					return boolValue, nextPath, true
				}
			}
			if found, foundPath, ok := findBoolByKey(v, key, nextPath); ok {
				return found, foundPath, true
			}
		}
	case []any:
		for _, item := range typed {
			if found, foundPath, ok := findBoolByKey(item, key, path); ok {
				return found, foundPath, true
			}
		}
	}
	return false, nil, false
}

func buildApprovalGatePatch(state ApprovalGateState, desired bool) (string, error) {
	if len(state.httpPath) == 0 || len(state.historyPath) == 0 {
		return "", fmt.Errorf("approval-gate JSON paths were not available")
	}
	rootName := state.Source
	if rootName == "" {
		return "", fmt.Errorf("approval-gate source was not available")
	}
	root := map[string]any{rootName: map[string]any{}}
	setNestedBool(root[rootName].(map[string]any), trimRootPath(state.httpPath, rootName), desired)
	setNestedBool(root[rootName].(map[string]any), trimRootPath(state.historyPath, rootName), desired)
	data, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func trimRootPath(path []string, root string) []string {
	if len(path) > 0 && path[0] == root {
		return path[1:]
	}
	return path
}

func setNestedBool(target map[string]any, path []string, value bool) {
	if len(path) == 0 {
		return
	}
	if len(path) == 1 {
		target[path[0]] = value
		return
	}
	child, ok := target[path[0]].(map[string]any)
	if !ok {
		child = map[string]any{}
		target[path[0]] = child
	}
	setNestedBool(child, path[1:], value)
}

func extractRawHost(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

func extractRawRequestLine(content string) (string, string) {
	first := strings.TrimSpace(strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")[0])
	parts := strings.Fields(first)
	if len(parts) >= 2 && strings.HasPrefix(parts[1], "/") {
		return parts[0], parts[1]
	}
	return "", ""
}

func (m *Manager) discoverTools(ctx context.Context) ([]string, string, string, error) {
	result, serverName, serverVersion, err := m.callMCP(ctx, "tools/list", nil)
	if err != nil {
		return nil, "", "", err
	}
	var parsed struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil, "", "", fmt.Errorf("decode tools/list: %w", err)
	}
	tools := make([]string, 0, len(parsed.Tools))
	for _, t := range parsed.Tools {
		tools = append(tools, t.Name)
	}
	m.mu.Lock()
	m.tools = tools
	m.serverName = serverName
	m.serverVersion = serverVersion
	m.mu.Unlock()
	return tools, serverName, serverVersion, nil
}

func (m *Manager) callMCPTool(ctx context.Context, toolName string, args map[string]any) (json.RawMessage, error) {
	params := map[string]any{
		"name":      toolName,
		"arguments": args,
	}
	returnRaw, _, _, err := m.callMCP(ctx, "tools/call", params)
	return returnRaw, err
}

func (m *Manager) callMCP(ctx context.Context, method string, params any) (json.RawMessage, string, string, error) {
	sseCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(sseCtx, http.MethodGet, m.cfg.MCPURL, nil)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", "", fmt.Errorf("mcp sse failed (%d): %s", resp.StatusCode, string(body))
	}

	reader := bufio.NewReader(resp.Body)
	endpoint, err := readEndpoint(ctx, reader)
	if err != nil {
		return nil, "", "", err
	}
	postURL, err := resolveEndpoint(m.cfg.MCPURL, endpoint)
	if err != nil {
		return nil, "", "", err
	}

	serverName := ""
	serverVersion := ""

	if err := m.postJSON(ctx, postURL, rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "revelion-daemon",
				"version": "phase1",
			},
		},
	}); err != nil {
		return nil, "", "", err
	}
	initResult, err := readRPCResult(ctx, reader, 1, 10*time.Second)
	if err != nil {
		return nil, "", "", err
	}
	var initParsed struct {
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if json.Unmarshal(initResult, &initParsed) == nil {
		serverName = initParsed.ServerInfo.Name
		serverVersion = initParsed.ServerInfo.Version
	}

	if err := m.postJSON(ctx, postURL, rpcRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
		Params:  map[string]any{},
	}); err != nil {
		return nil, "", "", err
	}

	callID := 2
	timeout := ApprovalTimeout
	if method == "tools/list" {
		timeout = 10 * time.Second
	}
	if err := m.postJSON(ctx, postURL, rpcRequest{
		JSONRPC: "2.0",
		ID:      callID,
		Method:  method,
		Params:  params,
	}); err != nil {
		if isMCPApprovalPostTimeout(method, err) {
			return nil, serverName, serverVersion, ErrApprovalPending
		}
		return nil, "", "", err
	}
	result, err := readRPCResult(ctx, reader, callID, timeout)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, serverName, serverVersion, ErrApprovalPending
		}
		return nil, serverName, serverVersion, err
	}
	return result, serverName, serverVersion, nil
}

func isMCPApprovalPostTimeout(method string, err error) bool {
	if method != "tools/call" || err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "context deadline exceeded") ||
		strings.Contains(message, "client.timeout exceeded") ||
		strings.Contains(message, "awaiting headers")
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

func (m *Manager) postJSON(ctx context.Context, endpoint string, payload rpcRequest) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("mcp post %s failed (%d): %s", payload.Method, resp.StatusCode, string(body))
	}
	return nil
}

func readEndpoint(ctx context.Context, reader *bufio.Reader) (string, error) {
	for {
		ev, err := readSSEEvent(ctx, reader, 10*time.Second)
		if err != nil {
			return "", err
		}
		if ev.Event == "endpoint" && strings.TrimSpace(ev.Data) != "" {
			return strings.TrimSpace(ev.Data), nil
		}
	}
}

func readRPCResult(ctx context.Context, reader *bufio.Reader, id int, timeout time.Duration) (json.RawMessage, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		ev, err := readSSEEvent(deadlineCtx, reader, timeout)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(ev.Data) == "" {
			continue
		}
		var envelope struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  any             `json:"error"`
		}
		if err := json.Unmarshal([]byte(ev.Data), &envelope); err != nil {
			continue
		}
		if envelope.ID != id {
			continue
		}
		if envelope.Error != nil {
			errJSON, _ := json.Marshal(envelope.Error)
			return nil, fmt.Errorf("mcp rpc error: %s", string(errJSON))
		}
		return envelope.Result, nil
	}
}

type sseEvent struct {
	Event string
	Data  string
}

func readSSEEvent(ctx context.Context, reader *bufio.Reader, timeout time.Duration) (sseEvent, error) {
	type result struct {
		ev  sseEvent
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ev := sseEvent{}
		var data []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				ch <- result{err: err}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				ev.Data = strings.Join(data, "\n")
				ch <- result{ev: ev}
				return
			}
			if strings.HasPrefix(line, "event:") {
				ev.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
	}()

	select {
	case <-ctx.Done():
		return sseEvent{}, ctx.Err()
	case res := <-ch:
		return res.ev, res.err
	case <-time.After(timeout):
		return sseEvent{}, context.DeadlineExceeded
	}
}

func resolveEndpoint(base, endpoint string) (string, error) {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint, nil
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(endpoint, "?") {
		baseURL.RawQuery = strings.TrimPrefix(endpoint, "?")
		return baseURL.String(), nil
	}
	rel, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(rel).String(), nil
}

func (m *Manager) tcpReachable(rawURL string) bool {
	hostPort, err := proxyHostPort(rawURL)
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("tcp", hostPort, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func proxyHostPort(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid URL: %s", rawURL)
	}
	return u.Host, nil
}

func hasTool(tools []string, name string) bool {
	for _, tool := range tools {
		if tool == name {
			return true
		}
	}
	return false
}

func caFingerprint(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) > 1<<20 {
		return "", fmt.Errorf("CA file too large")
	}
	cert, err := parseCertificate(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(fmt.Sprintf("%x", sum[:])), nil
}

func fetchBurpCA(ctx context.Context, client *http.Client, sourceURL string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build Burp CA request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream, application/x-x509-ca-cert, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch Burp CA from %s: %w", sourceURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, resp.Body)
		return nil, "", fmt.Errorf("Burp CA endpoint %s returned %d", sourceURL, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", fmt.Errorf("read Burp CA: %w", err)
	}
	if len(data) == 0 {
		return nil, "", fmt.Errorf("Burp CA endpoint returned empty certificate")
	}

	cert, err := parseCertificate(data)
	if err != nil {
		return nil, "", fmt.Errorf("parse Burp CA: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	fingerprint := strings.ToUpper(fmt.Sprintf("%x", sum[:]))
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if len(certPEM) == 0 {
		return nil, "", fmt.Errorf("encode Burp CA as PEM")
	}
	return certPEM, fingerprint, nil
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	return x509.ParseCertificate(data)
}

// Forwarder is a local raw TCP forwarder from sandbox containers to Burp.
type Forwarder struct {
	listener net.Listener
	target   string
	port     int
	done     chan struct{}
}

func StartForwarder(target string) (*Forwarder, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := ln.Addr().(*net.TCPAddr)
	f := &Forwarder{listener: ln, target: target, port: addr.Port, done: make(chan struct{})}
	go f.serve()
	log.Printf("Burp proxy forwarder listening on 127.0.0.1:%d -> %s", f.port, target)
	return f, nil
}

func (f *Forwarder) Port() int {
	if f == nil {
		return 0
	}
	return f.port
}

func (f *Forwarder) Close() error {
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	if f.listener != nil {
		return f.listener.Close()
	}
	return nil
}

func (f *Forwarder) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			select {
			case <-f.done:
				return
			default:
				log.Printf("Burp forwarder accept error: %v", err)
				continue
			}
		}
		go f.handle(conn)
	}
}

func (f *Forwarder) handle(src net.Conn) {
	defer src.Close()
	dst, err := net.DialTimeout("tcp", f.target, 5*time.Second)
	if err != nil {
		log.Printf("Burp forwarder dial error: %v", err)
		return
	}
	defer dst.Close()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(dst, src)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(src, dst)
		errCh <- err
	}()
	<-errCh
}
