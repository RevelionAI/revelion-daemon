package burp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/revelion/daemon/internal/config"
)

func TestExtensionServerRejectsMissingOrBadPairToken(t *testing.T) {
	cfg := &config.Config{BurpExtensionPairToken: "good-token"}
	server := newExtensionServer(cfg, func(*config.Config) error { return nil })
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + extensionPath
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("missing token unexpectedly connected")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token status = %#v, want 401", resp)
	}

	headers := http.Header{}
	headers.Set("X-Revelion-Pair-Token", "bad-token")
	_, resp, err = websocket.DefaultDialer.Dial(wsURL, headers)
	if err == nil {
		t.Fatal("bad token unexpectedly connected")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token status = %#v, want 401", resp)
	}
}

func TestPairInitiateGeneratesTokenAndFile(t *testing.T) {
	cfg := &config.Config{BurpExtensionAddr: "127.0.0.1:48761"}
	server, pairFile := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := requestPairAPI(t, ts.URL, http.MethodPost, pairInitiatePath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body pairInitiateResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.PairCode) != 6 {
		t.Fatalf("pair_code = %q, want 6 digits", body.PairCode)
	}
	if body.DaemonURL != "ws://127.0.0.1:48761/burp/extension" {
		t.Fatalf("daemon_url = %q", body.DaemonURL)
	}
	if cfg.BurpExtensionPairToken == "" {
		t.Fatal("pair token was not persisted")
	}
	if cfg.BurpExtensionPairTokenExpiresAt.IsZero() {
		t.Fatal("pair token expiry was not persisted")
	}
	raw, err := os.ReadFile(pairFile)
	if err != nil {
		t.Fatalf("read pair file: %v", err)
	}
	text := string(raw)
	for _, want := range []string{cfg.BurpExtensionPairToken, body.PairCode, body.ExpiresAt, body.DaemonURL} {
		if !strings.Contains(text, want) {
			t.Fatalf("pair file missing %q: %s", want, text)
		}
	}
}

func TestInitiatePairMethodCallable(t *testing.T) {
	cfg := &config.Config{BurpExtensionAddr: "127.0.0.1:48761"}
	server, pairFile := testPairServer(t, cfg)

	body, err := server.InitiatePair()
	if err != nil {
		t.Fatalf("InitiatePair: %v", err)
	}
	if len(body.PairCode) != 6 {
		t.Fatalf("pair_code = %q, want 6 digits", body.PairCode)
	}
	if body.DaemonURL != "ws://127.0.0.1:48761/burp/extension" {
		t.Fatalf("daemon_url = %q", body.DaemonURL)
	}
	if cfg.BurpExtensionPairToken == "" {
		t.Fatal("pair token was not persisted")
	}
	if _, err := os.Stat(pairFile); err != nil {
		t.Fatalf("pair file not written: %v", err)
	}
}

func TestPairStatusReturnsCurrentState(t *testing.T) {
	expires := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		BurpExtensionPairToken:          "pending",
		BurpExtensionPairTokenExpiresAt: expires,
		BurpExtensionSessionToken:       "session",
	}
	server, _ := testPairServer(t, cfg)
	server.now = func() time.Time { return expires.Add(-time.Minute) }
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := requestPairAPI(t, ts.URL, http.MethodGet, pairStatusPath, "http://localhost:3000")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body pairStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Connected {
		t.Fatal("connected should be false without WebSocket")
	}
	if !body.PairedSession {
		t.Fatal("paired_session should be true")
	}
	if !body.PairPending {
		t.Fatal("pair_pending should be true")
	}
	if body.PairExpiresAt != expires.Format(time.RFC3339) {
		t.Fatalf("pair_expires_at = %q", body.PairExpiresAt)
	}
}

func TestPairCancelClearsTokenAndFile(t *testing.T) {
	cfg := &config.Config{
		BurpExtensionPairToken:          "pending",
		BurpExtensionPairTokenExpiresAt: time.Now().Add(time.Minute),
	}
	server, pairFile := testPairServer(t, cfg)
	if err := os.MkdirAll(filepath.Dir(pairFile), 0700); err != nil {
		t.Fatalf("create pair dir: %v", err)
	}
	if err := os.WriteFile(pairFile, []byte("x"), 0600); err != nil {
		t.Fatalf("write pair file: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := requestPairAPI(t, ts.URL, http.MethodPost, pairCancelPath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cfg.BurpExtensionPairToken != "" {
		t.Fatal("pair token not cleared")
	}
	if !cfg.BurpExtensionPairTokenExpiresAt.IsZero() {
		t.Fatal("pair expiry not cleared")
	}
	if _, err := os.Stat(pairFile); !os.IsNotExist(err) {
		t.Fatalf("pair file still exists or stat failed: %v", err)
	}
}

func TestPairTokenTTLExpiry(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		BurpExtensionPairToken:          "expired-token",
		BurpExtensionPairTokenExpiresAt: now.Add(-time.Second),
	}
	server, _ := testPairServer(t, cfg)
	server.now = func() time.Time { return now }
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	headers := http.Header{}
	headers.Set("X-Revelion-Pair-Token", "expired-token")
	headers.Set("User-Agent", "Burp-Revelion-Extension/0.1")
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + extensionPath
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err == nil {
		t.Fatal("expired token unexpectedly connected")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %#v, want 401", resp)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `pair_expired`) {
		t.Fatalf("WWW-Authenticate = %q, want pair_expired", got)
	}
}

func TestPairAPICORSRejectsUntrustedOrigin(t *testing.T) {
	cfg := &config.Config{}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := requestPairAPI(t, ts.URL, http.MethodPost, pairInitiatePath, "https://attacker.example.com")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected CORS allow origin: %q", got)
	}
}

func TestPairAPICORSAcceptsAllowedOrigins(t *testing.T) {
	for _, origin := range []string{"https://app.revelion.ai", "http://localhost:3000"} {
		t.Run(origin, func(t *testing.T) {
			cfg := &config.Config{BurpExtensionAddr: "127.0.0.1:48761"}
			server, _ := testPairServer(t, cfg)
			ts := httptest.NewServer(server.Handler())
			defer ts.Close()

			resp := requestPairAPI(t, ts.URL, http.MethodOptions, pairInitiatePath, origin)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", resp.StatusCode)
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
				t.Fatalf("allow-origin = %q, want %q", got, origin)
			}
			if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "false" {
				t.Fatalf("allow-credentials = %q, want false", got)
			}
			if got := resp.Header.Get("Vary"); got != "Origin" {
				t.Fatalf("vary = %q, want Origin", got)
			}
		})
	}
}

func TestPairFileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode check is not meaningful on Windows")
	}
	cfg := &config.Config{BurpExtensionAddr: "127.0.0.1:48761"}
	server, pairFile := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := requestPairAPI(t, ts.URL, http.MethodPost, pairInitiatePath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	info, err := os.Stat(pairFile)
	if err != nil {
		t.Fatalf("stat pair file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("mode = %o, want 0600", got)
	}
}

func TestExtensionServerAcceptsPairTokenAndIssuesSession(t *testing.T) {
	cfg := &config.Config{BurpExtensionPairToken: "good-token"}
	saveCount := 0
	server := newExtensionServer(cfg, func(*config.Config) error {
		saveCount++
		return nil
	})
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Pair-Token", "good-token")
	defer conn.Close()

	msg := readJSONRPC(t, conn)
	if msg["method"] != "session.granted" {
		t.Fatalf("method = %v, want session.granted", msg["method"])
	}
	params := msg["params"].(map[string]any)
	token, _ := params["session_token"].(string)
	if token == "" {
		t.Fatal("session token missing")
	}
	if cfg.BurpExtensionPairToken != "" {
		t.Fatal("pair token should be cleared after first use")
	}
	if cfg.BurpExtensionSessionToken != token {
		t.Fatal("session token was not persisted on config")
	}
	if saveCount != 1 {
		t.Fatalf("saveCount = %d, want 1", saveCount)
	}
}

func TestExtensionServerAcceptsPersistedSessionToken(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server := newExtensionServer(cfg, func(*config.Config) error { return nil })
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()

	msg := readJSONRPC(t, conn)
	if msg["method"] != "session.granted" {
		t.Fatalf("method = %v, want session.granted", msg["method"])
	}
	params := msg["params"].(map[string]any)
	if params["reconnected"] != true {
		t.Fatalf("reconnected = %v, want true", params["reconnected"])
	}
}

func TestExtensionServerPingPong(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server := newExtensionServer(cfg, func(*config.Config) error { return nil })
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)

	if err := conn.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": "ping-1", "method": "ping"}); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	msg := readJSONRPC(t, conn)
	if msg["id"] != "ping-1" {
		t.Fatalf("id = %v, want ping-1", msg["id"])
	}
	result := msg["result"].(map[string]any)
	if result["pong"] != true {
		t.Fatalf("pong = %v, want true", result["pong"])
	}
}

func TestStatePushStoredAndRetrievable(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)

	pushState(t, conn, "Burp Suite Professional", "Project A")
	ack := readJSONRPC(t, conn)
	if ack["method"] != "state.ack" {
		t.Fatalf("method = %v, want state.ack", ack["method"])
	}

	resp := requestPairAPI(t, ts.URL, http.MethodGet, extensionStatePath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	var state BurpExtensionState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if state.BurpVersion != "Burp Suite Professional" {
		t.Fatalf("burp_version = %q", state.BurpVersion)
	}
	if state.ProjectName != "Project A" {
		t.Fatalf("project_name = %q", state.ProjectName)
	}
	if len(state.ProxyListeners) != 1 || state.ProxyListeners[0].Port != 8080 {
		t.Fatalf("proxy_listeners = %#v", state.ProxyListeners)
	}
	if len(state.Scope.IncludeRules) != 1 || state.Scope.IncludeRules[0] != "https://example.com/" {
		t.Fatalf("include_rules = %#v", state.Scope.IncludeRules)
	}
	if len(state.InstalledExtensions) != 1 || state.InstalledExtensions[0].Name != "MCP Server" {
		t.Fatalf("installed_extensions = %#v", state.InstalledExtensions)
	}
}

func TestStatePushReplacesPriorState(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)

	pushState(t, conn, "Burp Suite Professional", "Project A")
	_ = readJSONRPC(t, conn)
	pushState(t, conn, "Burp Suite Professional", "Project B")
	_ = readJSONRPC(t, conn)

	resp := requestPairAPI(t, ts.URL, http.MethodGet, extensionStatePath, "https://app.revelion.ai")
	defer resp.Body.Close()
	var state BurpExtensionState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if state.ProjectName != "Project B" {
		t.Fatalf("project_name = %q, want Project B", state.ProjectName)
	}
}

func TestStateBeforeAnyPushReturns404(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := requestPairAPI(t, ts.URL, http.MethodGet, extensionStatePath, "http://localhost:3000")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPairDisconnectClearsSessionAndClosesConnection(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)

	resp := requestPairAPI(t, ts.URL, http.MethodPost, pairDisconnectPath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if cfg.BurpExtensionSessionToken != "" {
		t.Fatal("session token was not cleared")
	}
	msg := readJSONRPC(t, conn)
	if msg["method"] != "connection.evicted" {
		t.Fatalf("method = %v, want connection.evicted", msg["method"])
	}

	headers := http.Header{}
	headers.Set("X-Revelion-Session-Token", "session-token")
	headers.Set("User-Agent", "Burp-Revelion-Extension/0.1")
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + extensionPath
	_, retryResp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err == nil {
		t.Fatal("old session token unexpectedly reconnected")
	}
	if retryResp == nil || retryResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %#v, want 401", retryResp)
	}
	if got := retryResp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "invalid_session") {
		t.Fatalf("WWW-Authenticate = %q, want invalid_session", got)
	}
}

func TestPairDisconnectCORS(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	rejected := requestPairAPI(t, ts.URL, http.MethodPost, pairDisconnectPath, "https://attacker.example.com")
	defer rejected.Body.Close()
	if rejected.StatusCode != http.StatusForbidden {
		t.Fatalf("rejected status = %d, want 403", rejected.StatusCode)
	}
	if got := rejected.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected CORS allow origin: %q", got)
	}

	accepted := requestPairAPI(t, ts.URL, http.MethodOptions, pairDisconnectPath, "http://localhost:3000")
	defer accepted.Body.Close()
	if accepted.StatusCode != http.StatusNoContent {
		t.Fatalf("accepted status = %d, want 204", accepted.StatusCode)
	}
	if got := accepted.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("allow-origin = %q", got)
	}
}

func TestSendScopeSetWritesNotification(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)

	if err := server.SendScopeSet("m_123", "snap_123", []string{"https://example.com"}, []string{}); err != nil {
		t.Fatalf("SendScopeSet: %v", err)
	}
	msg := readJSONRPC(t, conn)
	if msg["method"] != "scope.set" {
		t.Fatalf("method = %v, want scope.set", msg["method"])
	}
	params := msg["params"].(map[string]any)
	if params["mission_id"] != "m_123" || params["snapshot_id"] != "snap_123" {
		t.Fatalf("params = %#v", params)
	}
}

func TestScopeAppliedAckUpdatesState(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)
	if err := server.SendScopeSet("m_123", "snap_123", []string{"https://example.com"}, nil); err != nil {
		t.Fatalf("SendScopeSet: %v", err)
	}
	_ = readJSONRPCUntilMethod(t, conn, "scope.set")
	if err := conn.WriteJSON(map[string]any{
		"jsonrpc": "2.0",
		"method":  "scope.applied",
		"params":  map[string]any{"snapshot_id": "snap_123", "applied_at": time.Now().UTC().Format(time.RFC3339)},
	}); err != nil {
		t.Fatalf("write scope.applied: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	scope := server.ActiveScope()
	if scope == nil || scope.Status != "applied" {
		t.Fatalf("scope = %#v, want applied", scope)
	}
}

func TestScopeRestoredAckClearsState(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)
	if err := server.SendScopeSet("m_123", "snap_123", []string{"https://example.com"}, nil); err != nil {
		t.Fatalf("SendScopeSet: %v", err)
	}
	_ = readJSONRPC(t, conn)
	if err := conn.WriteJSON(map[string]any{
		"jsonrpc": "2.0",
		"method":  "scope.restored",
		"params":  map[string]any{"snapshot_id": "snap_123"},
	}); err != nil {
		t.Fatalf("write scope.restored: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if scope := server.ActiveScope(); scope != nil {
		t.Fatalf("scope = %#v, want nil", scope)
	}
}

func TestScopeAPIActiveReturnsCurrentState(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := requestPairAPI(t, ts.URL, http.MethodGet, scopeActivePath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("empty status = %d, want 204", resp.StatusCode)
	}

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)
	if err := server.SendScopeSet("m_123", "snap_123", []string{"https://example.com"}, []string{"https://example.com/logout"}); err != nil {
		t.Fatalf("SendScopeSet: %v", err)
	}
	_ = readJSONRPC(t, conn)

	resp = requestPairAPI(t, ts.URL, http.MethodGet, scopeActivePath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var active ActiveScope
	if err := json.NewDecoder(resp.Body).Decode(&active); err != nil {
		t.Fatalf("decode active scope: %v", err)
	}
	if active.MissionID != "m_123" || active.SnapshotID != "snap_123" {
		t.Fatalf("active = %#v", active)
	}
}

func TestScopeAPIClearSendsRestoreNotification(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)
	if err := server.SendScopeSet("m_123", "snap_123", []string{"https://example.com"}, nil); err != nil {
		t.Fatalf("SendScopeSet: %v", err)
	}
	_ = readJSONRPC(t, conn)

	resp := requestPairAPI(t, ts.URL, http.MethodPost, scopeClearPath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	msg := readJSONRPCUntilMethod(t, conn, "scope.restore")
	if msg["method"] != "scope.restore" {
		t.Fatalf("method = %v, want scope.restore", msg["method"])
	}
}

func TestScopeOperationsRejectedWhenNotPaired(t *testing.T) {
	cfg := &config.Config{}
	server, _ := testPairServer(t, cfg)
	if err := server.SendScopeSet("m_123", "snap_123", []string{"https://example.com"}, nil); err == nil || !strings.Contains(err.Error(), "extension_not_paired") {
		t.Fatalf("SendScopeSet error = %v, want extension_not_paired", err)
	}
	if err := server.SendScopeRestore("snap_123"); err == nil || !strings.Contains(err.Error(), "extension_not_paired") {
		t.Fatalf("SendScopeRestore error = %v, want extension_not_paired", err)
	}
}

func TestSendApprovalGatesSetWritesNotification(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)

	if err := server.SendApprovalGatesSet("gate_snap_123", true); err != nil {
		t.Fatalf("SendApprovalGatesSet: %v", err)
	}
	msg := readJSONRPC(t, conn)
	if msg["method"] != "approval_gates.set" {
		t.Fatalf("method = %v, want approval_gates.set", msg["method"])
	}
	params := msg["params"].(map[string]any)
	if params["snapshot_id"] != "gate_snap_123" || params["autonomous"] != true {
		t.Fatalf("params = %#v", params)
	}
}

func TestApprovalGatesAppliedAckUpdatesState(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)
	if err := server.SendApprovalGatesSet("gate_snap_123", true); err != nil {
		t.Fatalf("SendApprovalGatesSet: %v", err)
	}
	_ = readJSONRPC(t, conn)
	if err := conn.WriteJSON(map[string]any{
		"jsonrpc": "2.0",
		"method":  "approval_gates.applied",
		"params":  map[string]any{"snapshot_id": "gate_snap_123", "autonomous": true, "applied_at": time.Now().UTC().Format(time.RFC3339)},
	}); err != nil {
		t.Fatalf("write approval_gates.applied: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	gates := server.ActiveApprovalGates()
	if gates == nil || gates.Status != "applied" || !gates.Autonomous {
		t.Fatalf("gates = %#v, want applied autonomous", gates)
	}
}

func TestApprovalGatesRestoredAckClearsState(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)
	if err := server.SendApprovalGatesSet("gate_snap_123", true); err != nil {
		t.Fatalf("SendApprovalGatesSet: %v", err)
	}
	_ = readJSONRPC(t, conn)
	if err := conn.WriteJSON(map[string]any{
		"jsonrpc": "2.0",
		"method":  "approval_gates.restored",
		"params":  map[string]any{"snapshot_id": "gate_snap_123"},
	}); err != nil {
		t.Fatalf("write approval_gates.restored: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if gates := server.ActiveApprovalGates(); gates != nil {
		t.Fatalf("gates = %#v, want nil", gates)
	}
}

func TestApprovalGatesAPIActiveReturnsCurrentState(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := requestPairAPI(t, ts.URL, http.MethodGet, approvalGatesActivePath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("empty status = %d, want 204", resp.StatusCode)
	}

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)
	if err := server.SendApprovalGatesSet("gate_snap_123", true); err != nil {
		t.Fatalf("SendApprovalGatesSet: %v", err)
	}
	_ = readJSONRPC(t, conn)

	resp = requestPairAPI(t, ts.URL, http.MethodGet, approvalGatesActivePath, "https://app.revelion.ai")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var active ActiveApprovalGates
	if err := json.NewDecoder(resp.Body).Decode(&active); err != nil {
		t.Fatalf("decode active approval gates: %v", err)
	}
	if active.SnapshotID != "gate_snap_123" || !active.Autonomous {
		t.Fatalf("active = %#v", active)
	}
}

func TestExtensionServerPingTimeout(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server, _ := testPairServer(t, cfg)
	server.pingTimeout = 20 * time.Millisecond
	server.pingCheckInterval = 5 * time.Millisecond
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	conn := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer conn.Close()
	_ = readJSONRPC(t, conn)

	msg := readJSONRPC(t, conn)
	if msg["method"] != "connection.timeout" {
		t.Fatalf("method = %v, want connection.timeout", msg["method"])
	}
}

func TestExtensionServerRejectsUntrustedOrigin(t *testing.T) {
	cfg := &config.Config{BurpExtensionPairToken: "good-token"}
	server := newExtensionServer(cfg, func(*config.Config) error { return nil })
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	headers := http.Header{}
	headers.Set("X-Revelion-Pair-Token", "good-token")
	headers.Set("Origin", "https://attacker.example.com")
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + extensionPath
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err == nil {
		t.Fatal("untrusted origin unexpectedly connected")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("origin status = %#v, want 403", resp)
	}
}

func TestExtensionServerEvictsPriorConnection(t *testing.T) {
	cfg := &config.Config{BurpExtensionSessionToken: "session-token"}
	server := newExtensionServer(cfg, func(*config.Config) error { return nil })
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	first := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer first.Close()
	_ = readJSONRPC(t, first)

	second := dialExtension(t, ts.URL, "X-Revelion-Session-Token", "session-token")
	defer second.Close()

	evicted := readJSONRPC(t, first)
	if evicted["method"] != "connection.evicted" {
		t.Fatalf("first connection message = %#v, want connection.evicted", evicted)
	}
	granted := readJSONRPC(t, second)
	if granted["method"] != "session.granted" {
		t.Fatalf("second connection message = %#v, want session.granted", granted)
	}
}

func dialExtension(t *testing.T, httpURL, headerName, token string) *websocket.Conn {
	t.Helper()
	headers := http.Header{}
	headers.Set(headerName, token)
	headers.Set("User-Agent", "Burp-Revelion-Extension/0.1")
	wsURL := "ws" + strings.TrimPrefix(httpURL, "http") + extensionPath
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("dial extension: %v", err)
	}
	return conn
}

func testPairServer(t *testing.T, cfg *config.Config) (*ExtensionServer, string) {
	t.Helper()
	pairFile := filepath.Join(t.TempDir(), ".revelion", "burp-pair.json")
	server := newExtensionServer(cfg, func(*config.Config) error { return nil })
	server.pairFilePath = pairFile
	return server, pairFile
}

func requestPairAPI(t *testing.T, baseURL, method, path, origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, baseURL+path, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = "127.0.0.1:48761"
	req.Header.Set("Origin", origin)
	if method == http.MethodOptions {
		req.Header.Set("Access-Control-Request-Method", "POST")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, path, err)
	}
	return resp
}

func pushState(t *testing.T, conn *websocket.Conn, burpVersion, projectName string) {
	t.Helper()
	err := conn.WriteJSON(map[string]any{
		"jsonrpc": "2.0",
		"method":  "state.push",
		"params": map[string]any{
			"burp_version":  burpVersion,
			"burp_edition":  "PROFESSIONAL",
			"project_name":  projectName,
			"project_saved": true,
			"proxy_listeners": []map[string]any{
				{"port": 8080, "bind_address": "127.0.0.1", "tls": false, "invisible_proxy": false},
			},
			"scope": map[string]any{
				"include_rules": []string{"https://example.com/"},
				"exclude_rules": []string{"https://example.com/logout"},
			},
			"scanner_ready": true,
			"installed_extensions": []map[string]any{
				{"name": "MCP Server", "enabled": true},
			},
			"pushed_at": time.Now().UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		t.Fatalf("push state: %v", err)
	}
}

func readJSONRPC(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("decode message %s: %v", string(raw), err)
	}
	return msg
}

func readJSONRPCUntilMethod(t *testing.T, conn *websocket.Conn, method string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		_, raw, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read message waiting for %s: %v", method, err)
		}
		var msg map[string]any
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("decode message %s: %v", string(raw), err)
		}
		if msg["method"] == method {
			return msg
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for JSON-RPC method %s", method)
		}
	}
}

func TestScanIssueForwardedToBrain(t *testing.T) {
	cfg := &config.Config{}
	server, _ := testPairServer(t, cfg)
	server.activeBurpScan = &ActiveBurpScan{MissionID: "mission-1", ScanID: "scan-1", Status: "running"}
	called := make(chan struct {
		missionID string
		scanID    string
		issue     string
	}, 1)
	server.SetScanIssueHandler(func(missionID, scanID string, issue json.RawMessage) {
		called <- struct {
			missionID string
			scanID    string
			issue     string
		}{missionID: missionID, scanID: scanID, issue: string(issue)}
	})

	server.handleScanIssueFound(json.RawMessage(`{"name":"SQL injection","severity":"HIGH"}`))

	select {
	case got := <-called:
		if got.missionID != "mission-1" || got.scanID != "scan-1" {
			t.Fatalf("correlation = %s/%s, want mission-1/scan-1", got.missionID, got.scanID)
		}
		if !strings.Contains(got.issue, "SQL injection") {
			t.Fatalf("issue payload not forwarded: %s", got.issue)
		}
	case <-time.After(time.Second):
		t.Fatal("scan issue was not forwarded")
	}
}

func TestScanIssueDroppedWhenNoActiveMission(t *testing.T) {
	cfg := &config.Config{}
	server, _ := testPairServer(t, cfg)
	called := false
	server.SetScanIssueHandler(func(string, string, json.RawMessage) {
		called = true
	})

	server.handleScanIssueFound(json.RawMessage(`{"name":"Outside mission"}`))

	if called {
		t.Fatal("scan issue was forwarded without an active mission")
	}
}
