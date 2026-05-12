package ws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/revelion/daemon/internal/burp"
	"github.com/revelion/daemon/internal/config"
)

func TestBrainPairInitiateWSMessageRoundtrip(t *testing.T) {
	client := newBurpProxyTestClient(t, &config.Config{BurpExtensionAddr: "127.0.0.1:48761"})

	client.handleBurpExtensionProxyRequest(Message{
		Type:      "burp_pair_initiate_request",
		ID:        "req_1",
		RequestID: "req_1",
	})

	msg := readClientMessage(t, client)
	if msg.Type != "burp_pair_initiate_response" {
		t.Fatalf("type = %q, want burp_pair_initiate_response", msg.Type)
	}
	if msg.ID != "req_1" || msg.RequestID != "req_1" {
		t.Fatalf("correlation = id:%q request_id:%q", msg.ID, msg.RequestID)
	}
	if msg.StatusCode != 200 {
		t.Fatalf("status_code = %d, want 200", msg.StatusCode)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(msg.Result), &body); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if body["pair_code"] == "" || body["daemon_url"] == "" || body["expires_at"] == "" {
		t.Fatalf("incomplete pair response: %#v", body)
	}
}

func TestBrainPairStatusWSMessageRoundtrip(t *testing.T) {
	client := newBurpProxyTestClient(t, &config.Config{BurpExtensionSessionToken: "session"})

	client.handleBurpExtensionProxyRequest(Message{Type: "burp_pair_status_request", ID: "req_2"})

	msg := readClientMessage(t, client)
	if msg.Type != "burp_pair_status_response" || msg.StatusCode != 200 {
		t.Fatalf("response = %#v", msg)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(msg.Result), &body); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if body["paired_session"] != true {
		t.Fatalf("paired_session = %#v, want true", body["paired_session"])
	}
}

func TestBrainStateWSMessageRoundtripNoState(t *testing.T) {
	client := newBurpProxyTestClient(t, &config.Config{})

	client.handleBurpExtensionProxyRequest(Message{Type: "burp_state_request", ID: "req_3"})

	msg := readClientMessage(t, client)
	if msg.Type != "burp_state_response" || msg.StatusCode != 404 {
		t.Fatalf("response = %#v", msg)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(msg.Result), &body); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if body["error"] != "state_not_received" {
		t.Fatalf("body = %#v", body)
	}
}

func TestBrainScopeActiveWSMessageRoundtripNoScope(t *testing.T) {
	client := newBurpProxyTestClient(t, &config.Config{})

	client.handleBurpExtensionProxyRequest(Message{Type: "burp_scope_active_request", ID: "req_4"})

	msg := readClientMessage(t, client)
	if msg.Type != "burp_scope_active_response" || msg.StatusCode != 204 {
		t.Fatalf("response = %#v", msg)
	}
}

func TestBrainApprovalGatesActiveWSMessageRoundtripNoState(t *testing.T) {
	client := newBurpProxyTestClient(t, &config.Config{})

	client.handleBurpExtensionProxyRequest(Message{Type: "burp_approval_gates_active_request", ID: "req_5"})

	msg := readClientMessage(t, client)
	if msg.Type != "burp_approval_gates_active_response" || msg.StatusCode != 204 {
		t.Fatalf("response = %#v", msg)
	}
}

func TestBrainApprovalGatesSetWSMessageRoundtrip(t *testing.T) {
	client := newBurpProxyTestClient(t, &config.Config{})

	client.handleBurpApprovalGatesSet(Message{Type: "burp_approval_gates_set", ID: "req_6", SnapshotID: "snap_1", Autonomous: true})

	msg := readClientMessage(t, client)
	if msg.Type != "error" || msg.Error != "extension_not_paired" {
		t.Fatalf("response = %#v, want extension_not_paired error", msg)
	}
}

func newBurpProxyTestClient(t *testing.T, cfg *config.Config) *Client {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if cfg.BurpExtensionAddr == "" {
		cfg.BurpExtensionAddr = "127.0.0.1:48761"
	}
	ext := burp.NewExtensionServer(cfg)
	return &Client{
		cfg:       cfg,
		extension: ext,
		sendCh:    make(chan []byte, sendChanSize),
		pongCh:    make(chan []byte, 1),
		done:      make(chan struct{}),
	}
}

func readClientMessage(t *testing.T, client *Client) Message {
	t.Helper()
	select {
	case raw := <-client.sendCh:
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("decode message %s: %v", string(raw), err)
		}
		return msg
	default:
		t.Fatal("no message queued")
	}
	return Message{}
}

func TestMain(m *testing.M) {
	code := m.Run()
	_ = os.RemoveAll(filepath.Join(os.TempDir(), ".revelion-ws-tests"))
	os.Exit(code)
}
