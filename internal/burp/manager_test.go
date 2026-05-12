package burp

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestReadSSEEventAcceptsLFDelimiter(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("event: message\ndata: {\"id\":1}\n\n"))

	ev, err := readSSEEvent(context.Background(), reader, time.Second)
	if err != nil {
		t.Fatalf("readSSEEvent returned error: %v", err)
	}
	if ev.Event != "message" {
		t.Fatalf("event = %q, want message", ev.Event)
	}
	if ev.Data != `{"id":1}` {
		t.Fatalf("data = %q, want JSON payload", ev.Data)
	}
}

func TestReadSSEEventAcceptsCRLFDelimiter(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("event: message\r\ndata: {\"id\":2}\r\n\r\n"))

	ev, err := readSSEEvent(context.Background(), reader, time.Second)
	if err != nil {
		t.Fatalf("readSSEEvent returned error: %v", err)
	}
	if ev.Event != "message" {
		t.Fatalf("event = %q, want message", ev.Event)
	}
	if ev.Data != `{"id":2}` {
		t.Fatalf("data = %q, want JSON payload", ev.Data)
	}
}

func TestBuildApprovalPendingExtractsRawRequestContext(t *testing.T) {
	pending := BuildApprovalPending("send_http1_request", map[string]any{
		"content": "POST /login.php HTTP/1.1\r\nHost: localhost:8081\r\n\r\nusername=admin",
	})

	if pending.Status != "approval_pending" {
		t.Fatalf("status = %q, want approval_pending", pending.Status)
	}
	if pending.Host != "localhost:8081" {
		t.Fatalf("host = %q, want localhost:8081", pending.Host)
	}
	if pending.Method != "POST" {
		t.Fatalf("method = %q, want POST", pending.Method)
	}
	if pending.Path != "/login.php" {
		t.Fatalf("path = %q, want /login.php", pending.Path)
	}
	if pending.OriginalCall["tool_name"] != "send_http1_request" {
		t.Fatalf("original call tool name not preserved: %#v", pending.OriginalCall)
	}
}

func TestParseApprovalGatesFromUserOptions(t *testing.T) {
	state, ok := parseApprovalGates(`{
		"user_options": {
			"extensions": {
				"mcp": {
					"requireHttpRequestApproval": false,
					"requireHistoryAccessApproval": false
				}
			}
		}
	}`, "user_options")
	if !ok {
		t.Fatal("approval gates were not detected")
	}
	if !state.Supported {
		t.Fatal("state should be supported")
	}
	if !state.AutonomousReady {
		t.Fatal("approval gates are false, autonomous mode should be ready")
	}
	if state.HTTPRequestApprovalRequired || state.HistoryAccessApprovalRequired {
		t.Fatalf("approval flags parsed incorrectly: %#v", state)
	}
}

func TestBuildApprovalGatePatchPreservesNestedPath(t *testing.T) {
	state, ok := parseApprovalGates(`{
		"user_options": {
			"extensions": {
				"mcp": {
					"requireHttpRequestApproval": true,
					"requireHistoryAccessApproval": true
				}
			}
		}
	}`, "user_options")
	if !ok {
		t.Fatal("approval gates were not detected")
	}
	patch, err := buildApprovalGatePatch(state, false)
	if err != nil {
		t.Fatalf("buildApprovalGatePatch returned error: %v", err)
	}
	want := `"requireHttpRequestApproval":false`
	if !strings.Contains(patch, want) {
		t.Fatalf("patch %s does not contain %s", patch, want)
	}
	if !strings.Contains(patch, `"requireHistoryAccessApproval":false`) {
		t.Fatalf("patch %s does not disable history approval", patch)
	}
}

func TestMCPApprovalPostTimeoutClassifiedOnlyForToolCalls(t *testing.T) {
	err := fmt.Errorf(`Post "http://127.0.0.1:9876?sessionId=abc": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`)

	if !isMCPApprovalPostTimeout("tools/call", err) {
		t.Fatal("tools/call timeout should be classified as approval pending")
	}
	if isMCPApprovalPostTimeout("tools/list", err) {
		t.Fatal("tools/list timeout should not be classified as approval pending")
	}
	if isMCPApprovalPostTimeout("initialize", err) {
		t.Fatal("initialize timeout should not be classified as approval pending")
	}
}

func TestRESTURLUsesKeyInPath(t *testing.T) {
	manager := &Manager{cfg: Config{RESTURL: "http://127.0.0.1:1337"}}
	u, err := manager.restURL("secret-key", "/scan/task-123", nil)
	if err != nil {
		t.Fatalf("restURL returned error: %v", err)
	}
	want := "http://127.0.0.1:1337/secret-key/v0.1/scan/task-123"
	if u != want {
		t.Fatalf("url = %q, want %q", u, want)
	}
}

func TestNormalizeRESTTaskIDAcceptsLocationPath(t *testing.T) {
	got := normalizeRESTTaskID("/secret-key/v0.1/scan/18")
	if got != "18" {
		t.Fatalf("task ID = %q, want 18", got)
	}
}
