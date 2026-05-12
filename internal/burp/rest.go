package burp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const restOperationTimeout = 10 * time.Minute

// RESTScanCreated is the Desktop REST response shape for POST /scan.
// Burp returns the task ID in the Location header, not in a JSON body.
type RESTScanCreated struct {
	ScanTaskID string          `json:"scan_task_id"`
	Location   string          `json:"location"`
	StatusCode int             `json:"status_code"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

type RESTScanConfiguration struct {
	Name   string   `json:"name"`
	Source string   `json:"source"`
	Note   string   `json:"note,omitempty"`
	Names  []string `json:"names,omitempty"`
}

func (m *Manager) ListScanConfigurations(ctx context.Context, apiKey string) (map[string]any, error) {
	if _, err := m.restDo(ctx, http.MethodGet, apiKey, "/knowledge_base/issue_definitions", nil, nil, 20*time.Second); err != nil {
		return nil, err
	}
	configs := []RESTScanConfiguration{
		{Name: "Revelion quick active scan", Source: "revelion_bundle", Names: []string{"Crawl strategy - fastest", "Audit checks - critical issues only", "Minimize false positives"}},
		{Name: "Revelion normal active scan", Source: "revelion_bundle", Names: []string{"Crawl strategy - fastest", "Audit checks - all except time-based detection methods", "Minimize false positives"}},
		{Name: "Revelion deep active scan", Source: "revelion_bundle", Names: []string{"Audit checks - all"}},
		{Name: "Crawl strategy - fastest", Source: "phase0_static"},
		{Name: "Audit checks - critical issues only", Source: "phase0_static"},
		{Name: "Audit checks - all except time-based detection methods", Source: "phase0_static"},
		{Name: "Audit checks - all", Source: "phase0_static"},
		{Name: "Minimize false positives", Source: "phase0_static"},
		{Name: "Crawl and audit - lightweight", Source: "spec_static"},
		{Name: "Crawl and audit - deep", Source: "spec_static"},
	}
	return map[string]any{
		"configurations": configs,
		"source":         "static_known_burp_names",
		"note":           "Burp Desktop REST v0.1 exposes NamedConfiguration references but no endpoint to list user/project configuration names; scan creation validates the selected names.",
	}, nil
}

func (m *Manager) CreateRESTScan(ctx context.Context, apiKey string, payload json.RawMessage) (RESTScanCreated, error) {
	if len(payload) == 0 {
		return RESTScanCreated{}, fmt.Errorf("missing scan payload")
	}
	resp, err := m.restDo(ctx, http.MethodPost, apiKey, "/scan", nil, payload, restOperationTimeout)
	if err != nil {
		return RESTScanCreated{}, err
	}
	taskID := strings.TrimSpace(resp.Header.Get("Location"))
	if taskID == "" {
		return RESTScanCreated{}, fmt.Errorf("burp REST scan create returned no Location task ID")
	}
	taskID = normalizeRESTTaskID(taskID)
	return RESTScanCreated{
		ScanTaskID: taskID,
		Location:   taskID,
		StatusCode: resp.StatusCode,
		Payload:    payload,
	}, nil
}

func (m *Manager) PollRESTScan(ctx context.Context, apiKey string, taskID string, after string, issueEvents int) (json.RawMessage, error) {
	taskID = normalizeRESTTaskID(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("missing scan task ID")
	}
	if issueEvents <= 0 {
		issueEvents = 25
	}
	query := url.Values{}
	query.Set("issue_events", fmt.Sprintf("%d", issueEvents))
	if strings.TrimSpace(after) != "" {
		query.Set("after", strings.TrimSpace(after))
	}
	resp, err := m.restDo(ctx, http.MethodGet, apiKey, "/scan/"+url.PathEscape(taskID), query, nil, restOperationTimeout)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (m *Manager) CancelRESTScan(ctx context.Context, apiKey string, taskID string) (json.RawMessage, error) {
	taskID = normalizeRESTTaskID(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("missing scan task ID")
	}
	resp, err := m.restDo(ctx, http.MethodDelete, apiKey, "/scan/"+url.PathEscape(taskID), nil, nil, restOperationTimeout)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (m *Manager) GetIssueDefinitions(ctx context.Context, apiKey string) (json.RawMessage, error) {
	resp, err := m.restDo(ctx, http.MethodGet, apiKey, "/knowledge_base/issue_definitions", nil, nil, 60*time.Second)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

type restResponse struct {
	StatusCode int
	Header     http.Header
	Body       json.RawMessage
}

func (m *Manager) restDo(ctx context.Context, method string, apiKey string, path string, query url.Values, body json.RawMessage, timeout time.Duration) (restResponse, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return restResponse{}, fmt.Errorf("missing Burp REST API key")
	}
	u, err := m.restURL(apiKey, path, query)
	if err != nil {
		return restResponse{}, err
	}
	client := &http.Client{Timeout: timeout}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return restResponse{}, fmt.Errorf("build Burp REST request")
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return restResponse{}, fmt.Errorf("Burp REST request failed")
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
	if readErr != nil {
		return restResponse{}, fmt.Errorf("read Burp REST response")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return restResponse{}, fmt.Errorf("Burp REST returned %d: %s", resp.StatusCode, truncateRESTError(data))
	}
	if len(data) == 0 {
		data = []byte("{}")
	}
	return restResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: json.RawMessage(data)}, nil
}

func (m *Manager) restURL(apiKey string, path string, query url.Values) (string, error) {
	parsed, err := url.Parse(m.cfg.RESTURL)
	if err != nil {
		return "", fmt.Errorf("invalid REST URL")
	}
	cleanPath := "/" + strings.Trim(apiKey, "/") + "/v0.1"
	if strings.TrimSpace(path) != "" {
		cleanPath += "/" + strings.TrimLeft(path, "/")
	}
	parsed.Path = cleanPath
	parsed.RawQuery = ""
	if query != nil {
		parsed.RawQuery = query.Encode()
	}
	return parsed.String(), nil
}

func truncateRESTError(data []byte) string {
	text := strings.TrimSpace(string(data))
	if len(text) > 1024 {
		return text[:1024] + "... [truncated]"
	}
	return text
}

func normalizeRESTTaskID(taskID string) string {
	clean := strings.TrimSpace(taskID)
	if clean == "" {
		return ""
	}
	clean = strings.TrimRight(clean, "/")
	if idx := strings.LastIndex(clean, "/"); idx >= 0 {
		return clean[idx+1:]
	}
	return clean
}
