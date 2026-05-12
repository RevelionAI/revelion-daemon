package burp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/revelion/daemon/internal/config"
)

const (
	extensionPath           = "/burp/extension"
	pairInitiatePath        = "/api/burp/pair/initiate"
	pairStatusPath          = "/api/burp/pair/status"
	pairCancelPath          = "/api/burp/pair/cancel"
	pairDisconnectPath      = "/api/burp/pair/disconnect"
	extensionStatePath      = "/api/burp/state"
	scopeActivePath         = "/api/burp/scope/active"
	scopeClearPath          = "/api/burp/scope/clear"
	approvalGatesActivePath = "/api/burp/approval-gates/active"
	extensionPingTimeout    = 90 * time.Second
	extensionPingCheck      = 5 * time.Second
	pairWindow              = 5 * time.Minute
	extensionWriteWait      = 10 * time.Second
)

var allowedPairOrigins = map[string]bool{
	"https://app.revelion.ai": true,
	"http://localhost:3000":   true,
}

var ErrExtensionStateNotReceived = errors.New("extension_state_not_received")

type configSaver func(*config.Config) error

// ExtensionServer exposes the local Revelion Burp Extension control-plane
// WebSocket. It is daemon-local only and must be bound to loopback.
type ExtensionServer struct {
	cfg  *config.Config
	save configSaver

	mu                  sync.Mutex
	writeMu             sync.Mutex
	server              *http.Server
	conn                *websocket.Conn
	connectedAt         time.Time
	lastPing            time.Time
	remoteAddr          string
	burpState           *BurpExtensionState
	activeScope         *ActiveScope
	activeApprovalGates *ActiveApprovalGates
	activeBurpScan      *ActiveBurpScan
	scanIssueHandler    func(missionID, scanID string, issue json.RawMessage)

	pairFilePath      string
	now               func() time.Time
	pingTimeout       time.Duration
	pingCheckInterval time.Duration
}

// ExtensionConnectionState is the current in-process extension connection state.
type ExtensionConnectionState struct {
	Connected           bool      `json:"connected"`
	ConnectedAt         time.Time `json:"connected_at,omitempty"`
	LastPingAt          time.Time `json:"last_ping_at,omitempty"`
	RemoteAddr          string    `json:"remote_addr,omitempty"`
	SessionTokenPresent bool      `json:"session_token_present"`
}

type BurpExtensionState struct {
	BurpVersion         string                   `json:"burp_version"`
	BurpEdition         string                   `json:"burp_edition"`
	ProjectName         string                   `json:"project_name"`
	ProjectSaved        bool                     `json:"project_saved"`
	ProxyListeners      []BurpProxyListener      `json:"proxy_listeners"`
	Scope               BurpScopeState           `json:"scope"`
	ScannerReady        bool                     `json:"scanner_ready"`
	InstalledExtensions []BurpInstalledExtension `json:"installed_extensions"`
	PushedAt            time.Time                `json:"pushed_at"`
}

type BurpProxyListener struct {
	Port           int    `json:"port"`
	BindAddress    string `json:"bind_address"`
	TLS            bool   `json:"tls"`
	InvisibleProxy bool   `json:"invisible_proxy"`
}

type BurpScopeState struct {
	IncludeRules []string `json:"include_rules"`
	ExcludeRules []string `json:"exclude_rules"`
}

type BurpInstalledExtension struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type ActiveScope struct {
	MissionID  string    `json:"mission_id"`
	SnapshotID string    `json:"snapshot_id"`
	Include    []string  `json:"include"`
	Exclude    []string  `json:"exclude"`
	AppliedAt  time.Time `json:"applied_at,omitempty"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
}

type ActiveApprovalGates struct {
	SnapshotID string    `json:"snapshot_id"`
	Autonomous bool      `json:"autonomous"`
	AppliedAt  time.Time `json:"applied_at,omitempty"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
}

type ActiveBurpScan struct {
	MissionID        string    `json:"mission_id"`
	ScanID           string    `json:"scan_id"`
	TargetURL        string    `json:"target_url"`
	AuditConfigLabel string    `json:"audit_config_label,omitempty"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	Status           string    `json:"status"`
	Error            string    `json:"error,omitempty"`
}

type jsonRPCMessage struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type pairInitiateResponse struct {
	PairCode  string `json:"pair_code"`
	ExpiresAt string `json:"expires_at"`
	DaemonURL string `json:"daemon_url"`
}

type pairStatusResponse struct {
	Connected     bool   `json:"connected"`
	PairedSession bool   `json:"paired_session"`
	PairPending   bool   `json:"pair_pending"`
	PairExpiresAt string `json:"pair_expires_at,omitempty"`
	RemoteAddr    string `json:"remote_addr,omitempty"`
}

type pairCancelResponse struct {
	Cancelled bool `json:"cancelled"`
}

type pairDisconnectResponse struct {
	Disconnected bool `json:"disconnected"`
}

func NewExtensionServer(cfg *config.Config) *ExtensionServer {
	return newExtensionServer(cfg, config.Save)
}

func newExtensionServer(cfg *config.Config, save configSaver) *ExtensionServer {
	if strings.TrimSpace(cfg.BurpExtensionAddr) == "" {
		cfg.BurpExtensionAddr = config.DefaultConfig().BurpExtensionAddr
	}
	return &ExtensionServer{
		cfg:               cfg,
		save:              save,
		now:               func() time.Time { return time.Now().UTC() },
		pingTimeout:       extensionPingTimeout,
		pingCheckInterval: extensionPingCheck,
	}
}

func (s *ExtensionServer) EnsurePairToken() (string, error) {
	if strings.TrimSpace(s.cfg.BurpExtensionPairToken) != "" {
		return s.cfg.BurpExtensionPairToken, nil
	}
	token, err := config.RandomHexToken(32)
	if err != nil {
		return "", err
	}
	s.cfg.BurpExtensionPairToken = token
	if err := s.save(s.cfg); err != nil {
		return "", err
	}
	return token, nil
}

func (s *ExtensionServer) URL() string {
	return "ws://" + s.cfg.BurpExtensionAddr + extensionPath
}

func (s *ExtensionServer) SetScanIssueHandler(handler func(missionID, scanID string, issue json.RawMessage)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanIssueHandler = handler
}

func (s *ExtensionServer) Start() error {
	ln, err := net.Listen("tcp", s.cfg.BurpExtensionAddr)
	if err != nil {
		return fmt.Errorf("listen for Burp extension on %s: %w", s.cfg.BurpExtensionAddr, err)
	}
	s.server = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Burp extension server stopped with error: %v", err)
		}
	}()
	return nil
}

func (s *ExtensionServer) Close() {
	s.mu.Lock()
	if s.conn != nil {
		_ = s.writeNotificationLocked(s.conn, "connection.evicted", map[string]any{"reason": "daemon_shutdown"})
		_ = s.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "daemon shutdown"), time.Now().Add(extensionWriteWait))
		_ = s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
	if s.server != nil {
		_ = s.server.Close()
	}
}

func (s *ExtensionServer) disconnectExtension(reason string) error {
	s.mu.Lock()
	conn := s.conn
	s.cfg.BurpExtensionSessionToken = ""
	if conn != nil {
		_ = s.writeNotificationLocked(conn, "connection.evicted", map[string]any{"reason": reason})
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason), time.Now().Add(extensionWriteWait))
		_ = conn.Close()
		s.conn = nil
		s.remoteAddr = ""
	}
	s.mu.Unlock()
	return s.save(s.cfg)
}

func (s *ExtensionServer) State() ExtensionConnectionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ExtensionConnectionState{
		Connected:           s.conn != nil,
		ConnectedAt:         s.connectedAt,
		LastPingAt:          s.lastPing,
		RemoteAddr:          s.remoteAddr,
		SessionTokenPresent: strings.TrimSpace(s.cfg.BurpExtensionSessionToken) != "",
	}
}

func (s *ExtensionServer) InitiatePair() (pairInitiateResponse, error) {
	token, err := config.RandomHexToken(32)
	if err != nil {
		return pairInitiateResponse{}, fmt.Errorf("token generation failed: %w", err)
	}
	code, err := randomPairCode()
	if err != nil {
		return pairInitiateResponse{}, fmt.Errorf("pair code generation failed: %w", err)
	}
	expiresAt := s.now().Add(pairWindow).UTC()

	s.mu.Lock()
	s.cfg.BurpExtensionPairToken = token
	s.cfg.BurpExtensionPairTokenExpiresAt = expiresAt
	s.mu.Unlock()

	if err := s.writePairFile(token, code, expiresAt); err != nil {
		return pairInitiateResponse{}, fmt.Errorf("pair file write failed: %w", err)
	}
	if err := s.save(s.cfg); err != nil {
		return pairInitiateResponse{}, fmt.Errorf("pair state save failed: %w", err)
	}

	return pairInitiateResponse{
		PairCode:  code,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		DaemonURL: s.URL(),
	}, nil
}

func (s *ExtensionServer) PairStatus() pairStatusResponse {
	s.mu.Lock()
	connected := s.conn != nil
	remoteAddr := s.remoteAddr
	pairedSession := strings.TrimSpace(s.cfg.BurpExtensionSessionToken) != ""
	pairPending := strings.TrimSpace(s.cfg.BurpExtensionPairToken) != "" && !s.pairTokenExpiredLocked()
	expiresAt := s.cfg.BurpExtensionPairTokenExpiresAt
	s.mu.Unlock()

	resp := pairStatusResponse{
		Connected:     connected,
		PairedSession: pairedSession,
		PairPending:   pairPending,
		RemoteAddr:    remoteAddr,
	}
	if !expiresAt.IsZero() {
		resp.PairExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	}
	return resp
}

func (s *ExtensionServer) CancelPair() error {
	s.mu.Lock()
	s.cfg.BurpExtensionPairToken = ""
	s.cfg.BurpExtensionPairTokenExpiresAt = time.Time{}
	s.mu.Unlock()

	_ = os.Remove(s.pairPath())
	return s.save(s.cfg)
}

func (s *ExtensionServer) DisconnectExtension() error {
	return s.disconnectExtension("pair_disconnect")
}

func (s *ExtensionServer) BurpState() (*BurpExtensionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.burpState == nil {
		return nil, ErrExtensionStateNotReceived
	}
	copy := *s.burpState
	copy.ProxyListeners = append([]BurpProxyListener{}, s.burpState.ProxyListeners...)
	copy.Scope.IncludeRules = append([]string{}, s.burpState.Scope.IncludeRules...)
	copy.Scope.ExcludeRules = append([]string{}, s.burpState.Scope.ExcludeRules...)
	copy.InstalledExtensions = append([]BurpInstalledExtension{}, s.burpState.InstalledExtensions...)
	return &copy, nil
}

func (s *ExtensionServer) ActiveScope() *ActiveScope {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeScope == nil {
		return nil
	}
	copy := *s.activeScope
	copy.Include = append([]string{}, s.activeScope.Include...)
	copy.Exclude = append([]string{}, s.activeScope.Exclude...)
	return &copy
}

func (s *ExtensionServer) ActiveApprovalGates() *ActiveApprovalGates {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeApprovalGates == nil {
		return nil
	}
	copy := *s.activeApprovalGates
	return &copy
}

func (s *ExtensionServer) ActiveBurpScan() *ActiveBurpScan {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeBurpScan == nil {
		return nil
	}
	copy := *s.activeBurpScan
	return &copy
}

func (s *ExtensionServer) SendScopeSet(missionID, snapshotID string, include []string, exclude []string) error {
	s.mu.Lock()
	conn := s.conn
	if conn == nil {
		s.mu.Unlock()
		return errors.New("extension_not_paired")
	}
	scope := &ActiveScope{
		MissionID:  missionID,
		SnapshotID: snapshotID,
		Include:    append([]string{}, include...),
		Exclude:    append([]string{}, exclude...),
		AppliedAt:  s.now(),
		Status:     "applied",
	}
	s.activeScope = scope
	payload := map[string]any{
		"mission_id":    missionID,
		"snapshot_id":   snapshotID,
		"include_rules": append([]string{}, include...),
		"exclude_rules": append([]string{}, exclude...),
	}
	s.mu.Unlock()
	return s.writeNotification(conn, "scope.set", payload)
}

func (s *ExtensionServer) SendScopeRestore(snapshotID string) error {
	s.mu.Lock()
	conn := s.conn
	if conn == nil {
		s.mu.Unlock()
		return errors.New("extension_not_paired")
	}
	if s.activeScope != nil {
		s.activeScope.Status = "restoring"
	}
	s.mu.Unlock()
	return s.writeNotification(conn, "scope.restore", map[string]any{"snapshot_id": snapshotID})
}

func (s *ExtensionServer) SendApprovalGatesSet(snapshotID string, autonomous bool) error {
	s.mu.Lock()
	conn := s.conn
	if conn == nil {
		s.mu.Unlock()
		return errors.New("extension_not_paired")
	}
	gates := &ActiveApprovalGates{
		SnapshotID: snapshotID,
		Autonomous: autonomous,
		AppliedAt:  s.now(),
		Status:     "applying",
	}
	s.activeApprovalGates = gates
	payload := map[string]any{
		"snapshot_id": snapshotID,
		"autonomous":  autonomous,
	}
	s.mu.Unlock()
	return s.writeNotification(conn, "approval_gates.set", payload)
}

func (s *ExtensionServer) SendApprovalGatesRestore(snapshotID string) error {
	s.mu.Lock()
	conn := s.conn
	if conn == nil {
		s.mu.Unlock()
		return errors.New("extension_not_paired")
	}
	if s.activeApprovalGates != nil {
		s.activeApprovalGates.Status = "restoring"
	}
	s.mu.Unlock()
	return s.writeNotification(conn, "approval_gates.restore", map[string]any{"snapshot_id": snapshotID})
}

func (s *ExtensionServer) SendScanStart(missionID, scanID, targetURL, auditConfigLabel string) error {
	s.mu.Lock()
	conn := s.conn
	if conn == nil {
		s.mu.Unlock()
		return errors.New("extension_not_paired")
	}
	if scanID == "" {
		scanID = missionID
	}
	s.activeBurpScan = &ActiveBurpScan{
		MissionID:        missionID,
		ScanID:           scanID,
		TargetURL:        targetURL,
		AuditConfigLabel: auditConfigLabel,
		StartedAt:        s.now(),
		Status:           "starting",
	}
	payload := map[string]any{
		"mission_id":         missionID,
		"scan_id":            scanID,
		"target_url":         targetURL,
		"audit_config_label": auditConfigLabel,
	}
	s.mu.Unlock()
	return s.writeNotification(conn, "scan.start", payload)
}

func (s *ExtensionServer) SendScanCancel(scanID string) error {
	s.mu.Lock()
	conn := s.conn
	if conn == nil {
		s.mu.Unlock()
		return errors.New("extension_not_paired")
	}
	if scanID == "" && s.activeBurpScan != nil {
		scanID = s.activeBurpScan.ScanID
	}
	if s.activeBurpScan != nil && (scanID == "" || s.activeBurpScan.ScanID == scanID) {
		s.activeBurpScan.Status = "cancelling"
	}
	s.mu.Unlock()
	return s.writeNotification(conn, "scan.cancel", map[string]any{"scan_id": scanID})
}

func (s *ExtensionServer) ClearScanForMission(missionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeBurpScan != nil && (missionID == "" || s.activeBurpScan.MissionID == missionID) {
		s.activeBurpScan = nil
	}
}

func (s *ExtensionServer) ClearScope() error {
	scope := s.ActiveScope()
	snapshotID := ""
	if scope != nil {
		snapshotID = scope.SnapshotID
	}
	return s.SendScopeRestore(snapshotID)
}

func (s *ExtensionServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(extensionPath, s.handleExtension)
	mux.HandleFunc(pairInitiatePath, s.handlePairInitiate)
	mux.HandleFunc(pairStatusPath, s.handlePairStatus)
	mux.HandleFunc(pairCancelPath, s.handlePairCancel)
	mux.HandleFunc(pairDisconnectPath, s.handlePairDisconnect)
	mux.HandleFunc(extensionStatePath, s.handleExtensionState)
	mux.HandleFunc(scopeActivePath, s.handleScopeActive)
	mux.HandleFunc(scopeClearPath, s.handleScopeClear)
	mux.HandleFunc(approvalGatesActivePath, s.handleApprovalGatesActive)
	return mux
}

func (s *ExtensionServer) handlePairInitiate(w http.ResponseWriter, r *http.Request) {
	if !s.prepareLocalAPI(w, r, http.MethodPost) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	resp, err := s.InitiatePair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeHTTPJSON(w, resp)
}

func (s *ExtensionServer) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	if !s.prepareLocalAPI(w, r, http.MethodGet) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	writeHTTPJSON(w, s.PairStatus())
}

func (s *ExtensionServer) handlePairCancel(w http.ResponseWriter, r *http.Request) {
	if !s.prepareLocalAPI(w, r, http.MethodPost) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := s.CancelPair(); err != nil {
		http.Error(w, "pair state save failed", http.StatusInternalServerError)
		return
	}
	writeHTTPJSON(w, pairCancelResponse{Cancelled: true})
}

func (s *ExtensionServer) handlePairDisconnect(w http.ResponseWriter, r *http.Request) {
	if !s.prepareLocalAPI(w, r, http.MethodPost) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := s.DisconnectExtension(); err != nil {
		http.Error(w, "disconnect failed", http.StatusInternalServerError)
		return
	}
	writeHTTPJSON(w, pairDisconnectResponse{Disconnected: true})
}

func (s *ExtensionServer) handleExtensionState(w http.ResponseWriter, r *http.Request) {
	if !s.prepareLocalAPI(w, r, http.MethodGet) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	state, err := s.BurpState()
	if errors.Is(err, ErrExtensionStateNotReceived) {
		http.Error(w, "state not received", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "state unavailable", http.StatusInternalServerError)
		return
	}
	writeHTTPJSON(w, state)
}

func (s *ExtensionServer) handleScopeActive(w http.ResponseWriter, r *http.Request) {
	if !s.prepareLocalAPI(w, r, http.MethodGet) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	scope := s.ActiveScope()
	if scope == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeHTTPJSON(w, scope)
}

func (s *ExtensionServer) handleScopeClear(w http.ResponseWriter, r *http.Request) {
	if !s.prepareLocalAPI(w, r, http.MethodPost) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.ClearScope(); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeHTTPJSON(w, map[string]any{"cleared": true})
}

func (s *ExtensionServer) handleApprovalGatesActive(w http.ResponseWriter, r *http.Request) {
	if !s.prepareLocalAPI(w, r, http.MethodGet) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	gates := s.ActiveApprovalGates()
	if gates == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeHTTPJSON(w, gates)
}

func (s *ExtensionServer) prepareLocalAPI(w http.ResponseWriter, r *http.Request, allowedMethod string) bool {
	if r.URL.Path != pairInitiatePath &&
		r.URL.Path != pairStatusPath &&
		r.URL.Path != pairCancelPath &&
		r.URL.Path != pairDisconnectPath &&
		r.URL.Path != extensionStatePath &&
		r.URL.Path != scopeActivePath &&
		r.URL.Path != scopeClearPath &&
		r.URL.Path != approvalGatesActivePath {
		http.NotFound(w, r)
		return false
	}
	if !s.validHost(r.Host) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if !s.applyCORS(w, r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if r.Method != allowedMethod && r.Method != http.MethodOptions {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (s *ExtensionServer) applyCORS(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Vary", "Origin")
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if !allowedPairOrigins[origin] {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "false")
	return true
}

func (s *ExtensionServer) writePairFile(token, code string, expiresAt time.Time) error {
	path := s.pairPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(map[string]string{
		"daemon_url": s.URL(),
		"pair_token": token,
		"pair_code":  code,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0600)
}

func (s *ExtensionServer) pairPath() string {
	if s.pairFilePath != "" {
		return s.pairFilePath
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".revelion", "burp-pair.json")
}

func (s *ExtensionServer) handleExtension(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != extensionPath {
		http.NotFound(w, r)
		return
	}
	if !s.validHost(r.Host) || !s.validOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	sessionToken, reconnected, authErr, ok := s.authenticate(r)
	if !ok {
		if authErr != "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s"`, authErr))
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Burp extension upgrade failed: %v", err)
		return
	}

	now := s.now()
	s.registerConnection(conn, now, r.RemoteAddr)
	log.Printf("Burp extension connected from %s", r.RemoteAddr)

	_ = s.writeNotification(conn, "session.granted", map[string]any{
		"session_token": sessionToken,
		"reconnected":   reconnected,
		"server_time":   now.Format(time.RFC3339),
	})
	s.republishActiveState(conn)

	s.readLoop(conn)
}

func (s *ExtensionServer) republishActiveState(conn *websocket.Conn) {
	var scope *ActiveScope
	var gates *ActiveApprovalGates
	s.mu.Lock()
	if s.activeScope != nil {
		copy := *s.activeScope
		copy.Include = append([]string{}, s.activeScope.Include...)
		copy.Exclude = append([]string{}, s.activeScope.Exclude...)
		scope = &copy
	}
	if s.activeApprovalGates != nil && s.activeApprovalGates.Status != "restoring" {
		copy := *s.activeApprovalGates
		gates = &copy
	}
	s.mu.Unlock()

	if scope != nil && scope.Status != "failed" {
		_ = s.writeNotification(conn, "scope.set", map[string]any{
			"mission_id":    scope.MissionID,
			"snapshot_id":   scope.SnapshotID,
			"include_rules": scope.Include,
			"exclude_rules": scope.Exclude,
			"reconnected":   true,
		})
	}
	if gates != nil && gates.Status != "failed" {
		_ = s.writeNotification(conn, "approval_gates.set", map[string]any{
			"snapshot_id": gates.SnapshotID,
			"autonomous":  gates.Autonomous,
			"reconnected": true,
		})
	}
}

func (s *ExtensionServer) validHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	return host == "127.0.0.1" || strings.EqualFold(host, "localhost")
}

func (s *ExtensionServer) validOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	ua := strings.ToLower(r.UserAgent())
	return strings.Contains(ua, "burp")
}

func (s *ExtensionServer) authenticate(r *http.Request) (sessionToken string, reconnected bool, authErr string, ok bool) {
	if token := strings.TrimSpace(r.Header.Get("X-Revelion-Session-Token")); token != "" {
		expected := strings.TrimSpace(s.cfg.BurpExtensionSessionToken)
		if expected != "" && subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1 {
			return expected, true, "", true
		}
		return "", false, "invalid_session", false
	}

	pairToken := strings.TrimSpace(r.Header.Get("X-Revelion-Pair-Token"))
	expectedPair := strings.TrimSpace(s.cfg.BurpExtensionPairToken)
	s.mu.Lock()
	expired := expectedPair != "" && s.pairTokenExpiredLocked()
	s.mu.Unlock()
	if expired {
		return "", false, "pair_expired", false
	}
	if pairToken == "" || expectedPair == "" || subtle.ConstantTimeCompare([]byte(pairToken), []byte(expectedPair)) != 1 {
		return "", false, "invalid_pair", false
	}

	newSession, err := config.RandomHexToken(32)
	if err != nil {
		log.Printf("Failed to generate Burp extension session token: %v", err)
		return "", false, "session_generation_failed", false
	}
	s.cfg.BurpExtensionSessionToken = newSession
	s.cfg.BurpExtensionPairToken = ""
	s.cfg.BurpExtensionPairTokenExpiresAt = time.Time{}
	if err := s.save(s.cfg); err != nil {
		log.Printf("Failed to persist Burp extension session token: %v", err)
		return "", false, "session_save_failed", false
	}
	return newSession, false, "", true
}

func (s *ExtensionServer) registerConnection(conn *websocket.Conn, connectedAt time.Time, remoteAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil && s.conn != conn {
		_ = s.writeNotificationLocked(s.conn, "connection.evicted", map[string]any{"reason": "new_extension_connection"})
		_ = s.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "new extension connection"), time.Now().Add(extensionWriteWait))
		_ = s.conn.Close()
	}
	s.conn = conn
	s.connectedAt = connectedAt
	s.lastPing = connectedAt
	s.remoteAddr = remoteAddr
}

func (s *ExtensionServer) clearConnection(conn *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == conn {
		s.conn = nil
		s.remoteAddr = ""
	}
}

func (s *ExtensionServer) readLoop(conn *websocket.Conn) {
	defer func() {
		s.clearConnection(conn)
		_ = conn.Close()
	}()

	done := make(chan struct{})
	go s.watchPingTimeout(conn, done)
	defer close(done)

	conn.SetPingHandler(func(appData string) error {
		s.markPing(conn)
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(extensionWriteWait))
	})

	for {
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if messageType != websocket.TextMessage {
			continue
		}

		var msg jsonRPCMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_json", "message": "Invalid JSON-RPC message"})
			continue
		}
		switch msg.Method {
		case "ping":
			s.markPing(conn)
			_ = s.writeResponse(conn, msg.ID, map[string]any{"pong": true, "server_time": time.Now().UTC().Format(time.RFC3339)})
		case "state.push":
			if err := s.handleStatePush(conn, msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_state", "message": err.Error()})
			}
		case "scope.applied":
			if err := s.handleScopeApplied(msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_scope_ack", "message": err.Error()})
			}
		case "scope.restored":
			if err := s.handleScopeRestored(msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_scope_ack", "message": err.Error()})
			}
		case "scope.failed":
			if err := s.handleScopeFailed(msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_scope_ack", "message": err.Error()})
			}
		case "approval_gates.applied":
			if err := s.handleApprovalGatesApplied(msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_approval_gates_ack", "message": err.Error()})
			}
		case "approval_gates.restored":
			if err := s.handleApprovalGatesRestored(msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_approval_gates_ack", "message": err.Error()})
			}
		case "approval_gates.failed":
			if err := s.handleApprovalGatesFailed(msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_approval_gates_ack", "message": err.Error()})
			}
		case "scan.started":
			if err := s.handleScanStarted(msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_scan_ack", "message": err.Error()})
			}
		case "scan.cancelled":
			if err := s.handleScanCancelled(msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_scan_ack", "message": err.Error()})
			}
		case "scan.failed":
			if err := s.handleScanFailed(msg.Params); err != nil {
				_ = s.writeNotification(conn, "error", map[string]any{"code": "invalid_scan_ack", "message": err.Error()})
			}
		case "scan.issue.found":
			s.handleScanIssueFound(msg.Params)
		}
	}
}

func (s *ExtensionServer) handleStatePush(conn *websocket.Conn, raw json.RawMessage) error {
	if len(raw) == 0 {
		return errors.New("state.push missing params")
	}
	var state BurpExtensionState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("decode state.push params: %w", err)
	}
	if state.PushedAt.IsZero() {
		state.PushedAt = s.now()
	}
	if state.ProxyListeners == nil {
		state.ProxyListeners = []BurpProxyListener{}
	}
	if state.Scope.IncludeRules == nil {
		state.Scope.IncludeRules = []string{}
	}
	if state.Scope.ExcludeRules == nil {
		state.Scope.ExcludeRules = []string{}
	}
	if state.InstalledExtensions == nil {
		state.InstalledExtensions = []BurpInstalledExtension{}
	}
	s.mu.Lock()
	if s.conn != conn {
		s.mu.Unlock()
		return errors.New("state.push from stale connection")
	}
	s.burpState = &state
	s.mu.Unlock()

	return s.writeNotification(conn, "state.ack", map[string]any{"received_at": s.now().Format(time.RFC3339)})
}

func (s *ExtensionServer) handleScopeApplied(raw json.RawMessage) error {
	var params struct {
		SnapshotID string `json:"snapshot_id"`
		AppliedAt  string `json:"applied_at"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeScope == nil {
		return nil
	}
	if params.SnapshotID != "" && s.activeScope.SnapshotID != params.SnapshotID {
		return nil
	}
	s.activeScope.Status = "applied"
	s.activeScope.Error = ""
	if params.AppliedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, params.AppliedAt); err == nil {
			s.activeScope.AppliedAt = parsed
		}
	}
	return nil
}

func (s *ExtensionServer) handleScopeRestored(raw json.RawMessage) error {
	var params struct {
		SnapshotID string `json:"snapshot_id"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &params); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeScope == nil || params.SnapshotID == "" || s.activeScope.SnapshotID == params.SnapshotID {
		s.activeScope = nil
	}
	return nil
}

func (s *ExtensionServer) handleScopeFailed(raw json.RawMessage) error {
	var params struct {
		SnapshotID string `json:"snapshot_id"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeScope == nil {
		s.activeScope = &ActiveScope{SnapshotID: params.SnapshotID}
	}
	if params.SnapshotID == "" || s.activeScope.SnapshotID == params.SnapshotID {
		s.activeScope.Status = "failed"
		s.activeScope.Error = params.Error
	}
	return nil
}

func (s *ExtensionServer) handleApprovalGatesApplied(raw json.RawMessage) error {
	var params struct {
		SnapshotID string `json:"snapshot_id"`
		AppliedAt  string `json:"applied_at"`
		Autonomous bool   `json:"autonomous"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeApprovalGates == nil {
		s.activeApprovalGates = &ActiveApprovalGates{SnapshotID: params.SnapshotID, Autonomous: params.Autonomous}
	}
	if params.SnapshotID != "" && s.activeApprovalGates.SnapshotID != params.SnapshotID {
		return nil
	}
	s.activeApprovalGates.Status = "applied"
	s.activeApprovalGates.Error = ""
	s.activeApprovalGates.Autonomous = params.Autonomous
	if params.AppliedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, params.AppliedAt); err == nil {
			s.activeApprovalGates.AppliedAt = parsed
		}
	}
	return nil
}

func (s *ExtensionServer) handleApprovalGatesRestored(raw json.RawMessage) error {
	var params struct {
		SnapshotID string `json:"snapshot_id"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &params); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeApprovalGates == nil || params.SnapshotID == "" || s.activeApprovalGates.SnapshotID == params.SnapshotID {
		s.activeApprovalGates = nil
	}
	return nil
}

func (s *ExtensionServer) handleApprovalGatesFailed(raw json.RawMessage) error {
	var params struct {
		SnapshotID string `json:"snapshot_id"`
		Error      string `json:"error"`
		Reason     string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeApprovalGates == nil {
		s.activeApprovalGates = &ActiveApprovalGates{SnapshotID: params.SnapshotID}
	}
	if params.SnapshotID == "" || s.activeApprovalGates.SnapshotID == params.SnapshotID {
		s.activeApprovalGates.Status = "failed"
		if params.Reason != "" {
			s.activeApprovalGates.Error = params.Reason
		} else {
			s.activeApprovalGates.Error = params.Error
		}
	}
	return nil
}

func (s *ExtensionServer) handleScanStarted(raw json.RawMessage) error {
	var params struct {
		ScanID           string `json:"scan_id"`
		MissionID        string `json:"mission_id"`
		TargetURL        string `json:"target_url"`
		AuditConfigLabel string `json:"audit_config_label"`
		StartedAt        string `json:"started_at"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeBurpScan == nil {
		s.activeBurpScan = &ActiveBurpScan{}
	}
	if params.ScanID != "" {
		s.activeBurpScan.ScanID = params.ScanID
	}
	if params.MissionID != "" {
		s.activeBurpScan.MissionID = params.MissionID
	}
	if params.TargetURL != "" {
		s.activeBurpScan.TargetURL = params.TargetURL
	}
	if params.AuditConfigLabel != "" {
		s.activeBurpScan.AuditConfigLabel = params.AuditConfigLabel
	}
	if params.StartedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, params.StartedAt); err == nil {
			s.activeBurpScan.StartedAt = parsed
		}
	}
	if s.activeBurpScan.StartedAt.IsZero() {
		s.activeBurpScan.StartedAt = s.now()
	}
	s.activeBurpScan.Status = "running"
	s.activeBurpScan.Error = ""
	return nil
}

func (s *ExtensionServer) handleScanCancelled(raw json.RawMessage) error {
	var params struct {
		ScanID string `json:"scan_id"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &params); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeBurpScan == nil || params.ScanID == "" || s.activeBurpScan.ScanID == params.ScanID {
		s.activeBurpScan = nil
	}
	return nil
}

func (s *ExtensionServer) handleScanFailed(raw json.RawMessage) error {
	var params struct {
		ScanID string `json:"scan_id"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeBurpScan == nil {
		s.activeBurpScan = &ActiveBurpScan{ScanID: params.ScanID}
	}
	if params.ScanID == "" || s.activeBurpScan.ScanID == params.ScanID {
		s.activeBurpScan.Status = "failed"
		s.activeBurpScan.Error = params.Error
	}
	return nil
}

func (s *ExtensionServer) handleScanIssueFound(raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var handler func(string, string, json.RawMessage)
	missionID := ""
	scanID := ""

	s.mu.Lock()
	if s.activeBurpScan != nil {
		missionID = s.activeBurpScan.MissionID
		scanID = s.activeBurpScan.ScanID
	}
	if scanID == "" {
		scanID = missionID
	}
	handler = s.scanIssueHandler
	s.mu.Unlock()

	if missionID == "" {
		log.Printf("Dropping Burp scanner issue because no active Revelion mission is registered")
		return
	}
	if handler == nil {
		log.Printf("Dropping Burp scanner issue for mission %s because no handler is registered", missionID)
		return
	}
	handler(missionID, scanID, raw)
}

func (s *ExtensionServer) watchPingTimeout(conn *websocket.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(s.pingCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			s.mu.Lock()
			stale := s.conn == conn && s.now().Sub(s.lastPing) > s.pingTimeout
			s.mu.Unlock()
			if stale {
				_ = s.writeNotification(conn, "connection.timeout", map[string]any{"reason": "ping_timeout"})
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "ping timeout"), time.Now().Add(extensionWriteWait))
				_ = conn.Close()
				return
			}
		}
	}
}

func (s *ExtensionServer) markPing(conn *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == conn {
		s.lastPing = s.now()
	}
}

func (s *ExtensionServer) writeNotification(conn *websocket.Conn, method string, params any) error {
	return s.writeJSON(conn, map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

func (s *ExtensionServer) writeNotificationLocked(conn *websocket.Conn, method string, params any) error {
	return s.writeJSON(conn, map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

func (s *ExtensionServer) writeResponse(conn *websocket.Conn, id any, result any) error {
	return s.writeJSON(conn, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *ExtensionServer) writeJSON(conn *websocket.Conn, payload any) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	conn.SetWriteDeadline(time.Now().Add(extensionWriteWait))
	return conn.WriteJSON(payload)
}

func (s *ExtensionServer) pairTokenExpiredLocked() bool {
	return !s.cfg.BurpExtensionPairTokenExpiresAt.IsZero() && s.now().After(s.cfg.BurpExtensionPairTokenExpiresAt)
}

func randomPairCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func writeHTTPJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
