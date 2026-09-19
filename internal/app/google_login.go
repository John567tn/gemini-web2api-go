package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
)

const (
	googleLoginURL           = "https://gemini.google.com/app"
	googleLoginTTL           = 10 * time.Minute
	googleLoginKeepAlive     = 5 * time.Minute
	googleLoginProfileMarker = ".gemini-web2api-login-profile"
	googleLoginOrphanAge     = googleLoginTTL + googleLoginKeepAlive
)

var (
	googleLoginPollInterval          = 2 * time.Second
	googleLoginValidationRetryWindow = 5 * time.Second
)

const (
	googleLoginLaunching  = "launching"
	googleLoginWaiting    = "waiting_for_login"
	googleLoginValidating = "validating"
	googleLoginSucceeded  = "succeeded"
	googleLoginFailed     = "failed"
	googleLoginCanceled   = "canceled"
	googleLoginExpired    = "expired"
)

// browserCookie is the small, credential-bearing part of a CDP cookie.  It is
// intentionally kept behind the browser driver interface so the login state
// machine can be tested without starting a real browser.
type browserCookie struct {
	Name   string
	Value  string
	Domain string
	Path   string
}

type googleLoginBrowser interface {
	Navigate(context.Context, string) error
	Cookies(context.Context) ([]browserCookie, error)
	Close() error
}

type googleLoginBrowserFactory func(context.Context, string, string) (googleLoginBrowser, error)

type googleSessionValidationRequest struct {
	Cookie           string
	TargetAccountID  int64
	PreferredProxyID int64
}

type googleSessionValidation struct {
	ProxyID       int64
	ProxyFallback bool
	Warning       string
}

type googleSessionValidator func(googleSessionValidationRequest) (googleSessionValidation, error)

type googleLoginManager struct {
	mu        sync.Mutex
	sessions  map[string]*googleLoginSession
	factory   googleLoginBrowserFactory
	validator googleSessionValidator
}

type googleLoginSession struct {
	manager *googleLoginManager

	mu          sync.RWMutex
	id          string
	state       string
	message     string
	browserName string
	profileDir  string
	accountID   int64
	label       string
	note        string
	warning     string
	startedAt   time.Time
	expiresAt   time.Time
	finishedAt  time.Time

	browser         googleLoginBrowser
	cancel          context.CancelFunc
	cancelRequested bool
	lastFingerprint string
	lastValidation  time.Time
}

func newGoogleLoginManager(factory googleLoginBrowserFactory, validator googleSessionValidator) *googleLoginManager {
	return &googleLoginManager{
		sessions:  make(map[string]*googleLoginSession),
		factory:   factory,
		validator: validator,
	}
}

var googleLogins = newGoogleLoginManager(launchChromedpBrowser, validateGoogleLoginCookie)

func (m *googleLoginManager) start(label, note string, targetAccountID int64) (*googleLoginSession, error) {
	executable, browserName, err := discoverGoogleBrowser()
	if err != nil {
		return nil, err
	}
	if targetAccountID > 0 && accountByID(targetAccountID) == nil {
		return nil, fmt.Errorf("account not found")
	}

	id := uuid.NewString()
	profileRoot := googleBrowserProfileRoot()
	profileDir := filepath.Join(profileRoot, id)
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		return nil, fmt.Errorf("create browser profile: %w", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, googleLoginProfileMarker), []byte("gemini-web2api native login profile\n"), 0o600); err != nil {
		_ = os.RemoveAll(profileDir)
		return nil, fmt.Errorf("mark browser profile: %w", err)
	}
	warning := googleLoginNetworkWarning()
	message := "正在启动受控浏览器；请只在 Google 页面中完成登录"
	if warning != "" {
		message += "；警告：" + warning
	}

	ctx, cancel := context.WithTimeout(context.Background(), googleLoginTTL)
	s := &googleLoginSession{
		manager:     m,
		id:          id,
		state:       googleLoginLaunching,
		message:     message,
		browserName: browserName,
		profileDir:  profileDir,
		accountID:   targetAccountID,
		label:       strings.TrimSpace(label),
		note:        strings.TrimSpace(note),
		warning:     warning,
		startedAt:   time.Now(),
		expiresAt:   time.Now().Add(googleLoginTTL),
		cancel:      cancel,
	}

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	go s.run(ctx, executable)
	return s, nil
}

func (m *googleLoginManager) get(id string) *googleLoginSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return nil
	}
	if time.Now().After(s.expiresAt.Add(googleLoginKeepAlive)) {
		delete(m.sessions, id)
		return nil
	}
	return s
}

func (m *googleLoginManager) remove(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

func (s *googleLoginSession) run(ctx context.Context, executable string) {
	browser, err := s.manager.factory(ctx, executable, s.profileDir)
	if err != nil {
		s.fail("受控浏览器启动失败")
		if cleanupErr := removeGoogleBrowserProfile(s.profileDir); cleanupErr != nil {
			logf("[google-login] browser profile cleanup failed: %v", cleanupErr)
			scheduleGoogleBrowserProfileCleanup(s.profileDir)
		}
		s.cleanupLater()
		return
	}
	s.mu.Lock()
	s.browser = browser
	s.mu.Unlock()
	defer func() {
		_ = browser.Close()
		if err := removeGoogleBrowserProfile(s.profileDir); err != nil {
			logf("[google-login] browser profile cleanup failed: %v", err)
			scheduleGoogleBrowserProfileCleanup(s.profileDir)
		}
		s.cleanupLater()
	}()

	if err := browser.Navigate(ctx, googleLoginURL); err != nil {
		if s.wasCanceled() {
			return
		}
		s.fail("无法打开 Gemini 登录页面")
		return
	}
	s.setState(googleLoginWaiting, "请在浏览器窗口中直接完成 Google 登录；程序不会读取或填写密码、2FA、Passkey")

	ticker := time.NewTicker(googleLoginPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if s.wasCanceled() {
				return
			}
			s.expire()
			return
		case <-ticker.C:
		}

		cookies, err := browser.Cookies(ctx)
		if err != nil {
			if s.wasCanceled() {
				return
			}
			s.fail("浏览器窗口已关闭或不可用")
			return
		}
		cookie, ok := browserCookiesToHeader(cookies)
		if !ok {
			continue
		}

		fingerprint := cookieKey(cookie)
		s.mu.Lock()
		shouldValidate := fingerprint != s.lastFingerprint || time.Since(s.lastValidation) >= googleLoginValidationRetryWindow
		if shouldValidate {
			s.lastFingerprint = fingerprint
			s.lastValidation = time.Now()
		}
		s.mu.Unlock()
		if !shouldValidate {
			continue
		}

		s.setState(googleLoginValidating, "已检测到 Google session，正在验证 Gemini Web 登录态")
		preferredProxyID := int64(0)
		if s.accountID > 0 {
			if account := accountByID(s.accountID); account != nil {
				preferredProxyID = account.ProxyID
			}
		}
		validation, err := s.manager.validator(googleSessionValidationRequest{
			Cookie:           cookie,
			TargetAccountID:  s.accountID,
			PreferredProxyID: preferredProxyID,
		})
		if err != nil {
			// 不把上游错误原文写进状态或日志：它可能包含部署相关的请求细节。
			s.setState(googleLoginWaiting, "登录态尚未验证成功，请在 Google 页面完成登录后稍候")
			continue
		}

		accountID, err := adoptGoogleLogin(cookie, s.accountID, s.label, s.note, validation)
		if err != nil {
			s.fail("Google session 已验证，但写入本地账号池失败")
			return
		}
		_ = browser.Close()
		s.succeed(accountID, validation.Warning)
		return
	}
}

func (s *googleLoginSession) setState(state, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isGoogleLoginTerminal(s.state) {
		return
	}
	s.state = state
	s.message = message
}

func (s *googleLoginSession) succeed(accountID int64, warning string) {
	s.mu.Lock()
	if isGoogleLoginTerminal(s.state) {
		s.mu.Unlock()
		return
	}
	s.state = googleLoginSucceeded
	warning = combineGoogleLoginWarnings(s.warning, warning)
	s.warning = warning
	s.message = "Google 登录成功，浏览器窗口已关闭，账号已加入本地账号池"
	if warning != "" {
		s.message += "；警告：" + warning
	}
	s.accountID = accountID
	s.finishedAt = time.Now()
	s.mu.Unlock()
}

func (s *googleLoginSession) fail(message string) {
	s.mu.Lock()
	if isGoogleLoginTerminal(s.state) {
		s.mu.Unlock()
		return
	}
	s.state = googleLoginFailed
	s.message = message
	s.finishedAt = time.Now()
	s.mu.Unlock()
}

func (s *googleLoginSession) expire() {
	s.mu.Lock()
	if isGoogleLoginTerminal(s.state) {
		s.mu.Unlock()
		return
	}
	s.state = googleLoginExpired
	s.message = "登录 session 已过期，请重新开始 Google 登录"
	s.finishedAt = time.Now()
	s.mu.Unlock()
}

func (s *googleLoginSession) cancelSession() {
	s.mu.Lock()
	if isGoogleLoginTerminal(s.state) {
		s.mu.Unlock()
		return
	}
	s.cancelRequested = true
	s.state = googleLoginCanceled
	s.message = "登录已取消，受控浏览器正在关闭"
	s.finishedAt = time.Now()
	cancel := s.cancel
	browser := s.browser
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if browser != nil {
		_ = browser.Close()
	}
	s.cleanupLater()
}

func (s *googleLoginSession) wasCanceled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cancelRequested || s.state == googleLoginCanceled
}

func (s *googleLoginSession) cleanupLater() {
	time.AfterFunc(googleLoginKeepAlive, func() {
		s.manager.remove(s.id)
	})
}

func (s *googleLoginSession) view() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"session":    s.id,
		"state":      s.state,
		"message":    s.message,
		"browser":    s.browserName,
		"account_id": s.accountID,
		"warning":    s.warning,
		"started_at": s.startedAt.UTC().Format(time.RFC3339),
		"expires_at": s.expiresAt.UTC().Format(time.RFC3339),
		"finished_at": func() string {
			if s.finishedAt.IsZero() {
				return ""
			}
			return s.finishedAt.UTC().Format(time.RFC3339)
		}(),
	}
}

func isGoogleLoginTerminal(state string) bool {
	switch state {
	case googleLoginSucceeded, googleLoginFailed, googleLoginCanceled, googleLoginExpired:
		return true
	default:
		return false
	}
}

// handleGoogleLoginStart handles the admin-only browser launch request.  The
// browser path is discovered synchronously so a missing browser is reported
// as a clear HTTP error instead of leaving a failed background session behind.
func handleGoogleLoginStart(w http.ResponseWriter, r *http.Request) {
	if !isLocalAdminRequest(r) {
		writeJSON(w, 403, map[string]string{"error": "native Google login is localhost-only on the server host"})
		return
	}
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		Label     string `json:"label"`
		Note      string `json:"note"`
		AccountID int64  `json:"account_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	s, err := googleLogins.start(req.Label, req.Note, req.AccountID)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 202, s.view())
}

func handleGoogleLoginSession(w http.ResponseWriter, r *http.Request) {
	if !isLocalAdminRequest(r) {
		writeJSON(w, 403, map[string]string{"error": "native Google login is localhost-only on the server host"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/admin/api/google-login/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, 404, map[string]string{"error": "missing session"})
		return
	}
	s := googleLogins.get(parts[0])
	if s == nil {
		writeJSON(w, 404, map[string]string{"error": "login session not found or expired"})
		return
	}
	switch r.Method {
	case "GET":
		if len(parts) > 1 && parts[1] != "status" {
			writeJSON(w, 404, map[string]string{"error": "unknown action"})
			return
		}
		writeJSON(w, 200, s.view())
	case "POST":
		if len(parts) != 2 || parts[1] != "cancel" {
			writeJSON(w, 404, map[string]string{"error": "unknown action"})
			return
		}
		s.cancelSession()
		writeJSON(w, 200, s.view())
	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

// Native login is a browser-sensitive local capability.  Do not use
// Forwarded/X-Forwarded-* here: a client can provide those headers, and a
// reverse proxy can make a remote request appear loopback to the backend.
// The Host/origin checks below intentionally make public-domain proxying
// fail closed while still allowing a local curl request without Origin.
func isLocalAdminRequest(r *http.Request) bool {
	remote := strings.TrimSpace(r.RemoteAddr)
	if !isLoopbackRemoteAddr(remote) {
		return false
	}
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
		if values, present := r.Header[http.CanonicalHeaderKey(header)]; present && len(values) > 0 {
			return false
		}
	}
	if _, _, ok := requestLocalAuthority(r); !ok {
		return false
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if strings.EqualFold(origin, "null") || !isSameLocalBrowserAuthority(r, origin) {
			return false
		}
	}
	if fetchSite := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); fetchSite != "" {
		for _, token := range strings.Split(fetchSite, ",") {
			if strings.TrimSpace(token) == "cross-site" {
				return false
			}
		}
	}
	return true
}

func isLoopbackRemoteAddr(remote string) bool {
	if remote == "" {
		return false
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil || host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseLocalBrowserOrigin(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, false
	}
	if !isLocalHostName(u.Hostname()) {
		return nil, false
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, false
		}
	}
	return u, true
}

func isSameLocalBrowserAuthority(r *http.Request, rawOrigin string) bool {
	u, ok := parseLocalBrowserOrigin(rawOrigin)
	if !ok {
		return false
	}
	host, port, ok := requestLocalAuthority(r)
	if !ok {
		return false
	}
	originPort := u.Port()
	if originPort == "" {
		if u.Scheme == "https" {
			originPort = "443"
		} else {
			originPort = "80"
		}
	}
	return host == canonicalLocalHost(u.Hostname()) && port == originPort
}

func requestLocalAuthority(r *http.Request) (string, string, bool) {
	hostPort := strings.TrimSpace(r.Host)
	if hostPort == "" {
		return "", "", false
	}
	host, port, ok := splitHostPortForLocal(hostPort)
	if !ok || !isLocalHostName(host) {
		return "", "", false
	}
	if port == "" {
		if r.TLS != nil || (r.URL != nil && r.URL.Scheme == "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return canonicalLocalHost(host), port, true
}

func splitHostPortForLocal(raw string) (string, string, bool) {
	if host, port, err := net.SplitHostPort(raw); err == nil {
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return "", "", false
		}
		return host, port, true
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return strings.Trim(raw, "[]"), "", true
	}
	if strings.Count(raw, ":") == 0 {
		return raw, "", true
	}
	return "", "", false
}

func canonicalLocalHost(host string) string {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func isLocalHostName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// browserProfileRoot keeps the browser profile next to the configured data
// directory while preserving the default requested layout ./data/browser-profiles.
func googleBrowserProfileRoot() string {
	dbPath := cfg.DBPath
	if dbPath == "" {
		return filepath.Join("data", "browser-profiles")
	}
	dir := filepath.Dir(dbPath)
	if dir == "." || dir == "" {
		dir = "data"
	}
	return filepath.Join(dir, "browser-profiles")
}

func removeGoogleBrowserProfile(profileDir string) error {
	if profileDir == "" {
		return nil
	}
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		err = os.RemoveAll(profileDir)
		if err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

func scheduleGoogleBrowserProfileCleanup(profileDir string) {
	if profileDir == "" {
		return
	}
	go func() {
		deadline := time.Now().Add(15 * time.Minute)
		delay := 250 * time.Millisecond
		for {
			if err := os.RemoveAll(profileDir); err == nil {
				return
			}
			if time.Now().After(deadline) {
				logf("[google-login] browser profile cleanup still pending after retry window")
				return
			}
			time.Sleep(delay)
			if delay < 5*time.Second {
				delay *= 2
			}
		}
	}()
}

// cleanupOrphanGoogleBrowserProfiles removes only direct child directories
// carrying our marker (or legacy UUID names from the first implementation).
// The age threshold prevents a service restart from deleting an active login
// profile that was created moments ago.
func cleanupOrphanGoogleBrowserProfiles(root string, now time.Time) int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profileDir := filepath.Join(root, entry.Name())
		info, err := entry.Info()
		if err != nil || now.Sub(info.ModTime()) < googleLoginOrphanAge {
			continue
		}
		marker := filepath.Join(profileDir, googleLoginProfileMarker)
		_, markerErr := os.Stat(marker)
		_, uuidErr := uuid.Parse(entry.Name())
		if markerErr != nil && uuidErr != nil {
			continue
		}
		if err := removeGoogleBrowserProfile(profileDir); err == nil {
			removed++
		} else {
			scheduleGoogleBrowserProfileCleanup(profileDir)
		}
	}
	return removed
}

type browserCandidate struct {
	name  string
	paths []string
}

func discoverGoogleBrowser() (string, string, error) {
	var candidates []browserCandidate
	switch runtime.GOOS {
	case "windows":
		programFiles := os.Getenv("ProgramFiles")
		programFilesX86 := os.Getenv("ProgramFiles(x86)")
		localAppData := os.Getenv("LOCALAPPDATA")
		candidates = []browserCandidate{
			{name: "Chrome", paths: []string{
				filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(localAppData, "Google", "Chrome", "Application", "chrome.exe"),
				"chrome.exe",
			}},
			{name: "Edge", paths: []string{
				filepath.Join(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
				filepath.Join(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
				filepath.Join(localAppData, "Microsoft", "Edge", "Application", "msedge.exe"),
				"msedge.exe",
			}},
			{name: "Chromium", paths: []string{
				filepath.Join(programFiles, "Chromium", "Application", "chromium.exe"),
				filepath.Join(programFilesX86, "Chromium", "Application", "chromium.exe"),
				filepath.Join(localAppData, "Chromium", "Application", "chromium.exe"),
				"chromium.exe",
			}},
		}
	case "darwin":
		candidates = []browserCandidate{
			{name: "Chrome", paths: []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}},
			{name: "Edge", paths: []string{"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"}},
			{name: "Chromium", paths: []string{"/Applications/Chromium.app/Contents/MacOS/Chromium"}},
		}
	default:
		candidates = []browserCandidate{
			{name: "Chrome", paths: []string{"google-chrome", "google-chrome-stable"}},
			{name: "Edge", paths: []string{"microsoft-edge", "microsoft-edge-stable"}},
			{name: "Chromium", paths: []string{"chromium", "chromium-browser"}},
		}
	}
	for _, candidate := range candidates {
		for _, path := range candidate.paths {
			if path == "" {
				continue
			}
			if filepath.IsAbs(path) {
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					return path, candidate.name, nil
				}
				continue
			}
			if found, err := exec.LookPath(path); err == nil {
				return found, candidate.name, nil
			}
		}
	}
	return "", "", errors.New("找不到可用的 Chrome/Edge/Chromium 浏览器；请先安装桌面浏览器")
}

type chromedpGoogleBrowser struct {
	ctx           context.Context
	browserCancel context.CancelFunc
	allocCancel   context.CancelFunc
	process       *exec.Cmd
	closeOnce     sync.Once
}

func launchChromedpBrowser(parent context.Context, executable, profileDir string) (googleLoginBrowser, error) {
	// chromedp v0.14.2's DefaultExecAllocatorOptions include
	// --enable-automation and default --remote-debugging-port=0.  Launch the
	// normal installed browser ourselves, without those defaults, then attach
	// chromedp through a loopback-only, non-zero ephemeral port.
	port, err := allocateLoopbackCDPPort()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(parent, executable, googleBrowserCommandArgs(profileDir, port)...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start browser: %w", err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- cmd.Wait() }()

	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	wsURL, err := waitForCDPWebSocketURL(parent, endpoint, processDone)
	if err != nil {
		stopGoogleBrowserProcess(cmd, processDone)
		return nil, err
	}
	remoteCtx, allocCancel := chromedp.NewRemoteAllocator(parent, wsURL, chromedp.NoModifyURL)
	browserCtx, browserCancel := chromedp.NewContext(remoteCtx)
	return &chromedpGoogleBrowser{
		ctx:           browserCtx,
		browserCancel: browserCancel,
		allocCancel:   allocCancel,
		process:       cmd,
	}, nil
}

const (
	googleCDPReadinessTimeout  = 12 * time.Second
	googleCDPReadinessInterval = 75 * time.Millisecond
)

type cdpVersionResponse struct {
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

func newLocalCDPHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   1 * time.Second,
	}
}

func waitForCDPWebSocketURL(parent context.Context, endpoint string, processDone <-chan error) (string, error) {
	return waitForCDPWebSocketURLWith(
		parent,
		endpoint,
		processDone,
		newLocalCDPHTTPClient(),
		googleCDPReadinessTimeout,
		googleCDPReadinessInterval,
	)
}

func waitForCDPWebSocketURLWith(parent context.Context, endpoint string, processDone <-chan error, client *http.Client, timeout, interval time.Duration) (string, error) {
	if client == nil {
		client = newLocalCDPHTTPClient()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	var processExit <-chan error
	if processDone != nil {
		exit := make(chan error, 1)
		processExit = exit
		go func() {
			select {
			case err := <-processDone:
				exit <- err
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	versionURL := strings.TrimRight(endpoint, "/") + "/json/version"
	for {
		if err := ctx.Err(); err != nil {
			if processExit != nil {
				select {
				case processErr := <-processExit:
					if processErr == nil {
						return "", errors.New("browser process exited before CDP readiness")
					}
					return "", fmt.Errorf("browser process exited before CDP readiness: %w", processErr)
				default:
				}
			}
			if parent.Err() != nil {
				return "", fmt.Errorf("CDP readiness canceled: %w", parent.Err())
			}
			return "", fmt.Errorf("CDP readiness timeout: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
		if err == nil {
			resp, requestErr := client.Do(req)
			if requestErr == nil {
				var version cdpVersionResponse
				decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&version)
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 && decodeErr == nil && strings.TrimSpace(version.WebSocketDebuggerURL) != "" {
					return strings.TrimSpace(version.WebSocketDebuggerURL), nil
				}
			} else if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}

		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}
}

func stopGoogleBrowserProcess(cmd *exec.Cmd, processDone <-chan error) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if processDone != nil {
		select {
		case <-processDone:
		case <-time.After(2 * time.Second):
		}
	}
}

func allocateLoopbackCDPPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocate loopback CDP port: %w", err)
	}
	defer listener.Close()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		return 0, errors.New("allocate loopback CDP port: invalid listener address")
	}
	return addr.Port, nil
}

func googleBrowserCommandArgs(profileDir string, port int) []string {
	return []string{
		"--user-data-dir=" + profileDir,
		"--remote-debugging-address=127.0.0.1",
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--no-first-run",
		"--no-default-browser-check",
	}
}

func (b *chromedpGoogleBrowser) Navigate(ctx context.Context, target string) error {
	return chromedp.Run(b.ctx, chromedp.Navigate(target), chromedp.WaitReady("body", chromedp.ByQuery))
}

func (b *chromedpGoogleBrowser) Cookies(ctx context.Context) ([]browserCookie, error) {
	cookies, err := network.GetCookies().WithURLs([]string{googleLoginURL}).Do(b.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]browserCookie, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, browserCookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path})
	}
	return out, nil
}

func (b *chromedpGoogleBrowser) Close() error {
	b.closeOnce.Do(func() {
		b.browserCancel()
		b.allocCancel()
		if b.process != nil && b.process.Process != nil {
			_ = b.process.Process.Kill()
		}
	})
	return nil
}

// browserCookiesToHeader keeps only cookies that a request to Gemini would
// legitimately receive.  It never reads the user's normal browser profile.
func browserCookiesToHeader(cookies []browserCookie) (string, bool) {
	type selectedCookie struct {
		cookie browserCookie
		rank   int
	}
	selected := map[string]selectedCookie{}
	for _, c := range cookies {
		if c.Name == "" || c.Value == "" || !isGeminiCookieDomain(c.Domain) {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(c.Domain))
		rank := len(strings.TrimPrefix(domain, "."))*10 + len(c.Path)
		if old, ok := selected[c.Name]; ok && old.rank >= rank {
			continue
		}
		selected[c.Name] = selectedCookie{cookie: c, rank: rank}
	}
	var names []string
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		c := selected[name].cookie
		parts = append(parts, c.Name+"="+c.Value)
	}
	cookie := strings.Join(parts, "; ")
	return cookie, hasNativeGoogleLoginCookies(cookie)
}

func isGeminiCookieDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	return d == "google.com" || d == ".google.com" || d == "gemini.google.com" || strings.HasSuffix(d, ".gemini.google.com")
}

func hasNativeGoogleLoginCookies(cookie string) bool {
	return cookieValue(cookie, "SAPISID") != "" &&
		cookieValue(cookie, "__Secure-1PSID") != "" &&
		cookieValue(cookie, "__Secure-1PSIDTS") != ""
}

func validateGoogleLoginCookie(req googleSessionValidationRequest) (googleSessionValidation, error) {
	if !hasNativeGoogleLoginCookies(req.Cookie) {
		return googleSessionValidation{}, errors.New("required Google session cookies are missing")
	}
	picked, ok, err := acquireSlot(req.PreferredProxyID)
	if !ok {
		return googleSessionValidation{}, err
	}
	defer releaseSlot(picked.ID)
	entry, err := fetchAppTokens(req.Cookie, picked.URL)
	if err != nil {
		return googleSessionValidation{}, err
	}
	if entry.token == "" {
		return googleSessionValidation{}, errors.New("Gemini /app did not return SNlM0e")
	}
	validation := googleSessionValidation{ProxyID: picked.ID}
	if req.PreferredProxyID > 0 && picked.ID != req.PreferredProxyID {
		validation.ProxyFallback = true
		validation.Warning = googleLoginProxyFallbackWarning(req.PreferredProxyID, picked.ID)
		logf("[google-login] account #%d validation used proxy fallback: preferred=%d selected=%d", req.TargetAccountID, req.PreferredProxyID, picked.ID)
	}
	return validation, nil
}

func adoptGoogleLogin(cookie string, targetAccountID int64, label, note string, validation googleSessionValidation) (int64, error) {
	cookie, ok := normalizeCookie(cookie, "native Google login")
	if !ok || !hasNativeGoogleLoginCookies(cookie) {
		return 0, errors.New("validated Google session cookie is incomplete")
	}
	if targetAccountID > 0 {
		old := accountByID(targetAccountID)
		if old == nil {
			return 0, errors.New("account not found")
		}
		invalidateXSRF(old.Cookie)
		if err := accountReplaceCookie(targetAccountID, cookie, label); err != nil {
			return 0, err
		}
		bindAccountProxy(targetAccountID, validation.ProxyID)
		invalidateXSRF(cookie)
		invalidateGeminiUsageCache(targetAccountID)
		return targetAccountID, nil
	}
	if existing := accountByCookie(cookie); existing != nil {
		if strings.TrimSpace(label) != "" && strings.TrimSpace(existing.Label) == "" {
			_ = accountUpdateMeta(existing.ID, label, existing.Note)
		}
		_ = accountSetStatus(existing.ID, "enabled")
		markAccountResult(existing.ID, true, "")
		bindAccountProxy(existing.ID, validation.ProxyID)
		invalidateGeminiUsageCache(existing.ID)
		return existing.ID, nil
	}
	id, err := accountAdopt(label, cookie, "native Google login"+formatLoginNote(note))
	if err != nil {
		return 0, err
	}
	markAccountResult(id, true, "")
	bindAccountProxy(id, validation.ProxyID)
	return id, nil
}

func googleLoginProxyFallbackWarning(preferredProxyID, selectedProxyID int64) string {
	selected := "direct connection"
	if selectedProxyID > 0 {
		selected = fmt.Sprintf("proxy #%d", selectedProxyID)
	}
	return fmt.Sprintf("preferred proxy #%d was unavailable; validation used %s", preferredProxyID, selected)
}

func googleLoginNetworkWarning() string {
	if len(listProxies()) == 0 {
		return ""
	}
	return "the browser signs in directly, while backend validation/API requests may use the configured proxy pool"
}

func combineGoogleLoginWarnings(first, second string) string {
	first = strings.TrimSpace(first)
	second = strings.TrimSpace(second)
	switch {
	case first == "":
		return second
	case second == "":
		return first
	default:
		return first + "; " + second
	}
}

func formatLoginNote(note string) string {
	if strings.TrimSpace(note) == "" {
		return ""
	}
	return ": " + strings.TrimSpace(note)
}
