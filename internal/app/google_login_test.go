package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeGoogleLoginIsLoopbackOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote string
		host   string
		origin string
		fetch  string
		local  bool
	}{
		{name: "localhost same-origin", remote: "127.0.0.1:8083", host: "localhost:8083", origin: "http://localhost:8083", local: true},
		{name: "ipv4 same-origin", remote: "127.0.0.1:8083", host: "127.0.0.1:8083", origin: "http://127.0.0.1:8083", local: true},
		{name: "ipv6 same-origin", remote: "[::1]:8083", host: "[::1]:8083", origin: "http://[::1]:8083", local: true},
		{name: "https same-authority", remote: "127.0.0.1:8443", host: "127.0.0.1:8443", origin: "https://127.0.0.1:8443", local: true},
		{name: "evil origin", remote: "127.0.0.1:8083", host: "localhost:8083", origin: "https://evil.example", local: false},
		{name: "null origin", remote: "127.0.0.1:8083", host: "localhost:8083", origin: "null", local: false},
		{name: "localhost different port", remote: "127.0.0.1:8083", host: "localhost:8083", origin: "http://localhost:9000", local: false},
		{name: "localhost versus ipv4", remote: "127.0.0.1:8083", host: "127.0.0.1:8083", origin: "http://localhost:8083", local: false},
		{name: "ftp origin", remote: "127.0.0.1:8083", host: "localhost:8083", origin: "ftp://localhost:8083", local: false},
		{name: "public host via loopback proxy", remote: "127.0.0.1:8083", host: "public.example", origin: "", local: false},
		{name: "cross-site fetch", remote: "127.0.0.1:8083", host: "localhost:8083", fetch: "cross-site", local: false},
		{name: "external remote", remote: "192.168.1.10:4567", host: "localhost:8083", origin: "http://localhost:8083", local: false},
		{name: "local curl without origin", remote: "127.0.0.1:8083", host: "localhost:8083", local: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://"+tc.host+"/admin/api/google-login/start", nil)
			r.RemoteAddr = tc.remote
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.fetch != "" {
				r.Header.Set("Sec-Fetch-Site", tc.fetch)
			}
			if got := isLocalAdminRequest(r); got != tc.local {
				t.Fatalf("isLocalAdminRequest(%q)=%v, want %v", tc.remote, got, tc.local)
			}
		})
	}
}

func TestBrowserCookieHeaderFiltersUnrelatedDomains(t *testing.T) {
	cookie, ok := browserCookiesToHeader([]browserCookie{
		{Name: "SAPISID", Value: "sapisid", Domain: ".google.com", Path: "/"},
		{Name: "__Secure-1PSID", Value: "psid", Domain: ".google.com", Path: "/"},
		{Name: "__Secure-1PSIDTS", Value: "psidts", Domain: "gemini.google.com", Path: "/"},
		{Name: "OTHER", Value: "ignore", Domain: "example.com", Path: "/"},
	})
	if !ok || cookie == "" {
		t.Fatalf("valid Gemini cookie set was rejected: %q", cookie)
	}
	if containsCookieName(cookie, "OTHER") {
		t.Fatalf("unrelated domain cookie leaked into Gemini header: %q", cookie)
	}
}

func TestNativeGoogleLoginRejectsForwardingHeaders(t *testing.T) {
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
		t.Run(header, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://localhost:8083/admin/api/google-login/start", nil)
			r.RemoteAddr = "127.0.0.1:8083"
			r.Header.Set(header, "remote.example")
			if isLocalAdminRequest(r) {
				t.Fatalf("forwarding header %s should fail closed", header)
			}
		})
	}
}

func containsCookieName(cookie, name string) bool {
	for _, pair := range splitCookiePairs(cookie) {
		if pair[0] == name {
			return true
		}
	}
	return false
}

func TestGoogleBrowserCommandArgsAvoidAutomationSignal(t *testing.T) {
	args := googleBrowserCommandArgs(filepath.Join("data", "browser-profiles", "p"), 4567)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "enable-automation") {
		t.Fatalf("browser command must not add --enable-automation: %v", args)
	}
	if !strings.Contains(joined, "--remote-debugging-address=127.0.0.1") {
		t.Fatalf("browser command is not loopback-bound: %v", args)
	}
	if !strings.Contains(joined, "--remote-debugging-port=4567") || strings.Contains(joined, "remote-debugging-port=0") {
		t.Fatalf("browser command must use a non-zero ephemeral port: %v", args)
	}
}

func TestCDPReadinessDelayedEndpointEventuallySucceeds(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"webSocketDebuggerUrl":"ws://127.0.0.1:4567/devtools/browser/test"}`))
	}))
	defer server.Close()
	wsURL, err := waitForCDPWebSocketURLWith(context.Background(), server.URL, nil, testCDPHTTPClient(), time.Second, 5*time.Millisecond)
	if err != nil || wsURL == "" || hits.Load() < 3 {
		t.Fatalf("delayed CDP readiness failed: ws=%q hits=%d err=%v", wsURL, hits.Load(), err)
	}
}

func TestCDPReadinessProcessExitFailsImmediately(t *testing.T) {
	done := make(chan error, 1)
	done <- errors.New("browser exited")
	started := time.Now()
	_, err := waitForCDPWebSocketURLWith(context.Background(), "http://127.0.0.1:1", done, testCDPHTTPClient(), 10*time.Second, 5*time.Millisecond)
	if err == nil || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("process exit was not handled immediately: elapsed=%s err=%v", time.Since(started), err)
	}
}

func TestCDPReadinessContextExitFailsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err := waitForCDPWebSocketURLWith(ctx, "http://127.0.0.1:1", nil, testCDPHTTPClient(), 10*time.Second, 5*time.Millisecond)
	if err == nil || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("context exit was not handled immediately: elapsed=%s err=%v", time.Since(started), err)
	}
}

func TestCDPReadinessTimeoutAndMalformedResponse(t *testing.T) {
	for _, body := range []string{"not-json", `{"webSocketDebuggerUrl":""}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		started := time.Now()
		_, err := waitForCDPWebSocketURLWith(context.Background(), server.URL, nil, testCDPHTTPClient(), 60*time.Millisecond, 5*time.Millisecond)
		server.Close()
		if err == nil || time.Since(started) < 50*time.Millisecond {
			t.Fatalf("malformed endpoint did not retry until timeout: body=%q elapsed=%s err=%v", body, time.Since(started), err)
		}
	}
}

func TestCDPReadinessEndpointNeverAppearsTimesOut(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	started := time.Now()
	_, err := waitForCDPWebSocketURLWith(context.Background(), server.URL, nil, testCDPHTTPClient(), 60*time.Millisecond, 5*time.Millisecond)
	if err == nil || time.Since(started) < 50*time.Millisecond {
		t.Fatalf("missing endpoint did not retry until timeout: elapsed=%s err=%v", time.Since(started), err)
	}
}

func TestCDPReadinessValidWebSocketURLSucceeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"webSocketDebuggerUrl":"ws://127.0.0.1:4567/devtools/browser/valid"}`))
	}))
	defer server.Close()
	wsURL, err := waitForCDPWebSocketURLWith(context.Background(), server.URL, nil, testCDPHTTPClient(), time.Second, 5*time.Millisecond)
	if err != nil || wsURL != "ws://127.0.0.1:4567/devtools/browser/valid" {
		t.Fatalf("valid CDP readiness failed: ws=%q err=%v", wsURL, err)
	}
}

func testCDPHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil}}
}

func TestCleanupOrphanGoogleBrowserProfiles(t *testing.T) {
	root := t.TempDir()
	oldProfile := filepath.Join(root, "123e4567-e89b-12d3-a456-426614174000")
	if err := os.MkdirAll(oldProfile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldProfile, googleLoginProfileMarker), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "user-profile")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * googleLoginOrphanAge)
	if err := os.Chtimes(oldProfile, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(foreign, old, old); err != nil {
		t.Fatal(err)
	}
	if got := cleanupOrphanGoogleBrowserProfiles(root, time.Now()); got != 1 {
		t.Fatalf("cleanup removed %d profiles, want 1", got)
	}
	if _, err := os.Stat(oldProfile); !os.IsNotExist(err) {
		t.Fatalf("old marked profile still exists: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("unmarked profile was removed: %v", err)
	}
}

func TestNativeLoginStateMachineCancel(t *testing.T) {
	withFastGoogleLoginTimers(t)
	fake := newFakeLoginBrowser()
	ctx, cancel := context.WithCancel(context.Background())
	s := startMockGoogleLogin(t, ctx, cancel, fake, 0, func(googleSessionValidationRequest) (googleSessionValidation, error) {
		return googleSessionValidation{}, errors.New("not reached")
	})
	waitForGoogleLoginState(t, s, googleLoginWaiting)
	s.cancelSession()
	waitForGoogleLoginState(t, s, googleLoginCanceled)
	waitForProfileGone(t, s.profileDir)
	if fake.closeCount.Load() != 1 {
		t.Fatalf("cancel closed browser %d times, want 1", fake.closeCount.Load())
	}
}

func TestNativeLoginStateMachineTTLExpiry(t *testing.T) {
	withFastGoogleLoginTimers(t)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	fake := newFakeLoginBrowser()
	s := startMockGoogleLogin(t, ctx, cancel, fake, 0, func(googleSessionValidationRequest) (googleSessionValidation, error) {
		return googleSessionValidation{}, errors.New("keep waiting")
	})
	waitForGoogleLoginState(t, s, googleLoginExpired)
	waitForProfileGone(t, s.profileDir)
	if fake.closeCount.Load() != 1 {
		t.Fatalf("expiry closed browser %d times, want 1", fake.closeCount.Load())
	}
}

func TestNativeLoginStateMachineBrowserClosesBeforeLogin(t *testing.T) {
	withFastGoogleLoginTimers(t)
	fake := newFakeLoginBrowser()
	fake.cookieErr = errors.New("browser closed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startMockGoogleLogin(t, ctx, cancel, fake, 0, func(googleSessionValidationRequest) (googleSessionValidation, error) {
		return googleSessionValidation{}, errors.New("not reached")
	})
	waitForGoogleLoginState(t, s, googleLoginFailed)
	waitForProfileGone(t, s.profileDir)
}

func TestNativeLoginTransientValidatorFailureThenSuccess(t *testing.T) {
	withFastGoogleLoginTimers(t)
	fake := newFakeLoginBrowser()
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startMockGoogleLogin(t, ctx, cancel, fake, 0, func(googleSessionValidationRequest) (googleSessionValidation, error) {
		if calls.Add(1) == 1 {
			return googleSessionValidation{}, errors.New("transient")
		}
		return googleSessionValidation{}, nil
	})
	waitForGoogleLoginState(t, s, googleLoginSucceeded)
	if calls.Load() < 2 {
		t.Fatalf("validator was called %d times, want transient retry", calls.Load())
	}
	waitForProfileGone(t, s.profileDir)
	if s.accountID > 0 {
		_ = accountDelete(s.accountID)
	}
}

func TestNativeLoginPermanentValidatorFailureUntilExpiry(t *testing.T) {
	withFastGoogleLoginTimers(t)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	fake := newFakeLoginBrowser()
	s := startMockGoogleLogin(t, ctx, cancel, fake, 0, func(googleSessionValidationRequest) (googleSessionValidation, error) {
		return googleSessionValidation{}, errors.New("permanent")
	})
	waitForGoogleLoginState(t, s, googleLoginExpired)
	waitForProfileGone(t, s.profileDir)
	if s.accountID != 0 {
		t.Fatalf("permanent validation unexpectedly created account %d", s.accountID)
	}
}

func TestNativeReloginPreservesAccountIDAndProxy(t *testing.T) {
	withFastGoogleLoginTimers(t)
	oldCookie := "SAPISID=old; __Secure-1PSID=old-psid; __Secure-1PSIDTS=old-ts"
	id, err := accountAdd("relogin", oldCookie, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	if _, err := getDB().Exec(`UPDATE accounts SET proxy_id=7 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	fake := newFakeLoginBrowser()
	var gotReq googleSessionValidationRequest
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startMockGoogleLogin(t, ctx, cancel, fake, id, func(req googleSessionValidationRequest) (googleSessionValidation, error) {
		gotReq = req
		return googleSessionValidation{ProxyID: 7}, nil
	})
	waitForGoogleLoginState(t, s, googleLoginSucceeded)
	if gotReq.TargetAccountID != id || gotReq.PreferredProxyID != 7 {
		t.Fatalf("validator did not receive target/proxy affinity: %+v", gotReq)
	}
	after := accountByID(id)
	if after == nil || after.ID != id || after.ProxyID != 7 {
		t.Fatalf("re-login changed account identity/affinity: %+v", after)
	}
	if s.accountID != id {
		t.Fatalf("re-login returned account %d, want %d", s.accountID, id)
	}
}

func TestNativeReloginProxyFallbackIsExplicit(t *testing.T) {
	withFastGoogleLoginTimers(t)
	id, err := accountAdd("fallback", "SAPISID=old2; __Secure-1PSID=old-psid2; __Secure-1PSIDTS=old-ts2", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	if _, err := getDB().Exec(`UPDATE accounts SET proxy_id=7 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	fake := newFakeLoginBrowser()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startMockGoogleLogin(t, ctx, cancel, fake, id, func(req googleSessionValidationRequest) (googleSessionValidation, error) {
		return googleSessionValidation{ProxyID: 8, ProxyFallback: true, Warning: googleLoginProxyFallbackWarning(req.PreferredProxyID, 8)}, nil
	})
	waitForGoogleLoginState(t, s, googleLoginSucceeded)
	if !strings.Contains(s.view()["warning"].(string), "preferred proxy #7") {
		t.Fatalf("proxy fallback warning missing: %+v", s.view())
	}
	if after := accountByID(id); after == nil || after.ProxyID != 8 {
		t.Fatalf("fallback proxy was not recorded explicitly: %+v", after)
	}
}

func withFastGoogleLoginTimers(t *testing.T) {
	t.Helper()
	oldPoll := googleLoginPollInterval
	oldRetry := googleLoginValidationRetryWindow
	googleLoginPollInterval = 3 * time.Millisecond
	googleLoginValidationRetryWindow = 6 * time.Millisecond
	t.Cleanup(func() {
		googleLoginPollInterval = oldPoll
		googleLoginValidationRetryWindow = oldRetry
	})
}

func newFakeLoginBrowser() *fakeGoogleLoginBrowser {
	return &fakeGoogleLoginBrowser{cookies: []browserCookie{
		{Name: "SAPISID", Value: "mock-sapisid", Domain: ".google.com", Path: "/"},
		{Name: "__Secure-1PSID", Value: "mock-psid", Domain: ".google.com", Path: "/"},
		{Name: "__Secure-1PSIDTS", Value: "mock-psidts", Domain: ".google.com", Path: "/"},
	}}
}

func startMockGoogleLogin(t *testing.T, ctx context.Context, cancel context.CancelFunc, fake *fakeGoogleLoginBrowser, targetID int64, validator googleSessionValidator) *googleLoginSession {
	t.Helper()
	manager := newGoogleLoginManager(
		func(context.Context, string, string) (googleLoginBrowser, error) { return fake, nil },
		validator,
	)
	profileDir := filepath.Join(t.TempDir(), "profile")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &googleLoginSession{
		manager:    manager,
		id:         "mock-" + time.Now().Format("150405.000000000"),
		state:      googleLoginLaunching,
		profileDir: profileDir,
		accountID:  targetID,
		startedAt:  time.Now(),
		expiresAt:  time.Now().Add(time.Minute),
		cancel:     cancel,
	}
	manager.sessions[s.id] = s
	go s.run(ctx, "mock-browser")
	return s
}

func waitForGoogleLoginState(t *testing.T, s *googleLoginSession, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.view()["state"] == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("login state=%v, want %s", s.view()["state"], want)
}

func waitForProfileGone(t *testing.T, profileDir string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(profileDir); os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("browser profile still exists: %s", profileDir)
}
