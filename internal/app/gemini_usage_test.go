package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func usageRPCFixture(t *testing.T, payload interface{}, lengthPrefixed bool) []byte {
	t.Helper()
	inner, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := []interface{}{[]interface{}{"wrb.fr", geminiUsageRPC, string(inner), nil}}
	frameJSON, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if lengthPrefixed {
		return []byte(")]}'\n" + "\n" + itoaForTest(len(string(frameJSON))) + "\n" + string(frameJSON))
	}
	return append([]byte(")]}'\n"), frameJSON...)
}

func itoaForTest(n int) string {
	return fmtInt(n)
}

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func schemaAWindow(typ int, used float64, reset float64) []interface{} {
	return []interface{}{"window", used, float64(typ), []interface{}{[]interface{}{reset}}}
}

func schemaBWindow(typ int, used, remaining interface{}, reset float64) []interface{} {
	return []interface{}{"x", "x", "x", "x", float64(typ), []interface{}{reset, float64(0)}, used, remaining}
}

func usagePayload(windows ...[]interface{}) interface{} {
	return []interface{}{"metadata", windows}
}

func TestParseGeminiUsageSchemaAAndReversedOrder(t *testing.T) {
	raw := usageRPCFixture(t, usagePayload(
		schemaAWindow(2, 0.032, 1710000200),
		schemaAWindow(1, 0.125, 1710000100),
	), true)
	windows, err := parseGeminiUsageRPC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !closeUsagePercent(windows[1].UsedPercent, 12.5) || !closeUsagePercent(windows[1].RemainingPercent, 87.5) {
		t.Fatalf("five-hour window parsed incorrectly: %+v", windows[1])
	}
	if !closeUsagePercent(windows[2].UsedPercent, 3.2) || !closeUsagePercent(windows[2].RemainingPercent, 96.8) {
		t.Fatalf("weekly window parsed incorrectly: %+v", windows[2])
	}
	if windows[1].ResetAt.Unix() != 1710000100 || windows[2].ResetAt.Unix() != 1710000200 {
		t.Fatalf("reset times parsed incorrectly: %+v", windows)
	}
}

func TestParseGeminiUsageSchemaBAndWindowOrder(t *testing.T) {
	cases := []struct {
		name       string
		firstType  int
		secondType int
	}{
		{name: "weekly first", firstType: 2, secondType: 1},
		{name: "five hour first", firstType: 1, secondType: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var first, second []interface{}
			if tc.firstType == 1 {
				first = schemaBWindow(1, 12.5, nil, 1710000100)
				second = schemaBWindow(2, nil, 96.8, 1710000200)
			} else {
				first = schemaBWindow(2, nil, 96.8, 1710000200)
				second = schemaBWindow(1, 12.5, nil, 1710000100)
			}
			windows, err := parseGeminiUsageRPC(usageRPCFixture(t, usagePayload(first, second), false))
			if err != nil {
				t.Fatal(err)
			}
			if !closeUsagePercent(windows[1].UsedPercent, 12.5) || !closeUsagePercent(windows[1].RemainingPercent, 87.5) {
				t.Fatalf("five-hour complement failed: %+v", windows[1])
			}
			if !closeUsagePercent(windows[2].UsedPercent, 3.2) || !closeUsagePercent(windows[2].RemainingPercent, 96.8) {
				t.Fatalf("weekly complement failed: %+v", windows[2])
			}
		})
	}
}

func closeUsagePercent(got, want float64) bool {
	return got-want < 0.000001 && want-got < 0.000001
}

func TestParseGeminiUsageExhaustedAndFullRemaining(t *testing.T) {
	windows, err := parseGeminiUsageRPC(usageRPCFixture(t, usagePayload(
		schemaBWindow(1, 100.0, 0.0, 1710000100),
		schemaBWindow(2, 0.0, 100.0, 1710000200),
	), false))
	if err != nil {
		t.Fatal(err)
	}
	if windows[1].RemainingPercent != 0 || windows[1].UsedPercent != 100 {
		t.Fatalf("exhausted window changed: %+v", windows[1])
	}
	if windows[2].RemainingPercent != 100 || windows[2].UsedPercent != 0 {
		t.Fatalf("full remaining window changed: %+v", windows[2])
	}
}

func TestParseGeminiUsageMissingMetricDoesNotBecomeZero(t *testing.T) {
	five := []interface{}{"x", "x", "x", "x", float64(1), []interface{}{1710000100.0}}
	weekly := schemaBWindow(2, nil, 96.8, 1710000200)
	windows, err := parseGeminiUsageRPC(usageRPCFixture(t, usagePayload(five, weekly), false))
	if err == nil || windows != nil || !strings.Contains(err.Error(), "neither used nor remaining") {
		t.Fatalf("missing usage metric must be an error, got windows=%v err=%v", windows, err)
	}
}

func TestParseGeminiUsageRejectsUnknownOrMalformedResponses(t *testing.T) {
	unknown := usageRPCFixture(t, usagePayload(
		schemaAWindow(9, 0.1, 1710000100),
		schemaAWindow(1, 0.1, 1710000100),
	), false)
	if _, err := parseGeminiUsageRPC(unknown); err == nil || !strings.Contains(err.Error(), "unknown usage window type") {
		t.Fatalf("unknown window type should be a parse error, got %v", err)
	}
	if _, err := parseGeminiUsageRPC([]byte(")]}'\nnot-json")); err == nil {
		t.Fatal("malformed RPC envelope should fail")
	}
	if _, err := extractGeminiUsagePageTokens([]byte(`{"cfb2h":"build"}`)); err == nil || !isGeminiUsageAuthFailure(err) {
		t.Fatalf("missing SNlM0e should be an auth/session error, got %v", err)
	}
	tokens, err := extractGeminiUsagePageTokens([]byte(`{"SNlM0e":"token-value-12345","cfb2h":"boq_assistant-bard-web-server_20260805.16_p0","FdrFJe":"sid-123"}`))
	if err != nil || tokens.SNlM0e == "" || tokens.Build == "" || tokens.FdrFJe != "sid-123" {
		t.Fatalf("usage page token extraction failed: %+v err=%v", tokens, err)
	}
}

func TestGeminiUsageHTTP401And403AreSessionErrors(t *testing.T) {
	for _, status := range []int{401, 403} {
		err := geminiUsageHTTPError(status)
		var usageErr *geminiUsageError
		if !errors.As(err, &usageErr) || usageErr.Code != "auth_session_expired" || usageErr.HTTPStatus != status {
			t.Fatalf("HTTP %d was not classified as session expiry: %#v", status, err)
		}
	}
}

func TestGeminiUsageCacheIsolatedByAccount(t *testing.T) {
	oldFetcher := geminiUsageFetcher
	oldCache := geminiUsageCache
	t.Cleanup(func() {
		geminiUsageFetcher = oldFetcher
		geminiUsageCache = oldCache
	})
	geminiUsageCache = map[int64]usageCacheEntry{}
	geminiUsageFetcher = func(a CookieAccount) (*geminiUsageSnapshot, error) {
		return &geminiUsageSnapshot{
			AccountID: a.ID, AccountLabel: a.Label,
			Windows:   map[int]geminiUsageWindow{1: {UsedPercent: float64(a.ID), RemainingPercent: 100 - float64(a.ID), ResetAt: time.Unix(1710000100+a.ID, 0)}},
			FetchedAt: time.Now().UTC(),
		}, nil
	}
	one, err := cachedGeminiUsage(CookieAccount{ID: 1, Label: "A"}, false)
	if err != nil {
		t.Fatal(err)
	}
	two, err := cachedGeminiUsage(CookieAccount{ID: 2, Label: "B"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if one.AccountID != 1 || two.AccountID != 2 || one.Windows[1].UsedPercent == two.Windows[1].UsedPercent {
		t.Fatalf("usage cache crossed account boundary: one=%+v two=%+v", one, two)
	}
}

type fakeGoogleLoginBrowser struct {
	cookies []browserCookie
	closed  atomic.Bool
}

func (b *fakeGoogleLoginBrowser) Navigate(context.Context, string) error { return nil }
func (b *fakeGoogleLoginBrowser) Cookies(context.Context) ([]browserCookie, error) {
	return b.cookies, nil
}
func (b *fakeGoogleLoginBrowser) Close() error { b.closed.Store(true); return nil }

func TestGoogleLoginStateMachineUsesMockBrowser(t *testing.T) {
	oldPoll := googleLoginPollInterval
	googleLoginPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { googleLoginPollInterval = oldPoll })

	dir := t.TempDir()
	fake := &fakeGoogleLoginBrowser{cookies: []browserCookie{
		{Name: "SAPISID", Value: "sapisid-test", Domain: ".google.com", Path: "/"},
		{Name: "__Secure-1PSID", Value: "psid-test", Domain: ".google.com", Path: "/"},
		{Name: "__Secure-1PSIDTS", Value: "psidts-test", Domain: ".google.com", Path: "/"},
	}}
	m := newGoogleLoginManager(
		func(context.Context, string, string) (googleLoginBrowser, error) { return fake, nil },
		func(cookie string) (googleSessionValidation, error) {
			if !hasNativeGoogleLoginCookies(cookie) {
				return googleSessionValidation{}, errors.New("missing cookies")
			}
			return googleSessionValidation{}, nil
		},
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := &googleLoginSession{
		manager: m, id: "mock-session", state: googleLoginLaunching,
		profileDir: filepath.Join(dir, "profile"), startedAt: time.Now(), expiresAt: time.Now().Add(time.Second),
	}
	_ = os.MkdirAll(s.profileDir, 0o700)
	m.sessions[s.id] = s
	go s.run(ctx, "mock")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		view := s.view()
		if view["state"] == googleLoginSucceeded {
			if view["account_id"].(int64) <= 0 || !fake.closed.Load() {
				t.Fatalf("mock login succeeded without account/browser cleanup: %+v closed=%v", view, fake.closed.Load())
			}
			_ = accountDelete(view["account_id"].(int64))
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("mock login did not complete: %+v", s.view())
}
