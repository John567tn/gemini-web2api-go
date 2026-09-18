package app

import (
	"net/http/httptest"
	"testing"
)

func TestNativeGoogleLoginIsLoopbackOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote string
		local  bool
	}{
		{name: "ipv4 loopback", remote: "127.0.0.1:8083", local: true},
		{name: "ipv6 loopback", remote: "[::1]:8083", local: true},
		{name: "lan", remote: "192.168.1.10:4567", local: false},
		{name: "invalid remote", remote: "not-an-address", local: false},
		{name: "test adapter without remote", remote: "", local: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/admin/api/google-login/start", nil)
			r.RemoteAddr = tc.remote
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

func containsCookieName(cookie, name string) bool {
	for _, pair := range splitCookiePairs(cookie) {
		if pair[0] == name {
			return true
		}
	}
	return false
}
