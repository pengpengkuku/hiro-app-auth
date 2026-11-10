package appauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	appauth "github.com/pengpengkuku/hiro-app-auth"
)

func TestAuthorizationJourney(t *testing.T) {
	const clientID = "notes-a"
	const secret = "synthetic-test-secret"
	var mu sync.Mutex
	state := "valid"
	expires := time.Now().Add(time.Hour).Unix()
	checks := 0
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oidc/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "introspection_endpoint": issuer + "/inspect", "revocation_endpoint": issuer + "/revoke"})
			return
		}
		user, password, ok := r.BasicAuth()
		if !ok || (user != url.QueryEscape(clientID) && user != "notes-b") || password != url.QueryEscape(secret) || r.Method != http.MethodPost {
			t.Error("missing confidential client authentication")
			w.WriteHeader(401)
			return
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("token") == "" || r.Form.Get("token_type_hint") != "access_token" {
			t.Error("invalid native token request")
			w.WriteHeader(400)
			return
		}
		if state == "unavailable" {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/oidc/revoke" {
			state = "revoked"
			return
		}
		if r.URL.Path != "/oidc/inspect" {
			w.WriteHeader(404)
			return
		}
		checks++
		value := map[string]any{"active": state != "revoked", "sub": "user-a", "client_id": user, "aud": "urn:hiro:app:" + user, "exp": expires, "scope": "openid hiro.app"}
		switch state {
		case "wrong-sub":
			value["sub"] = "user-b"
		case "wrong-client":
			value["client_id"] = "notes-b"
		case "wrong-audience":
			value["aud"] = "urn:hiro:app:notes-b"
		case "wrong-issuer":
			value["iss"] = "https://untrusted.invalid/oidc"
		case "expired":
			value["exp"] = time.Now().Add(-time.Second).Unix()
		case "forbidden":
			value["scope"] = "openid"
		case "malformed":
			w.Write([]byte(`{"active":true,"exp":"invalid"}`))
			return
		case "oversized":
			w.Write([]byte(strings.Repeat(" ", 33000)))
			return
		}
		json.NewEncoder(w).Encode(value)
	}))
	defer server.Close()
	issuer = server.URL + "/oidc"
	config := testConfig(t, issuer)
	config.ClientID = clientID
	config.PublicOrigin = "https://notes.example.invalid"
	client, err := appauth.New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	principal, cookie, err := client.BindSession(ctx, "synthetic-opaque-access-token")
	if err != nil {
		t.Fatal(err)
	}
	if principal.Issuer != issuer || principal.Subject != "user-a" {
		t.Fatalf("wrong principal: %#v", principal)
	}
	if cookie.Domain != "" || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Fatal("cookie does not enforce the host-only HTTPS contract")
	}
	if strings.Contains(cookie.Value, "synthetic") || len(cookie.String()) > 4096 {
		t.Fatal("cookie plaintext or excessive size")
	}
	headers := cookieHeaders(cookie)
	principal, err = client.RequireUser(ctx, headers)
	if err != nil || principal.Subject != "user-a" {
		t.Fatalf("read failed: %v", err)
	}
	mu.Lock()
	observedChecks := checks
	mu.Unlock()
	if observedChecks != 2 {
		t.Fatalf("expected callback and protected request to introspect, got %d", observedChecks)
	}
	for _, scenario := range []struct {
		state string
		want  error
	}{
		{"wrong-sub", appauth.ErrUnauthenticated}, {"wrong-client", appauth.ErrUnauthenticated}, {"wrong-audience", appauth.ErrUnauthenticated}, {"wrong-issuer", appauth.ErrUnauthenticated}, {"expired", appauth.ErrUnauthenticated}, {"forbidden", appauth.ErrForbidden}, {"unavailable", appauth.ErrUnavailable}, {"malformed", appauth.ErrUnavailable}, {"oversized", appauth.ErrUnavailable},
	} {
		t.Run(scenario.state, func(t *testing.T) {
			mu.Lock()
			state = scenario.state
			mu.Unlock()
			if _, err := client.RequireUser(ctx, headers); !errors.Is(err, scenario.want) {
				t.Fatalf("got %v, want %v", err, scenario.want)
			}
		})
	}
	mu.Lock()
	state = "valid"
	mu.Unlock()
	tampered := *cookie
	tampered.Value = "A" + cookie.Value[1:]
	if tampered.Value == cookie.Value {
		tampered.Value = "B" + cookie.Value[1:]
	}
	if _, err := client.RequireUser(ctx, cookieHeaders(&tampered)); !errors.Is(err, appauth.ErrUnauthenticated) {
		t.Fatal("tampered cookie accepted")
	}
	duplicate := headers.Clone()
	duplicate.Add("Cookie", cookie.Name+"="+cookie.Value)
	if _, err := client.RequireUser(ctx, duplicate); !errors.Is(err, appauth.ErrUnauthenticated) {
		t.Fatal("ambiguous duplicate cookie accepted")
	}
	otherConfig := config
	otherConfig.ClientID = "notes-b"
	other, err := appauth.New(otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.RequireUser(ctx, headers); !errors.Is(err, appauth.ErrUnauthenticated) {
		t.Fatal("cross-client cookie accepted")
	}
	_, otherCookie, err := other.BindSession(ctx, "synthetic-token-for-other-client")
	if err != nil || otherCookie.Name == cookie.Name {
		t.Fatal("client cookie names must differ")
	}
	renamed := *cookie
	renamed.Name = otherCookie.Name
	if _, err := other.RequireUser(ctx, cookieHeaders(&renamed)); !errors.Is(err, appauth.ErrUnauthenticated) {
		t.Fatal("cross-client ciphertext accepted after renaming")
	}
	mu.Lock()
	state = "valid"
	mu.Unlock()
	cleared, err := client.Logout(ctx, headers)
	if err != nil || cleared.MaxAge != -1 || cleared.Value != "" || cleared.Name != cookie.Name {
		t.Fatalf("logout failed: %v", err)
	}
	if _, err := client.RequireUser(ctx, headers); !errors.Is(err, appauth.ErrUnauthenticated) {
		t.Fatal("revoked token remained authorized")
	}
	mu.Lock()
	state = "unavailable"
	mu.Unlock()
	cleared, err = client.Logout(ctx, headers)
	if !errors.Is(err, appauth.ErrUnavailable) || cleared == nil || cleared.MaxAge != -1 {
		t.Fatal("unconfirmed logout must still clear cookie and expose failure")
	}
	mu.Lock()
	state = "valid"
	mu.Unlock()
	if _, _, err := client.BindSession(ctx, strings.Repeat("x", 4000)); !errors.Is(err, appauth.ErrCookieTooLarge) {
		t.Fatalf("oversized cookie: %v", err)
	}
	server.Close()
	if _, err := client.RequireUser(ctx, headers); !errors.Is(err, appauth.ErrUnavailable) {
		t.Fatal("connection failure did not fail closed")
	}
}

func TestTrustBoundaries(t *testing.T) {
	var server *httptest.Server
	endpoint := ""
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL + "/oidc", "introspection_endpoint": endpoint, "revocation_endpoint": server.URL + "/revoke"})
	}))
	defer server.Close()
	config := testConfig(t, server.URL+"/oidc")
	for _, endpointValue := range []string{"https://other.example.invalid/inspect", "http://localhost/inspect", "http://192.0.2.1/inspect", server.URL + "/inspect?untrusted=true"} {
		endpoint = endpointValue
		if _, err := appauth.New(config); !errors.Is(err, appauth.ErrConfiguration) {
			t.Fatalf("untrusted endpoint %q accepted: %v", endpoint, err)
		}
	}
	endpoint = server.URL + "/inspect"
	config.PublicOrigin = "http://192.0.2.1"
	if _, err := appauth.New(config); !errors.Is(err, appauth.ErrConfiguration) {
		t.Fatal("insecure non-loopback public origin accepted")
	}
	config.PublicOrigin = server.URL
	client, err := appauth.New(config)
	if err != nil || client == nil {
		t.Fatalf("literal loopback must support local development: %v", err)
	}
	config.CookieKeyFile = filepath.Join(t.TempDir(), "missing")
	if _, err := appauth.New(config); !errors.Is(err, appauth.ErrConfiguration) || strings.Contains(err.Error(), config.CookieKeyFile) {
		t.Fatal("missing runtime key must fail without exposing configuration values")
	}
}

func testConfig(t *testing.T, issuer string) appauth.Config {
	t.Helper()
	directory := t.TempDir()
	secret := filepath.Join(directory, "client-secret")
	key := filepath.Join(directory, "cookie-key")
	if err := os.WriteFile(secret, []byte("synthetic-test-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	return appauth.Config{Issuer: issuer, ClientID: "notes-a", ClientSecretFile: secret, CookieKeyFile: key, PublicOrigin: "https://notes.example.invalid"}
}

func cookieHeaders(cookie *http.Cookie) http.Header {
	return http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}
}
