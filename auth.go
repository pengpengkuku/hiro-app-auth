// Package appauth verifies Hiro application authorization on each protected request.
package appauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	ErrUnauthenticated = errors.New("appauth: authentication required")
	ErrForbidden       = errors.New("appauth: application permission required")
	ErrUnavailable     = errors.New("appauth: identity service unavailable")
	ErrConfiguration   = errors.New("appauth: invalid configuration")
	ErrCookieTooLarge  = errors.New("appauth: authorization cookie exceeds limit")
)

// Principal identifies the current user. Applications must still enforce resource ownership.
type Principal struct {
	Issuer  string
	Subject string
}

// Config contains trusted deployment values, never values taken from a request.
// CookieKeyFile contains exactly 32 random bytes. ClientSecretFile contains the
// confidential client secret, optionally followed by a CR/LF newline.
type Config struct {
	Issuer           string
	ClientID         string
	ClientSecretFile string
	CookieKeyFile    string
	PublicOrigin     string
	HTTPClient       *http.Client
}

type Client struct {
	issuer, clientID, secret, introspection, revocation, cookieName string
	secure                                                          bool
	http                                                            *http.Client
	aead                                                            cipher.AEAD
	binding                                                         []byte
}

type discovery struct {
	Issuer        string `json:"issuer"`
	Introspection string `json:"introspection_endpoint"`
	Revocation    string `json:"revocation_endpoint"`
}

type authorization struct {
	Active   bool   `json:"active"`
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
	Scope    string `json:"scope"`
	Issuer   string `json:"iss"`
}

type session struct {
	Token   string `json:"token"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Expires int64  `json:"expires"`
}

const maxBody = 32 << 10
const maxCookie = 4096

// New loads runtime secrets and fetches discovery from the configured issuer.
// Discovery and authorization requests are bounded to at most ten seconds.
func New(config Config) (*Client, error) {
	issuer, err := trustedURL(config.Issuer)
	if err != nil || config.ClientID == "" || len(config.ClientID) > 256 || strings.ContainsAny(config.ClientID, "\x00\r\n") {
		return nil, ErrConfiguration
	}
	origin, err := trustedURL(config.PublicOrigin)
	if err != nil || (origin.Path != "" && origin.Path != "/") {
		return nil, ErrConfiguration
	}
	secret, err := readSecret(config.ClientSecretFile, 4096)
	if err != nil {
		return nil, ErrConfiguration
	}
	secret = bytes.TrimRight(secret, "\r\n")
	if len(secret) == 0 || bytes.ContainsAny(secret, "\r\n") {
		return nil, ErrConfiguration
	}
	key, err := readSecret(config.CookieKeyFile, 32)
	if err != nil || len(key) != 32 {
		return nil, ErrConfiguration
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrConfiguration
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrConfiguration
	}
	transport := http.Client{Timeout: 5 * time.Second}
	if config.HTTPClient != nil {
		transport = *config.HTTPClient
	}
	if transport.Timeout <= 0 || transport.Timeout > 10*time.Second {
		transport.Timeout = 10 * time.Second
	}
	transport.Jar = nil
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	digest := sha256.Sum256([]byte(config.ClientID))
	cookieName := "hiro-app-" + hex.EncodeToString(digest[:16])
	if origin.Scheme == "https" {
		cookieName = "__Host-" + cookieName
	}
	c := &Client{issuer: config.Issuer, clientID: config.ClientID, secret: string(secret), secure: origin.Scheme == "https", cookieName: cookieName, http: &transport, aead: aead, binding: []byte(config.Issuer + "\x00" + config.ClientID)}
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(config.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, ErrConfiguration
	}
	var metadata discovery
	if err := c.exchange(request, &metadata); err != nil {
		return nil, err
	}
	if metadata.Issuer != config.Issuer {
		return nil, ErrConfiguration
	}
	for _, endpoint := range []string{metadata.Introspection, metadata.Revocation} {
		parsed, err := trustedURL(endpoint)
		if err != nil || parsed.Scheme != issuer.Scheme || parsed.Host != issuer.Host {
			return nil, ErrConfiguration
		}
	}
	c.introspection, c.revocation = metadata.Introspection, metadata.Revocation
	return c, nil
}

// BindSession is called only by the application's trusted OAuth callback after
// its normal state, nonce, PKCE and code checks. It validates the opaque token
// before returning a cookie for the response.
func (c *Client) BindSession(ctx context.Context, accessToken string) (Principal, *http.Cookie, error) {
	value, err := c.inspect(ctx, accessToken)
	if err != nil {
		return Principal{}, nil, err
	}
	stored := session{accessToken, c.issuer, value.Subject, value.Expires}
	plaintext, err := json.Marshal(stored)
	if err != nil {
		return Principal{}, nil, ErrUnauthenticated
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Principal{}, nil, ErrUnavailable
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, c.binding)
	cookie := c.cookie(base64.RawURLEncoding.EncodeToString(sealed), value.Expires)
	if len(cookie.String()) > maxCookie {
		return Principal{}, nil, ErrCookieTooLarge
	}
	return Principal{c.issuer, value.Subject}, cookie, nil
}

// RequireUser decrypts the app cookie and performs fresh online introspection.
// Authorization headers and client-supplied identity headers are not trusted.
func (c *Client) RequireUser(ctx context.Context, headers http.Header) (Principal, error) {
	stored, err := c.readSession(headers)
	if err != nil {
		return Principal{}, err
	}
	value, err := c.inspect(ctx, stored.Token)
	if err != nil {
		return Principal{}, err
	}
	if value.Subject != stored.Subject || value.Expires != stored.Expires {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{c.issuer, value.Subject}, nil
}

// Logout always returns a clearing cookie, including when revocation cannot be
// confirmed. The caller must write it even when err is non-nil.
func (c *Client) Logout(ctx context.Context, headers http.Header) (*http.Cookie, error) {
	cleared := c.cookie("", 1)
	cleared.MaxAge = -1
	stored, err := c.readSession(headers)
	if err != nil {
		return cleared, err
	}
	request, err := c.form(ctx, c.revocation, stored.Token)
	if err != nil {
		return cleared, err
	}
	return cleared, c.exchange(request, nil)
}

func (c *Client) inspect(ctx context.Context, token string) (authorization, error) {
	var value authorization
	if token == "" || len(token) > maxBody || strings.ContainsAny(token, "\x00\r\n") {
		return value, ErrUnauthenticated
	}
	request, err := c.form(ctx, c.introspection, token)
	if err != nil {
		return value, err
	}
	if err := c.exchange(request, &value); err != nil {
		return value, err
	}
	if !value.Active || value.Subject == "" || value.ClientID != c.clientID || value.Audience != "urn:hiro:app:"+c.clientID || value.Expires <= time.Now().Unix() || (value.Issuer != "" && value.Issuer != c.issuer) {
		return value, ErrUnauthenticated
	}
	scopes := strings.Fields(value.Scope)
	hasOpenID, hasApp := false, false
	for _, scope := range scopes {
		hasOpenID = hasOpenID || scope == "openid"
		hasApp = hasApp || scope == "hiro.app"
	}
	if !hasOpenID || !hasApp {
		return value, ErrForbidden
	}
	return value, nil
}

func (c *Client) form(ctx context.Context, endpoint, token string) (*http.Request, error) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// OAuth client_secret_basic requires form-encoding each credential before Basic.
	request.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.secret))
	return request, nil
}

func (c *Client) exchange(request *http.Request, target any) error {
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return ErrUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	if target == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return ErrUnavailable
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	return nil
}

func (c *Client) cookie(value string, expires int64) *http.Cookie {
	return &http.Cookie{Name: c.cookieName, Value: value, Path: "/", Expires: time.Unix(expires, 0).UTC(), Secure: c.secure, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func (c *Client) readSession(headers http.Header) (session, error) {
	var stored session
	request := http.Request{Header: headers}
	var value string
	count := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == c.cookieName {
			value = cookie.Value
			count++
		}
	}
	if count != 1 || len(value) > maxCookie {
		return stored, ErrUnauthenticated
	}
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	size := c.aead.NonceSize()
	if err != nil || len(sealed) < size+c.aead.Overhead() {
		return stored, ErrUnauthenticated
	}
	plaintext, err := c.aead.Open(nil, sealed[:size], sealed[size:], c.binding)
	if err != nil || json.Unmarshal(plaintext, &stored) != nil {
		return stored, ErrUnauthenticated
	}
	if stored.Issuer != c.issuer || stored.Subject == "" || stored.Expires <= time.Now().Unix() {
		return stored, ErrUnauthenticated
	}
	return stored, nil
}

func trustedURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, ErrConfiguration
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	ip := net.ParseIP(parsed.Hostname())
	if parsed.Scheme != "http" || ip == nil || !ip.IsLoopback() {
		return nil, ErrConfiguration
	}
	return parsed, nil
}

func readSecret(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(value)) > limit {
		return nil, ErrConfiguration
	}
	return value, nil
}
