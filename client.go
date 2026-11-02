// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

// Package kasapi is a Go client for the all-inkl.com KAS hosting API. The KAS
// panel is exposed as a SOAP service; this package wraps it in typed services
// over a transport that handles the session handshake, the flood-protection
// delays and the PHP-shaped responses. Standard-library only.
//
// Client.Exec runs any KAS action with raw parameters; the typed services
// are thin wrappers over it.
//
// Errors: a KAS fault is an *APIError; a missing object is ErrNotFound. Errors
// the package creates start with "kasapi: ". Service methods wrap them with
// the operation as context, e.g. "listing domains: kasapi: zone_not_found".
//
// Unofficial: not affiliated with all-inkl.com (Neue Medien Münnich GmbH).
package kasapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	DefaultAPIEndpoint  = "https://kasapi.kasserver.com/soap/KasApi.php"
	DefaultAuthEndpoint = "https://kasapi.kasserver.com/soap/KasAuth.php"

	apiNamespace  = "https://kasserver.com/soap/KasApi.php"
	authNamespace = "https://kasserver.com/soap/KasAuth.php"

	// MaxSessionLifetime is the longest session KAS grants, in seconds.
	MaxSessionLifetime = 30000
)

// APIError is a KAS API error reported as a SOAP fault, e.g.
// "kas_login_incorrect", "flood_protection", "zone_not_found".
type APIError struct {
	Code string
}

func (e *APIError) Error() string { return "kasapi: " + e.Code }

// ErrNotFound is returned by typed services when an object does not exist.
var ErrNotFound = errors.New("kasapi: not found")

// Config configures a Client.
type Config struct {
	Login    string // KAS login, e.g. "w0123456"
	Password string // account or API password
	AuthType AuthType

	// OTP supplies the one-time PIN for 2FA accounts on every session handshake.
	OTP func(ctx context.Context) (string, error)

	// SessionLifetime in seconds, 1-30000; default 1800. The client logs in
	// again shortly before it ends, so a very short lifetime means a handshake
	// on nearly every call.
	SessionLifetime int
	UserAgent       string

	// HTTPClient overrides the default client, which enforces TLS 1.2 or
	// newer, a 60 s timeout, the proxy settings of the environment and does
	// not follow redirects, so credentials never go to another host. A custom
	// client is responsible for all of that itself.
	HTTPClient *http.Client
	// APIEndpoint and AuthEndpoint must use https, except on the loopback
	// interface, where a fake server such as kasapitest may use http.
	APIEndpoint  string
	AuthEndpoint string
}

// Client talks to the KAS SOAP API. It is safe for concurrent use; requests
// are serialized because KAS enforces flood protection between calls. A call
// that waits for its turn stops when its context ends.
type Client struct {
	cfg  Config
	http *http.Client

	// sem is a context-aware mutex: holding its single slot owns the session
	// state below and the right to send the next request.
	sem       chan struct{}
	token     string
	tokenExp  time.Time
	notBefore time.Time // earliest the next request may be sent

	DNS        *DNSService
	Mail       *MailService
	Subdomains *SubdomainService
	Domains    *DomainService
	TLS        *TLSService
	FTP        *FTPService
	Databases  *DatabaseService
	Cronjobs   *CronjobService
	DDNS       *DDNSService

	MailingLists        *MailingListService
	DirectoryProtection *DirectoryProtectionService
	Samba               *SambaService
	Accounts            *AccountService
	Statistics          *StatisticsService
}

// New creates a configured Client.
func New(cfg Config) (*Client, error) {
	if cfg.Login == "" || cfg.Password == "" {
		return nil, errors.New("kasapi: login and password are required")
	}
	switch cfg.AuthType {
	case "":
		cfg.AuthType = AuthSHA1
	case AuthPlain, AuthSHA1:
	default:
		return nil, fmt.Errorf("kasapi: unsupported auth type %q", cfg.AuthType)
	}
	if cfg.SessionLifetime <= 0 {
		cfg.SessionLifetime = 1800
	}
	if cfg.SessionLifetime > MaxSessionLifetime {
		cfg.SessionLifetime = MaxSessionLifetime
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "kasapi-go"
	}
	if cfg.APIEndpoint == "" {
		cfg.APIEndpoint = DefaultAPIEndpoint
	}
	if cfg.AuthEndpoint == "" {
		cfg.AuthEndpoint = DefaultAuthEndpoint
	}
	for name, endpoint := range map[string]string{"API": cfg.APIEndpoint, "auth": cfg.AuthEndpoint} {
		if err := validateEndpoint(name, endpoint); err != nil {
			return nil, err
		}
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}

	c := &Client{cfg: cfg, http: httpClient, sem: make(chan struct{}, 1)}
	c.DNS = &DNSService{c: c}
	c.Mail = &MailService{c: c}
	c.Subdomains = &SubdomainService{c: c}
	c.Domains = &DomainService{c: c}
	c.TLS = &TLSService{c: c}
	c.FTP = &FTPService{c: c}
	c.Databases = &DatabaseService{c: c}
	c.Cronjobs = &CronjobService{c: c}
	c.DDNS = &DDNSService{c: c}
	c.MailingLists = &MailingListService{c: c}
	c.DirectoryProtection = &DirectoryProtectionService{c: c}
	c.Samba = &SambaService{c: c}
	c.Accounts = &AccountService{c: c}
	c.Statistics = &StatisticsService{c: c}
	return c, nil
}

// defaultHTTPClient starts from the standard transport, so proxies and the
// dial and handshake timeouts of the environment apply, and refuses redirects.
func defaultHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxIdleConnsPerHost = 2
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
		// The API never redirects. Following one would post the credentials
		// to wherever it points.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// validateEndpoint requires https, except for the loopback interface.
func validateEndpoint(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("kasapi: %s endpoint %q: %w", name, raw, err)
	}
	switch {
	case u.Scheme == "https" && u.Host != "":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("kasapi: %s endpoint %q must use https", name, raw)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// lock takes the client's turn, or gives up when ctx ends first.
func (c *Client) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) unlock() { <-c.sem }

// Exec runs an arbitrary KAS action with the given request parameters and
// returns its ReturnInfo as a generic value. It is the single entry point all
// typed services build on, and the escape hatch for un-wrapped actions.
//
// Expired sessions trigger one transparent re-authentication; "flood_protection"
// faults are retried with bounded backoff.
func (c *Client) Exec(ctx context.Context, action string, params map[string]any) (any, error) {
	if action == "" {
		return nil, errors.New("kasapi: action must not be empty")
	}
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()

	var r retries
	for {
		res, err := c.execLocked(ctx, action, params)
		if err == nil {
			return res, nil
		}
		if !r.again(c, err) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
}

// retries bounds the transparent retries of one Exec: one new session after
// the API rejected the old one, a few waits on flood protection.
type retries struct {
	reauthed bool
	flood    int
}

const maxFloodRetries = 3

// again prepares the next attempt and reports whether there is one.
func (r *retries) again(c *Client, err error) bool {
	switch retryOf(err) {
	case retrySession:
		if r.reauthed {
			return false
		}
		r.reauthed = true
		c.token = "" // force re-auth on next attempt
		return true
	case retryFlood:
		if r.flood == maxFloodRetries {
			return false
		}
		r.flood++
		c.notBefore = time.Now().Add(time.Duration(r.flood) * 2 * time.Second)
		return true
	}
	return false
}

type retry int

const (
	retryNone    retry = iota
	retrySession       // the API rejected the session: log in again once
	retryFlood         // flood protection: wait and send again
)

// retryOf classifies a failed call. A handshake KAS rejects is final, the
// same credentials would fail again; only a session the API rejects is renewed.
func retryOf(err error) retry {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return retryNone
	}
	var handshake *handshakeError
	switch {
	case apiErr.Code == "flood_protection":
		return retryFlood
	case isSessionError(apiErr.Code) && !errors.As(err, &handshake):
		return retrySession
	}
	return retryNone
}

func (c *Client) execLocked(ctx context.Context, action string, params map[string]any) (any, error) {
	if err := c.ensureSessionLocked(ctx); err != nil {
		return nil, err
	}
	if err := c.waitForFloodWindowLocked(ctx); err != nil {
		return nil, err
	}

	if params == nil {
		params = map[string]any{}
	}
	payload, err := json.Marshal(map[string]any{
		"kas_login":        c.cfg.Login,
		"kas_auth_type":    "session",
		"kas_auth_data":    c.token,
		"kas_action":       action,
		"KasRequestParams": params,
	})
	if err != nil {
		return nil, fmt.Errorf("kasapi: encoding request: %w", err)
	}

	ret, err := c.soapCall(ctx, c.cfg.APIEndpoint, apiNamespace, "KasApi", string(payload))
	if err != nil {
		return nil, err
	}
	c.applyFloodDelayLocked(ret)

	top, _ := ret.(map[string]any)
	response, _ := top["Response"].(map[string]any)
	if response == nil {
		// The response echoes the request, parameters and passwords included,
		// so the error names its shape, never its content.
		return nil, fmt.Errorf("kasapi: action %q: malformed response: %s", action, shapeOf(ret))
	}
	if rs := asString(response["ReturnString"]); rs != "TRUE" {
		return nil, fmt.Errorf("kasapi: action %q failed: ReturnString=%q", action, rs)
	}
	// KAS extends the session on use (session_update_lifetime).
	c.tokenExp = time.Now().Add(c.sessionTTL())
	return response["ReturnInfo"], nil
}

// shapeOf describes a decoded value by its structure, not its content.
func shapeOf(v any) string {
	switch t := v.(type) {
	case nil:
		return "nothing"
	case string:
		return "a string"
	case []any:
		return fmt.Sprintf("a list of %d", len(t))
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "a map with keys " + strings.Join(keys, ", ")
	}
	return fmt.Sprintf("%T", v)
}
