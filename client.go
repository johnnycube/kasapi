// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

// Package kasapi is a Go client for the all-inkl.com KAS hosting API. The KAS
// panel is exposed as a SOAP service; this package wraps it in typed services
// over a transport that handles the session handshake, the flood-protection
// delays and the PHP-shaped responses. Standard-library only.
//
// Client.Exec runs any KAS action with raw parameters; the typed services
// (DNS, Mail, Subdomains, Domains) are thin wrappers over it.
//
// Unofficial: not affiliated with all-inkl.com (Neue Medien Münnich GmbH).
package kasapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	DefaultAPIEndpoint  = "https://kasapi.kasserver.com/soap/KasApi.php"
	DefaultAuthEndpoint = "https://kasapi.kasserver.com/soap/KasAuth.php"

	apiNamespace  = "https://kasserver.com/soap/KasApi.php"
	authNamespace = "https://kasserver.com/soap/KasAuth.php"
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

	SessionLifetime int // seconds, max 3600; default 1800
	UserAgent       string

	// HTTPClient overrides the default (TLS >= 1.2, 60s timeout). A custom
	// client is responsible for its own TLS configuration.
	HTTPClient   *http.Client
	APIEndpoint  string
	AuthEndpoint string
}

// Client talks to the KAS SOAP API. It is safe for concurrent use; requests
// are serialized because KAS enforces flood protection between calls.
type Client struct {
	cfg  Config
	http *http.Client

	mu        sync.Mutex
	token     string
	tokenExp  time.Time
	notBefore time.Time // earliest the next request may be sent

	DNS        *DNSService
	Mail       *MailService
	Subdomains *SubdomainService
	Domains    *DomainService
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
	if cfg.SessionLifetime > 3600 {
		cfg.SessionLifetime = 3600
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
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2:   true,
				MaxIdleConnsPerHost: 2,
			},
		}
	}

	c := &Client{cfg: cfg, http: httpClient}
	c.DNS = &DNSService{c: c}
	c.Mail = &MailService{c: c}
	c.Subdomains = &SubdomainService{c: c}
	c.Domains = &DomainService{c: c}
	return c, nil
}

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

	c.mu.Lock()
	defer c.mu.Unlock()

	const maxFloodRetries = 3
	reauthed := false
	floodRetries := 0

	for {
		res, err := c.execLocked(ctx, action, params)
		if err == nil {
			return res, nil
		}

		var apiErr *APIError
		if errors.As(err, &apiErr) {
			switch {
			case isSessionError(apiErr.Code) && !reauthed:
				reauthed = true
				c.token = "" // force re-auth on next attempt
				continue
			case apiErr.Code == "flood_protection" && floodRetries < maxFloodRetries:
				floodRetries++
				c.notBefore = time.Now().Add(time.Duration(floodRetries) * 2 * time.Second)
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				continue
			}
		}
		return nil, err
	}
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

	top, _ := ret.(map[string]any)
	c.applyFloodDelayLocked(top)

	response, _ := top["Response"].(map[string]any)
	if response == nil {
		return nil, fmt.Errorf("kasapi: action %q: malformed response: %v", action, ret)
	}
	if rs := asString(response["ReturnString"]); rs != "TRUE" {
		return nil, fmt.Errorf("kasapi: action %q failed: ReturnString=%q", action, rs)
	}
	return response["ReturnInfo"], nil
}
