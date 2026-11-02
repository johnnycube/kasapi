// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AuthType selects how credentials are sent when creating a session.
type AuthType string

const (
	// AuthPlain sends the password as-is.
	AuthPlain AuthType = "plain"
	// AuthSHA1 sends the SHA1 hex digest of the password. KAS mandates the
	// algorithm; the digest is as good as the password, so TLS carries the
	// security either way.
	AuthSHA1 AuthType = "sha1"
)

// handshakeError is a KasAuth call KAS rejected, as opposed to a session the
// API rejected. It wraps the fault so callers can still read the code.
type handshakeError struct{ err error }

func (e *handshakeError) Error() string { return "authentication failed: " + e.err.Error() }
func (e *handshakeError) Unwrap() error { return e.err }

// ensureSessionLocked creates a session token via KasAuth if the cached one is
// missing or expired. Caller must hold c.sem.
func (c *Client) ensureSessionLocked(ctx context.Context) error {
	if c.token != "" && time.Now().Before(c.tokenExp) {
		return nil
	}

	authData := c.cfg.Password
	if c.cfg.AuthType == AuthSHA1 {
		sum := sha1.Sum([]byte(c.cfg.Password))
		authData = hex.EncodeToString(sum[:])
	}

	req := map[string]any{
		"kas_login":               c.cfg.Login,
		"kas_auth_type":           string(c.cfg.AuthType),
		"kas_auth_data":           authData,
		"session_lifetime":        c.cfg.SessionLifetime,
		"session_update_lifetime": "Y",
	}
	if c.cfg.OTP != nil {
		// session_2fa is not yet verified against an account with 2FA enabled.
		pin, err := c.cfg.OTP(ctx)
		if err != nil {
			return fmt.Errorf("kasapi: obtaining one-time PIN: %w", err)
		}
		if pin == "" {
			return errors.New("kasapi: one-time PIN must not be empty")
		}
		req["session_2fa"] = pin
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("kasapi: encoding auth request: %w", err)
	}

	if err := c.waitForFloodWindowLocked(ctx); err != nil {
		return err
	}
	ret, err := c.soapCall(ctx, c.cfg.AuthEndpoint, authNamespace, "KasAuth", string(payload))
	if err != nil {
		// The payload is intentionally omitted so credentials are never echoed.
		return &handshakeError{err: err}
	}

	token := asString(ret)
	if m, ok := ret.(map[string]any); ok {
		if t := asString(m["Response"]); t != "" {
			token = t
		}
	}
	if token == "" {
		return errors.New("kasapi: authentication returned no session token")
	}

	c.token = token
	c.tokenExp = time.Now().Add(c.sessionTTL())
	return nil
}

// sessionTTL is how long a fresh or used token is trusted: the lifetime less
// a margin, so the client never races the server's expiry.
func (c *Client) sessionTTL() time.Duration {
	lifetime := time.Duration(c.cfg.SessionLifetime) * time.Second
	margin := time.Minute
	if lifetime <= 2*margin {
		margin = lifetime / 2
	}
	return lifetime - margin
}

// setPassword replaces the stored password, e.g. after UpdateOwnPassword.
func (c *Client) setPassword(password string) {
	c.sem <- struct{}{}
	c.cfg.Password = password
	<-c.sem
}

func isSessionError(code string) bool {
	switch code {
	case "kas_auth_data_incorrect", "session_token_invalid", "session_expired":
		return true
	}
	return false
}

// Logout ends the open KAS session (delete_session). The next call logs in
// again. Without an open session it does nothing.
func (c *Client) Logout(ctx context.Context) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.token == "" || !time.Now().Before(c.tokenExp) {
		c.token = ""
		return nil
	}
	_, err := c.execLocked(ctx, "delete_session", nil)
	c.token = ""
	var apiErr *APIError
	if err != nil && errors.As(err, &apiErr) && (isSessionError(apiErr.Code) || apiErr.Code == "unknown_session") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("logging out: %w", err)
	}
	return nil
}
