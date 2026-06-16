// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// AuthType selects how credentials are sent when creating a session.
type AuthType string

const (
	AuthPlain AuthType = "plain" // password as-is
	AuthSHA1  AuthType = "sha1"  // SHA1 hex digest of the password
)

// ensureSessionLocked creates a session token via KasAuth if the cached one is
// missing or expired. Caller must hold c.mu.
func (c *Client) ensureSessionLocked(ctx context.Context) error {
	if c.token != "" && time.Now().Before(c.tokenExp) {
		return nil
	}

	authData := c.cfg.Password
	if c.cfg.AuthType == AuthSHA1 {
		sum := sha1.Sum([]byte(c.cfg.Password))
		authData = hex.EncodeToString(sum[:])
	}

	payload, err := json.Marshal(map[string]any{
		"kas_login":               c.cfg.Login,
		"kas_auth_type":           string(c.cfg.AuthType),
		"kas_auth_data":           authData,
		"session_lifetime":        c.cfg.SessionLifetime,
		"session_update_lifetime": "Y",
	})
	if err != nil {
		return fmt.Errorf("kasapi: encoding auth request: %w", err)
	}

	if err := c.waitForFloodWindowLocked(ctx); err != nil {
		return err
	}
	ret, err := c.soapCall(ctx, c.cfg.AuthEndpoint, authNamespace, "KasAuth", string(payload))
	if err != nil {
		// The payload is intentionally omitted so credentials are never echoed.
		return fmt.Errorf("kasapi: authentication failed: %w", err)
	}

	token := asString(ret)
	if m, ok := ret.(map[string]any); ok {
		if t := asString(m["Response"]); t != "" {
			token = t
		}
	}
	if token == "" {
		return fmt.Errorf("kasapi: authentication returned no session token")
	}

	c.token = token
	// Expire a bit early to avoid racing the server.
	c.tokenExp = time.Now().Add(time.Duration(c.cfg.SessionLifetime-60) * time.Second)
	return nil
}

func isSessionError(code string) bool {
	switch code {
	case "kas_auth_data_incorrect", "session_token_invalid", "session_expired":
		return true
	}
	return false
}
